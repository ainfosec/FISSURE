"""HIPRFISR-side receiving and finalization for streamed artifacts."""

from __future__ import annotations

import hashlib
import os
import time
from dataclasses import dataclass
from typing import Dict

import fissure.utils
from fissure.comms.ArtifactTransfer import (
    FRAME_CANCEL,
    FRAME_CHUNK,
    FRAME_COMPLETE,
    FRAME_ERROR,
    FRAME_START,
    ArtifactTransferFrame,
)


@dataclass
class _PendingTransfer:
    transfer_id: str
    artifact_id: str
    destination: str
    expected_size: int = 0
    received_size: int = 0
    expected_checksum: str = ""
    expected_sequence: int = 0
    part_path: str = ""
    final_path: str = ""
    file_handle: object = None
    hasher: object = None
    last_activity: float = 0.0


class HiprFisrArtifactTransferController:
    """Receives Sensor Node artifact streams without using command sockets."""

    TRANSFER_TIMEOUT_SECONDS = 60.0

    def __init__(self, component):
        self.component = component
        self.logger = component.logger
        self.pending: Dict[str, _PendingTransfer] = {}

    def register_request(self, transfer_id: str, artifact_id: str, destination: str) -> None:
        self.pending[transfer_id] = _PendingTransfer(
            transfer_id=transfer_id,
            artifact_id=artifact_id,
            destination=destination,
            last_activity=time.monotonic(),
        )

    async def handle_frame(self, frame: ArtifactTransferFrame) -> None:
        if frame.kind == FRAME_START:
            self._handle_start(frame)
        elif frame.kind == FRAME_CHUNK:
            self._handle_chunk(frame)
        elif frame.kind == FRAME_COMPLETE:
            await self._handle_complete(frame)
        elif frame.kind in (FRAME_ERROR, FRAME_CANCEL):
            message = str((frame.metadata or {}).get("message", "Transfer failed"))
            self.fail(frame.transfer_id, message)

    def expire_stalled_transfers(self) -> None:
        now = time.monotonic()
        expired = [
            transfer_id
            for transfer_id, transfer in self.pending.items()
            if now - transfer.last_activity >= self.TRANSFER_TIMEOUT_SECONDS
        ]
        for transfer_id in expired:
            self.fail(transfer_id, "Artifact transfer timed out")
            self.component.artifact_transfer_router.remove_transfer(transfer_id)

    def fail(self, transfer_id: str, message: str) -> None:
        transfer = self.pending.pop(transfer_id, None)
        if transfer is not None:
            self._close_file(transfer)
            self._delete_part(transfer)
        self.logger.error("Artifact transfer %s failed: %s", transfer_id, message)

    def _handle_start(self, frame: ArtifactTransferFrame) -> None:
        transfer = self.pending.get(frame.transfer_id)
        if transfer is None:
            self.logger.error("Received START for unknown artifact transfer %s", frame.transfer_id)
            return

        metadata = frame.metadata or {}
        received_artifact_id = str(metadata.get("artifact_id") or "")
        if received_artifact_id and received_artifact_id != transfer.artifact_id:
            self.fail(frame.transfer_id, "Artifact ID does not match the request")
            return

        artifact = self.component.artifact_tracker.get_artifact(transfer.artifact_id)
        if artifact is None:
            self.fail(frame.transfer_id, "Artifact metadata is unavailable at HIPRFISR")
            return

        filename = os.path.basename(str(metadata.get("filename") or os.path.basename(artifact.file_path)))
        if not filename:
            self.fail(frame.transfer_id, "Artifact filename is invalid")
            return

        destination_dir = os.path.join(
            self.component.artifact_tracker.base_dir,
            self._safe_component(artifact.source_id),
            self._safe_component(artifact.operation_id),
            "files",
        )
        os.makedirs(destination_dir, exist_ok=True)
        final_path = os.path.join(destination_dir, filename)
        part_path = final_path + ".part"

        try:
            file_handle = open(part_path, "wb")
        except OSError as exc:
            self.fail(frame.transfer_id, f"Unable to create artifact cache file: {exc}")
            return

        transfer.expected_size = int(metadata.get("file_size") or artifact.file_size or 0)
        transfer.expected_checksum = str(metadata.get("checksum") or artifact.checksum or "")
        transfer.part_path = part_path
        transfer.final_path = final_path
        transfer.file_handle = file_handle
        transfer.hasher = hashlib.sha256()
        transfer.last_activity = time.monotonic()

        self.logger.info(
            "Receiving artifact transfer_id=%s artifact_id=%s into %s",
            frame.transfer_id,
            transfer.artifact_id,
            part_path,
        )

    def _handle_chunk(self, frame: ArtifactTransferFrame) -> None:
        transfer = self.pending.get(frame.transfer_id)
        if transfer is None or transfer.file_handle is None:
            self.fail(frame.transfer_id, "Received artifact chunk before START")
            return

        if frame.sequence != transfer.expected_sequence:
            self.fail(
                frame.transfer_id,
                f"Unexpected chunk sequence {frame.sequence}; expected {transfer.expected_sequence}",
            )
            return

        data = frame.data or b""
        try:
            transfer.file_handle.write(data)
        except OSError as exc:
            self.fail(frame.transfer_id, f"Unable to write artifact data: {exc}")
            return

        transfer.hasher.update(data)
        transfer.received_size += len(data)
        transfer.expected_sequence += 1
        transfer.last_activity = time.monotonic()

    async def _handle_complete(self, frame: ArtifactTransferFrame) -> None:
        transfer = self.pending.get(frame.transfer_id)
        if transfer is None or transfer.file_handle is None:
            self.fail(frame.transfer_id, "Received COMPLETE before START")
            return

        self._close_file(transfer, flush=True)
        actual_checksum = transfer.hasher.hexdigest()

        if transfer.expected_size and transfer.received_size != transfer.expected_size:
            self.fail(
                frame.transfer_id,
                f"Size mismatch: received {transfer.received_size}, expected {transfer.expected_size}",
            )
            return

        if transfer.expected_checksum and actual_checksum != transfer.expected_checksum:
            self.fail(frame.transfer_id, "SHA-256 checksum mismatch")
            return

        try:
            os.replace(transfer.part_path, transfer.final_path)
        except OSError as exc:
            self.fail(frame.transfer_id, f"Unable to finalize artifact: {exc}")
            return

        artifact = self.component.artifact_tracker.get_artifact(transfer.artifact_id)
        if artifact is None:
            self.fail(frame.transfer_id, "Artifact metadata disappeared during transfer")
            return

        artifact.file_path = transfer.final_path
        artifact.file_size = transfer.received_size
        artifact.checksum = actual_checksum
        self.component.artifact_tracker.update_artifact(artifact)
        self.pending.pop(frame.transfer_id, None)

        self.logger.info(
            "Completed HIPRFISR artifact transfer_id=%s artifact_id=%s bytes=%s",
            frame.transfer_id,
            transfer.artifact_id,
            transfer.received_size,
        )

        if transfer.destination == "tak":
            data = self.component.artifact_tracker.get_data(transfer.artifact_id)
            if data is None:
                self.logger.error("Unable to read completed artifact %s for TAK", transfer.artifact_id)
                return
            await fissure.utils.tak_messages.send_artifact_event(
                self.component,
                artifact,
                data,
            )
        elif transfer.destination == "hiprfisr":
            self.logger.info("Artifact %s cached at HIPRFISR", transfer.artifact_id)

    @staticmethod
    def _safe_component(value: str) -> str:
        value = str(value).strip().replace(os.sep, "_")
        if os.altsep:
            value = value.replace(os.altsep, "_")
        return value or "unknown"

    @staticmethod
    def _close_file(transfer: _PendingTransfer, flush: bool = False) -> None:
        handle = transfer.file_handle
        if handle is None:
            return
        try:
            if flush:
                handle.flush()
                os.fsync(handle.fileno())
            handle.close()
        except OSError:
            pass
        transfer.file_handle = None

    @staticmethod
    def _delete_part(transfer: _PendingTransfer) -> None:
        if transfer.part_path and os.path.exists(transfer.part_path):
            try:
                os.remove(transfer.part_path)
            except OSError:
                pass
