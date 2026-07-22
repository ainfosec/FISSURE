"""Dashboard-side artifact download state and local cache handling."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
from dataclasses import dataclass
from typing import Dict, Optional
import time

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
class _ActiveDownload:
    transfer_id: str
    artifact_id: str
    open_when_complete: bool = False
    expected_size: int = 0
    received_size: int = 0
    expected_checksum: str = ""
    expected_sequence: int = 0
    part_path: str = ""
    final_path: str = ""
    file_handle: object = None
    hasher: object = None
    last_activity: float = 0.0


class ArtifactTransferController:
    """Receives streamed artifacts and commits verified local cache files."""

    REQUEST_TIMEOUT_SECONDS = 20.0
    TRANSFER_TIMEOUT_SECONDS = 20.0

    def __init__(self, backend, cache_root: Optional[str] = None):
        self.backend = backend
        self.frontend = backend.frontend
        self.logger = backend.logger
        self.cache_root = cache_root or os.path.join(
            fissure.utils.HUB_ARTIFACTS_DIR,
            "downloads",
        )
        self.index_path = os.path.join(self.cache_root, "index.json")
        self.pending_requests: Dict[str, Dict[str, object]] = {}
        self.active_downloads: Dict[str, _ActiveDownload] = {}
        self.local_cache = self._load_index()
        os.makedirs(self.cache_root, exist_ok=True)

    def register_request(
        self,
        transfer_id: str,
        artifact_id: str,
        open_when_complete: bool = False,
    ) -> None:
        self.pending_requests[transfer_id] = {
            "artifact_id": artifact_id,
            "open_when_complete": bool(open_when_complete),
            "last_activity": time.monotonic(),
        }
        self._set_download_button(True, "Downloading...")

    def get_local_path(self, artifact_id: str) -> Optional[str]:
        record = self.local_cache.get(artifact_id)
        if not isinstance(record, dict):
            return None

        local_path = record.get("local_path")
        if not local_path or not os.path.isfile(local_path):
            return None

        return local_path

    async def receive_loop(self) -> None:
        while not self.backend.shutdown:
            client = self.backend.artifact_transfer_client
            if client is None:
                return

            try:
                frame = await client.receive()
                if frame is not None:
                    self.handle_frame(frame)

                self._expire_stalled_transfers()
            except Exception as exc:
                if not self.backend.shutdown:
                    self.logger.error(
                        "Artifact transfer receive error: %s",
                        exc,
                    )

            await self._yield_control()

    def _expire_stalled_transfers(self) -> None:
            """Fail requests or downloads that stop receiving transfer traffic."""
            now = time.monotonic()

            expired_pending = [
                transfer_id
                for transfer_id, request in self.pending_requests.items()
                if now - float(request.get("last_activity", now))
                >= self.REQUEST_TIMEOUT_SECONDS
            ]

            for transfer_id in expired_pending:
                self.fail_request(
                    transfer_id,
                    "Transfer timed out before the source started sending",
                )

            expired_active = [
                transfer_id
                for transfer_id, transfer in self.active_downloads.items()
                if transfer.last_activity > 0
                and now - transfer.last_activity
                >= self.TRANSFER_TIMEOUT_SECONDS
            ]

            for transfer_id in expired_active:
                self.fail_request(
                    transfer_id,
                    "Transfer timed out while receiving artifact data",
                )

    @staticmethod
    async def _yield_control() -> None:
        import asyncio
        await asyncio.sleep(0)

    def handle_frame(self, frame: ArtifactTransferFrame) -> None:
        if frame.kind == FRAME_START:
            self._handle_start(frame)
        elif frame.kind == FRAME_CHUNK:
            self._handle_chunk(frame)
        elif frame.kind == FRAME_COMPLETE:
            self._handle_complete(frame)
        elif frame.kind in (FRAME_ERROR, FRAME_CANCEL):
            message = (frame.metadata or {}).get("message", "Transfer failed")
            self.fail_request(frame.transfer_id, str(message))

    def fail_request(self, transfer_id: str, message: str) -> None:
        transfer = self.active_downloads.pop(transfer_id, None)
        self.pending_requests.pop(transfer_id, None)

        if transfer is not None:
            self._close_transfer_file(transfer)
            if transfer.part_path and os.path.exists(transfer.part_path):
                try:
                    os.remove(transfer.part_path)
                except OSError:
                    pass

        self.logger.error("Artifact transfer %s failed: %s", transfer_id, message)
        self._show_status(f"Artifact download failed: {message}")
        self._set_download_button(False, "Download")

    def _handle_start(self, frame: ArtifactTransferFrame) -> None:
        metadata = frame.metadata or {}
        request = self.pending_requests.pop(frame.transfer_id, {})

        artifact_id = str(
            metadata.get("artifact_id")
            or request.get("artifact_id")
            or ""
        )
        source_id = self._safe_component(
            str(metadata.get("source_id") or "unknown-source")
        )
        operation_id = self._safe_component(
            str(metadata.get("operation_id") or "unknown-operation")
        )
        filename = os.path.basename(
            str(metadata.get("filename") or artifact_id or "artifact.bin")
        )

        if not artifact_id or not filename:
            self.fail_request(
                frame.transfer_id,
                "Invalid artifact metadata",
            )
            return

        destination_dir = os.path.join(
            self.cache_root,
            source_id,
            operation_id,
            "files",
        )
        os.makedirs(destination_dir, exist_ok=True)

        final_path = os.path.join(destination_dir, filename)
        part_path = final_path + ".part"

        try:
            file_handle = open(part_path, "wb")
        except OSError as exc:
            self.fail_request(
                frame.transfer_id,
                f"Unable to create destination: {exc}",
            )
            return

        transfer = _ActiveDownload(
            transfer_id=frame.transfer_id,
            artifact_id=artifact_id,
            open_when_complete=bool(
                request.get("open_when_complete", False)
            ),
            expected_size=int(metadata.get("file_size") or 0),
            expected_checksum=str(metadata.get("checksum") or ""),
            part_path=part_path,
            final_path=final_path,
            file_handle=file_handle,
            hasher=hashlib.sha256(),
            last_activity=time.monotonic(),
        )
        self.active_downloads[frame.transfer_id] = transfer

        self.logger.info(
            "Receiving artifact %s into %s",
            artifact_id,
            part_path,
        )

    def _handle_chunk(self, frame: ArtifactTransferFrame) -> None:
        transfer = self.active_downloads.get(frame.transfer_id)
        if transfer is None:
            self.fail_request(
                frame.transfer_id,
                "Received chunk before START",
            )
            return

        transfer.last_activity = time.monotonic()

        if frame.sequence != transfer.expected_sequence:
            self.fail_request(
                frame.transfer_id,
                (
                    f"Unexpected chunk sequence {frame.sequence}; "
                    f"expected {transfer.expected_sequence}"
                ),
            )
            return

        data = frame.data or b""
        try:
            transfer.file_handle.write(data)
        except OSError as exc:
            self.fail_request(
                frame.transfer_id,
                f"Unable to write artifact: {exc}",
            )
            return

        transfer.hasher.update(data)
        transfer.received_size += len(data)
        transfer.expected_sequence += 1

        if transfer.expected_size > 0:
            percent = min(
                100,
                int(
                    (transfer.received_size * 100)
                    / transfer.expected_size
                ),
            )
            self._set_download_button(
                True,
                f"Downloading {percent}%",
            )

    def _handle_complete(self, frame: ArtifactTransferFrame) -> None:
        transfer = self.active_downloads.pop(frame.transfer_id, None)
        if transfer is None:
            self.fail_request(frame.transfer_id, "Received COMPLETE before START")
            return

        self._close_transfer_file(transfer, flush=True)

        actual_checksum = transfer.hasher.hexdigest()
        if transfer.expected_size and transfer.received_size != transfer.expected_size:
            self._delete_part(transfer)
            self.fail_request(
                frame.transfer_id,
                f"Size mismatch: received {transfer.received_size}, expected {transfer.expected_size}",
            )
            return

        if transfer.expected_checksum and actual_checksum != transfer.expected_checksum:
            self._delete_part(transfer)
            self.fail_request(frame.transfer_id, "SHA-256 checksum mismatch")
            return

        try:
            os.replace(transfer.part_path, transfer.final_path)
        except OSError as exc:
            self._delete_part(transfer)
            self.fail_request(frame.transfer_id, f"Unable to finalize artifact: {exc}")
            return

        self.local_cache[transfer.artifact_id] = {
            "local_path": transfer.final_path,
            "checksum": actual_checksum,
            "file_size": transfer.received_size,
        }
        self._save_index()

        self.logger.info(
            "Artifact %s downloaded successfully: %s",
            transfer.artifact_id,
            transfer.final_path,
        )
        self._show_status("Artifact download complete")
        self._set_download_button(False, "Download")

        if transfer.open_when_complete:
            subprocess.Popen(["xdg-open", os.path.dirname(transfer.final_path)])

    @staticmethod
    def _safe_component(value: str) -> str:
        value = value.strip().replace(os.sep, "_")
        if os.altsep:
            value = value.replace(os.altsep, "_")
        return value or "unknown"

    @staticmethod
    def _close_transfer_file(transfer: _ActiveDownload, flush: bool = False) -> None:
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
    def _delete_part(transfer: _ActiveDownload) -> None:
        if transfer.part_path and os.path.exists(transfer.part_path):
            try:
                os.remove(transfer.part_path)
            except OSError:
                pass

    def _load_index(self) -> Dict[str, Dict[str, object]]:
        try:
            with open(self.index_path, "r", encoding="utf-8") as index_file:
                loaded = json.load(index_file)
            return loaded if isinstance(loaded, dict) else {}
        except (OSError, ValueError):
            return {}

    def _save_index(self) -> None:
        os.makedirs(self.cache_root, exist_ok=True)
        temporary_path = self.index_path + ".part"
        with open(temporary_path, "w", encoding="utf-8") as index_file:
            json.dump(self.local_cache, index_file, indent=2, sort_keys=True)
        os.replace(temporary_path, self.index_path)

    def _show_status(self, message: str) -> None:
        try:
            self.frontend.statusBar().showMessage(message, 5000)
        except Exception:
            pass

    def _set_download_button(self, active: bool, text: str) -> None:
        try:
            button = self.frontend.ui.pushButton_tactical_node_artifacts_download
            button.setText(text)
            button.setEnabled(not active)
        except Exception:
            pass
