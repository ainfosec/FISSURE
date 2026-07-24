"""HIPRFISR-side multi-file artifact receiving and cache handling."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import time

from dataclasses import dataclass, field
from typing import Dict, Optional

from fissure.comms.ArtifactTransfer import (
    FRAME_CANCEL,
    FRAME_CHUNK,
    FRAME_COMPLETE,
    FRAME_ERROR,
    FRAME_FILE_COMPLETE,
    FRAME_START,
    ArtifactTransferFrame,
)


@dataclass
class _ReceivingFile:
    file_id: str = ""
    relative_path: str = ""
    expected_size: int = 0
    received_size: int = 0
    expected_checksum: str = ""
    expected_sequence: int = 0
    part_path: str = ""
    final_path: str = ""
    file_handle: object = None
    hasher: object = None


@dataclass
class _PendingTransfer:
    transfer_id: str
    artifact_id: str
    destination: str

    expected_file_count: int = 0
    expected_total_size: int = 0
    received_total_size: int = 0

    artifact_root: str = ""
    files_root: str = ""

    current_file: Optional[_ReceivingFile] = None
    completed_files: Dict[str, Dict[str, object]] = field(
        default_factory=dict
    )

    last_activity: float = 0.0


class HiprFisrArtifactTransferController:
    """
    Receives complete logical artifacts from Sensor Nodes without using command
    sockets for payload bytes.
    """

    TRANSFER_TIMEOUT_SECONDS = 60.0

    def __init__(self, component):
        self.component = component
        self.logger = component.logger
        self.pending: Dict[
            str,
            _PendingTransfer,
        ] = {}

        self.cache_root = os.path.join(
            self.component.artifact_tracker.base_dir,
            "cache",
        )
        self.cache_index_path = os.path.join(
            self.cache_root,
            "index.json",
        )

        os.makedirs(
            self.cache_root,
            exist_ok=True,
        )

        self.local_cache = self._load_cache_index()

    def register_request(
        self,
        transfer_id: str,
        artifact_id: str,
        destination: str,
    ) -> None:
        self.pending[transfer_id] = (
            _PendingTransfer(
                transfer_id=transfer_id,
                artifact_id=artifact_id,
                destination=destination,
                last_activity=time.monotonic(),
            )
        )

    def get_local_path(
        self,
        artifact_id: str,
    ) -> Optional[str]:
        record = self.local_cache.get(
            str(artifact_id or "").strip()
        )

        if not isinstance(record, dict):
            return None

        local_path = str(
            record.get("local_path", "")
            or ""
        ).strip()

        if os.path.isfile(local_path):
            return local_path

        if os.path.isdir(local_path):
            return local_path

        return None

    def get_local_files(
        self,
        artifact_id: str,
    ) -> Dict[str, str]:
        record = self.local_cache.get(
            str(artifact_id or "").strip()
        )

        if not isinstance(record, dict):
            return {}

        files = record.get("files")

        if not isinstance(files, dict):
            return {}

        return {
            str(file_id): str(
                file_record.get(
                    "local_path",
                    "",
                )
            )
            for file_id, file_record
            in files.items()
            if isinstance(file_record, dict)
            and os.path.isfile(
                str(
                    file_record.get(
                        "local_path",
                        "",
                    )
                )
            )
        }

    async def handle_frame(
        self,
        frame: ArtifactTransferFrame,
    ) -> None:
        if frame.kind == FRAME_START:
            self._handle_start(frame)

        elif frame.kind == FRAME_CHUNK:
            self._handle_chunk(frame)

        elif frame.kind == FRAME_FILE_COMPLETE:
            self._handle_file_complete(frame)

        elif frame.kind == FRAME_COMPLETE:
            await self._handle_complete(frame)

        elif frame.kind in (
            FRAME_ERROR,
            FRAME_CANCEL,
        ):
            message = str(
                (
                    frame.metadata or {}
                ).get(
                    "message",
                    "Transfer failed",
                )
            )

            self.fail(
                frame.transfer_id,
                message,
            )

    def expire_stalled_transfers(self) -> None:
        now = time.monotonic()

        expired = [
            transfer_id
            for transfer_id, transfer
            in self.pending.items()
            if (
                now - transfer.last_activity
                >= self.TRANSFER_TIMEOUT_SECONDS
            )
        ]

        for transfer_id in expired:
            self.fail(
                transfer_id,
                "Artifact transfer timed out",
            )
            self.component.artifact_transfer_router.remove_transfer(
                transfer_id
            )

    def fail(
        self,
        transfer_id: str,
        message: str,
    ) -> None:
        transfer = self.pending.pop(
            transfer_id,
            None,
        )

        if transfer is not None:
            self._discard_current_file(
                transfer
            )

            if (
                transfer.artifact_root
                and os.path.isdir(
                    transfer.artifact_root
                )
            ):
                try:
                    shutil.rmtree(
                        transfer.artifact_root
                    )
                except OSError:
                    pass

        self.logger.error(
            "Artifact transfer %s failed: %s",
            transfer_id,
            message,
        )

    def _handle_start(
        self,
        frame: ArtifactTransferFrame,
    ) -> None:
        transfer = self.pending.get(
            frame.transfer_id
        )

        if transfer is None:
            self.logger.error(
                "Received START for unknown artifact transfer %s",
                frame.transfer_id,
            )
            return

        if transfer.current_file is not None:
            self.fail(
                frame.transfer_id,
                "Received START before the previous file completed",
            )
            return

        metadata = frame.metadata or {}

        received_artifact_id = str(
            metadata.get("artifact_id", "")
            or ""
        ).strip()

        if (
            received_artifact_id
            and received_artifact_id
            != transfer.artifact_id
        ):
            self.fail(
                frame.transfer_id,
                "Artifact ID does not match the request",
            )
            return

        artifact = (
            self.component.artifact_tracker
            .get_artifact(
                transfer.artifact_id
            )
        )

        if artifact is None:
            self.fail(
                frame.transfer_id,
                "Artifact metadata is unavailable at HIPRFISR",
            )
            return

        file_id = str(
            metadata.get("file_id", "")
            or ""
        ).strip()
        relative_path = self._safe_relative_path(
            metadata.get("relative_path", "")
            or metadata.get("filename", "")
        )

        declared_file = artifact.get_file(
            file_id
        )

        if declared_file is None:
            self.fail(
                frame.transfer_id,
                "Sensor Node requested an undeclared artifact file",
            )
            return

        if (
            relative_path
            != declared_file.relative_path
        ):
            self.fail(
                frame.transfer_id,
                "Artifact relative path does not match HIPRFISR metadata",
            )
            return

        declared_size = int(
            declared_file.size
        )
        declared_checksum = str(
            declared_file.sha256
        )

        received_size = int(
            metadata.get(
                "file_size",
                declared_size,
            )
            or declared_size
        )
        received_checksum = str(
            metadata.get(
                "sha256",
                declared_checksum,
            )
            or declared_checksum
        )

        if received_size != declared_size:
            self.fail(
                frame.transfer_id,
                "Artifact file size does not match HIPRFISR metadata",
            )
            return

        if received_checksum != declared_checksum:
            self.fail(
                frame.transfer_id,
                "Artifact checksum does not match HIPRFISR metadata",
            )
            return

        if not transfer.artifact_root:
            transfer.artifact_root = os.path.join(
                self.cache_root,
                self._safe_component(
                    artifact.source_id
                ),
                self._safe_component(
                    artifact.operation_id
                ),
                artifact.id,
            )
            transfer.files_root = os.path.join(
                transfer.artifact_root,
                "files",
            )

            if os.path.isdir(
                transfer.artifact_root
            ):
                try:
                    shutil.rmtree(
                        transfer.artifact_root
                    )
                except OSError as exc:
                    self.fail(
                        frame.transfer_id,
                        f"Unable to clear old artifact cache: {exc}",
                    )
                    return

            os.makedirs(
                transfer.files_root,
                exist_ok=True,
            )

            transfer.expected_file_count = (
                artifact.file_count
            )
            transfer.expected_total_size = (
                artifact.total_size
            )

        final_path = os.path.realpath(
            os.path.join(
                transfer.files_root,
                relative_path,
            )
        )
        files_root_real = os.path.realpath(
            transfer.files_root
        )

        try:
            common = os.path.commonpath(
                [files_root_real, final_path]
            )
        except ValueError:
            common = ""

        if common != files_root_real:
            self.fail(
                frame.transfer_id,
                "Artifact relative path escapes the HIPRFISR cache",
            )
            return

        os.makedirs(
            os.path.dirname(final_path),
            exist_ok=True,
        )

        part_path = f"{final_path}.part"

        try:
            file_handle = open(
                part_path,
                "wb",
            )
        except OSError as exc:
            self.fail(
                frame.transfer_id,
                f"Unable to create artifact cache file: {exc}",
            )
            return

        transfer.current_file = (
            _ReceivingFile(
                file_id=file_id,
                relative_path=relative_path,
                expected_size=declared_size,
                expected_checksum=declared_checksum,
                part_path=part_path,
                final_path=final_path,
                file_handle=file_handle,
                hasher=hashlib.sha256(),
            )
        )
        transfer.last_activity = (
            time.monotonic()
        )

        self.logger.info(
            "Receiving artifact file "
            "transfer_id=%s artifact_id=%s "
            "file_id=%s into %s",
            frame.transfer_id,
            transfer.artifact_id,
            file_id,
            part_path,
        )

    def _handle_chunk(
        self,
        frame: ArtifactTransferFrame,
    ) -> None:
        transfer = self.pending.get(
            frame.transfer_id
        )

        if (
            transfer is None
            or transfer.current_file is None
        ):
            self.fail(
                frame.transfer_id,
                "Received artifact chunk before START",
            )
            return

        current = transfer.current_file

        if frame.sequence != current.expected_sequence:
            self.fail(
                frame.transfer_id,
                (
                    f"Unexpected chunk sequence "
                    f"{frame.sequence}; expected "
                    f"{current.expected_sequence}"
                ),
            )
            return

        data = frame.data or b""

        try:
            current.file_handle.write(data)
        except OSError as exc:
            self.fail(
                frame.transfer_id,
                f"Unable to write artifact data: {exc}",
            )
            return

        current.hasher.update(data)
        current.received_size += len(data)
        current.expected_sequence += 1
        transfer.received_total_size += len(data)
        transfer.last_activity = (
            time.monotonic()
        )

    def _handle_file_complete(
        self,
        frame: ArtifactTransferFrame,
    ) -> None:
        transfer = self.pending.get(
            frame.transfer_id
        )

        if (
            transfer is None
            or transfer.current_file is None
        ):
            self.fail(
                frame.transfer_id,
                "Received FILE_COMPLETE before START",
            )
            return

        current = transfer.current_file
        metadata = frame.metadata or {}

        received_file_id = str(
            metadata.get("file_id", "")
            or ""
        ).strip()

        if (
            received_file_id
            and received_file_id
            != current.file_id
        ):
            self.fail(
                frame.transfer_id,
                "FILE_COMPLETE file ID does not match START",
            )
            return

        self._close_current_file(
            current,
            flush=True,
        )

        actual_checksum = (
            current.hasher.hexdigest()
        )

        if (
            current.received_size
            != current.expected_size
        ):
            self.fail(
                frame.transfer_id,
                (
                    f"Size mismatch for "
                    f"{current.relative_path}: "
                    f"received {current.received_size}, "
                    f"expected {current.expected_size}"
                ),
            )
            return

        if (
            actual_checksum
            != current.expected_checksum
        ):
            self.fail(
                frame.transfer_id,
                (
                    "SHA-256 checksum mismatch for "
                    f"{current.relative_path}"
                ),
            )
            return

        try:
            os.replace(
                current.part_path,
                current.final_path,
            )
        except OSError as exc:
            self.fail(
                frame.transfer_id,
                f"Unable to finalize artifact file: {exc}",
            )
            return

        transfer.completed_files[
            current.file_id
        ] = {
            "relative_path": current.relative_path,
            "local_path": current.final_path,
            "size": current.received_size,
            "sha256": actual_checksum,
        }
        transfer.current_file = None
        transfer.last_activity = (
            time.monotonic()
        )

        self.logger.info(
            "Completed HIPRFISR artifact file "
            "transfer_id=%s artifact_id=%s "
            "file_id=%s path=%s",
            frame.transfer_id,
            transfer.artifact_id,
            current.file_id,
            current.final_path,
        )

    async def _handle_complete(
        self,
        frame: ArtifactTransferFrame,
    ) -> None:
        transfer = self.pending.get(
            frame.transfer_id
        )

        if transfer is None:
            self.fail(
                frame.transfer_id,
                "Received COMPLETE before START",
            )
            return

        if transfer.current_file is not None:
            self.fail(
                frame.transfer_id,
                "Received COMPLETE before the current file completed",
            )
            return

        artifact = (
            self.component.artifact_tracker
            .get_artifact(
                transfer.artifact_id
            )
        )

        if artifact is None:
            self.fail(
                frame.transfer_id,
                "Artifact metadata disappeared during transfer",
            )
            return

        if (
            len(transfer.completed_files)
            != artifact.file_count
        ):
            self.fail(
                frame.transfer_id,
                (
                    f"Artifact file-count mismatch: "
                    f"received "
                    f"{len(transfer.completed_files)}, "
                    f"expected {artifact.file_count}"
                ),
            )
            return

        if (
            transfer.received_total_size
            != artifact.total_size
        ):
            self.fail(
                frame.transfer_id,
                (
                    f"Artifact total-size mismatch: "
                    f"received "
                    f"{transfer.received_total_size}, "
                    f"expected {artifact.total_size}"
                ),
            )
            return

        if artifact.file_count == 1:
            local_path = next(
                iter(
                    transfer.completed_files.values()
                )
            )["local_path"]
        else:
            local_path = transfer.artifact_root

        self.local_cache[
            artifact.id
        ] = {
            "artifact_id": artifact.id,
            "source_id": artifact.source_id,
            "operation_id": artifact.operation_id,
            "file_count": artifact.file_count,
            "total_size": artifact.total_size,
            "local_path": local_path,
            "artifact_root": transfer.artifact_root,
            "files": dict(
                transfer.completed_files
            ),
            "completed_at": time.time(),
        }
        self._save_cache_index()

        self.pending.pop(
            frame.transfer_id,
            None,
        )

        self.logger.info(
            "Completed HIPRFISR artifact transfer "
            "transfer_id=%s artifact_id=%s "
            "files=%s bytes=%s",
            frame.transfer_id,
            artifact.id,
            artifact.file_count,
            artifact.total_size,
        )

        if transfer.destination == "tak":
            await self._send_cached_artifact_to_tak(
                artifact
            )

        elif transfer.destination == "hiprfisr":
            self.logger.info(
                "Artifact %s cached at HIPRFISR",
                artifact.id,
            )

    async def _send_cached_artifact_to_tak(
        self,
        artifact,
    ) -> None:
        """
        Package the complete cached artifact for TAK without changing the
        artifact's original file representation.

        Patch 4 replaces tak_messages.send_artifact_files_event() with the
        final manifest-aware implementation.
        """
        local_files = self.get_local_files(
            artifact.id
        )

        if len(local_files) != artifact.file_count:
            self.logger.error(
                "Unable to package incomplete artifact %s for TAK",
                artifact.id,
            )
            return

        sender = getattr(
            __import__(
                "fissure.utils.tak_messages",
                fromlist=[
                    "send_artifact_files_event"
                ],
            ),
            "send_artifact_files_event",
            None,
        )

        if sender is None:
            self.logger.error(
                "Manifest-aware TAK artifact packaging is not installed yet"
            )
            return

        await sender(
            self.component,
            artifact,
            local_files,
        )

    @staticmethod
    def _safe_component(
        value: object,
    ) -> str:
        text = str(value or "").strip()
        text = text.replace(os.sep, "_")

        if os.altsep:
            text = text.replace(
                os.altsep,
                "_",
            )

        return text or "unknown"

    @staticmethod
    def _safe_relative_path(
        value: object,
    ) -> str:
        text = str(value or "").strip()

        if not text:
            return ""

        normalized = os.path.normpath(text)

        if os.path.isabs(normalized):
            return ""

        if (
            normalized == ".."
            or normalized.startswith(
                f"..{os.sep}"
            )
        ):
            return ""

        return normalized

    @staticmethod
    def _close_current_file(
        current: _ReceivingFile,
        flush: bool = False,
    ) -> None:
        handle = current.file_handle

        if handle is None:
            return

        try:
            if flush:
                handle.flush()
                os.fsync(handle.fileno())

            handle.close()

        except OSError:
            pass

        current.file_handle = None

    def _discard_current_file(
        self,
        transfer: _PendingTransfer,
    ) -> None:
        current = transfer.current_file

        if current is None:
            return

        self._close_current_file(current)

        if (
            current.part_path
            and os.path.exists(
                current.part_path
            )
        ):
            try:
                os.remove(
                    current.part_path
                )
            except OSError:
                pass

        transfer.current_file = None

    def _load_cache_index(
        self,
    ) -> Dict[str, Dict[str, object]]:
        try:
            with open(
                self.cache_index_path,
                "r",
                encoding="utf-8",
            ) as handle:
                loaded = json.load(handle)

            return (
                loaded
                if isinstance(loaded, dict)
                else {}
            )

        except (OSError, ValueError):
            return {}

    def _save_cache_index(self) -> None:
        os.makedirs(
            self.cache_root,
            exist_ok=True,
        )

        temporary_path = (
            self.cache_index_path + ".part"
        )

        with open(
            temporary_path,
            "w",
            encoding="utf-8",
        ) as handle:
            json.dump(
                self.local_cache,
                handle,
                indent=2,
                sort_keys=True,
            )
            handle.flush()
            os.fsync(handle.fileno())

        os.replace(
            temporary_path,
            self.cache_index_path,
        )
