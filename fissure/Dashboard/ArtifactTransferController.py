"""Dashboard-side multi-file artifact download state and cache handling."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import time
from PyQt5 import QtCore

from dataclasses import dataclass, field
from typing import Dict, Optional

import fissure.utils
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
class _ActiveDownload:
    transfer_id: str
    artifact_id: str
    open_when_complete: bool = False

    source_id: str = ""
    operation_id: str = ""
    artifact_name: str = ""
    artifact_type: str = ""

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


class ArtifactTransferController:
    """
    Receives one logical artifact containing one or more streamed files.

    Each file is verified independently and atomically finalized. The artifact
    cache is committed only after the final artifact-level COMPLETE frame.
    """

    REQUEST_TIMEOUT_SECONDS = 20.0
    TRANSFER_TIMEOUT_SECONDS = 20.0

    def __init__(
        self,
        backend,
        cache_root: Optional[str] = None,
    ):
        self.backend = backend
        self.frontend = backend.frontend
        self.logger = backend.logger

        self.cache_root = cache_root or os.path.join(
            fissure.utils.HUB_ARTIFACTS_DIR,
            "downloads",
        )
        self.index_path = os.path.join(
            self.cache_root,
            "index.json",
        )

        os.makedirs(self.cache_root, exist_ok=True)

        self.pending_requests: Dict[
            str,
            Dict[str, object],
        ] = {}
        self.active_downloads: Dict[
            str,
            _ActiveDownload,
        ] = {}
        self.local_cache = self._load_index()

    def register_request(
        self,
        transfer_id: str,
        artifact_id: str,
        open_when_complete: bool = False,
    ) -> None:
        self.pending_requests[transfer_id] = {
            "artifact_id": str(artifact_id),
            "open_when_complete": bool(open_when_complete),
            "last_activity": time.monotonic(),
        }

        self._set_download_button(
            True,
            "Downloading...",
        )

    def get_local_path(
        self,
        artifact_id: str,
    ) -> Optional[str]:
        """
        Return:
            the verified file path for a one-file artifact;
            the verified artifact directory for a multi-file artifact.
        """
        record = self.local_cache.get(
            str(artifact_id or "").strip()
        )

        if not isinstance(record, dict):
            return None

        local_path = str(
            record.get("local_path", "") or ""
        ).strip()

        if not local_path:
            return None

        if os.path.isfile(local_path):
            return local_path

        if os.path.isdir(local_path):
            return local_path

        return None

    def get_local_files(
        self,
        artifact_id: str,
    ) -> Dict[str, str]:
        """
        Return {file_id: local_file_path} for a complete cached artifact.
        """
        record = self.local_cache.get(
            str(artifact_id or "").strip()
        )

        if not isinstance(record, dict):
            return {}

        files = record.get("files")
        if not isinstance(files, dict):
            return {}

        return {
            str(file_id): str(file_record.get("local_path", ""))
            for file_id, file_record in files.items()
            if isinstance(file_record, dict)
            and os.path.isfile(
                str(file_record.get("local_path", ""))
            )
        }

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

    @staticmethod
    async def _yield_control() -> None:
        import asyncio
        await asyncio.sleep(0)

    def _expire_stalled_transfers(self) -> None:
        now = time.monotonic()

        expired_pending = [
            transfer_id
            for transfer_id, request
            in self.pending_requests.items()
            if (
                now
                - float(
                    request.get(
                        "last_activity",
                        now,
                    )
                )
                >= self.REQUEST_TIMEOUT_SECONDS
            )
        ]

        for transfer_id in expired_pending:
            self.fail_request(
                transfer_id,
                "Transfer timed out before the source started sending",
            )

        expired_active = [
            transfer_id
            for transfer_id, transfer
            in self.active_downloads.items()
            if (
                transfer.last_activity > 0
                and now - transfer.last_activity
                >= self.TRANSFER_TIMEOUT_SECONDS
            )
        ]

        for transfer_id in expired_active:
            self.fail_request(
                transfer_id,
                "Transfer timed out while receiving artifact data",
            )

    def handle_frame(
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
            self._handle_complete(frame)

        elif frame.kind in (
            FRAME_ERROR,
            FRAME_CANCEL,
        ):
            message = (
                frame.metadata or {}
            ).get(
                "message",
                "Transfer failed",
            )

            self.fail_request(
                frame.transfer_id,
                str(message),
            )

    def fail_request(
        self,
        transfer_id: str,
        message: str,
    ) -> None:
        transfer = self.active_downloads.pop(
            transfer_id,
            None,
        )
        self.pending_requests.pop(
            transfer_id,
            None,
        )

        self.frontend.iq_record_select_after_download_id = ""

        if transfer is not None:
            self._discard_current_file(transfer)

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
        self._show_status(
            f"Artifact download failed: {message}"
        )
        self._set_download_button(
            False,
            "Download",
        )

    def _handle_start(
        self,
        frame: ArtifactTransferFrame,
    ) -> None:
        metadata = frame.metadata or {}

        request = self.pending_requests.get(
            frame.transfer_id,
            {},
        )

        transfer = self.active_downloads.get(
            frame.transfer_id
        )

        artifact_id = str(
            metadata.get("artifact_id")
            or request.get("artifact_id")
            or (
                transfer.artifact_id
                if transfer is not None
                else ""
            )
            or ""
        ).strip()

        if not artifact_id:
            self.fail_request(
                frame.transfer_id,
                "Artifact ID is missing",
            )
            return

        if transfer is None:
            source_id = self._safe_component(
                metadata.get(
                    "source_id",
                    "unknown-source",
                )
            )
            operation_id = self._safe_component(
                metadata.get(
                    "operation_id",
                    "unknown-operation",
                )
            )

            artifact_root = os.path.join(
                self.cache_root,
                source_id,
                operation_id,
                artifact_id,
            )
            files_root = os.path.join(
                artifact_root,
                "files",
            )

            if os.path.isdir(artifact_root):
                try:
                    shutil.rmtree(artifact_root)
                except OSError as exc:
                    self.fail_request(
                        frame.transfer_id,
                        f"Unable to clear old artifact cache: {exc}",
                    )
                    return

            os.makedirs(
                files_root,
                exist_ok=True,
            )

            transfer = _ActiveDownload(
                transfer_id=frame.transfer_id,
                artifact_id=artifact_id,
                open_when_complete=bool(
                    request.get(
                        "open_when_complete",
                        False,
                    )
                ),
                source_id=str(
                    metadata.get("source_id", "")
                    or ""
                ),
                operation_id=str(
                    metadata.get("operation_id", "")
                    or ""
                ),
                artifact_name=str(
                    metadata.get("artifact_name", "")
                    or ""
                ),
                artifact_type=str(
                    metadata.get("artifact_type", "")
                    or ""
                ),
                expected_file_count=int(
                    metadata.get(
                        "artifact_file_count",
                        0,
                    )
                    or 0
                ),
                expected_total_size=int(
                    metadata.get(
                        "artifact_total_size",
                        0,
                    )
                    or 0
                ),
                artifact_root=artifact_root,
                files_root=files_root,
                last_activity=time.monotonic(),
            )

            self.active_downloads[
                frame.transfer_id
            ] = transfer

        else:
            if transfer.artifact_id != artifact_id:
                self.fail_request(
                    frame.transfer_id,
                    "Artifact ID changed during transfer",
                )
                return

            if transfer.current_file is not None:
                self.fail_request(
                    frame.transfer_id,
                    "Received START before the previous file completed",
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

        if not file_id or not relative_path:
            self.fail_request(
                frame.transfer_id,
                "Invalid artifact file metadata",
            )
            return

        if (
            file_id in transfer.completed_files
        ):
            self.fail_request(
                frame.transfer_id,
                f"Duplicate artifact file ID: {file_id}",
            )
            return

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
            self.fail_request(
                frame.transfer_id,
                "Artifact relative path escapes the cache root",
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
            self.fail_request(
                frame.transfer_id,
                f"Unable to create destination: {exc}",
            )
            return

        transfer.current_file = _ReceivingFile(
            file_id=file_id,
            relative_path=relative_path,
            expected_size=int(
                metadata.get("file_size", 0)
                or 0
            ),
            expected_checksum=str(
                metadata.get("sha256", "")
                or ""
            ),
            part_path=part_path,
            final_path=final_path,
            file_handle=file_handle,
            hasher=hashlib.sha256(),
        )
        transfer.last_activity = time.monotonic()

        self.pending_requests.pop(
            frame.transfer_id,
            None,
        )

        self.logger.info(
            "Receiving artifact file "
            "artifact_id=%s file_id=%s into %s",
            artifact_id,
            file_id,
            part_path,
        )

    def _handle_chunk(
        self,
        frame: ArtifactTransferFrame,
    ) -> None:
        transfer = self.active_downloads.get(
            frame.transfer_id
        )

        if (
            transfer is None
            or transfer.current_file is None
        ):
            self.fail_request(
                frame.transfer_id,
                "Received chunk before START",
            )
            return

        current = transfer.current_file
        transfer.last_activity = time.monotonic()

        if frame.sequence != current.expected_sequence:
            self.fail_request(
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
            self.fail_request(
                frame.transfer_id,
                f"Unable to write artifact: {exc}",
            )
            return

        current.hasher.update(data)
        current.received_size += len(data)
        current.expected_sequence += 1
        transfer.received_total_size += len(data)

        if transfer.expected_total_size > 0:
            percent = min(
                99,
                int(
                    (
                        transfer.received_total_size
                        * 100
                    )
                    / transfer.expected_total_size
                ),
            )

            self._set_download_button(
                True,
                f"Downloading {percent}%",
            )

    def _handle_file_complete(
        self,
        frame: ArtifactTransferFrame,
    ) -> None:
        transfer = self.active_downloads.get(
            frame.transfer_id
        )

        if (
            transfer is None
            or transfer.current_file is None
        ):
            self.fail_request(
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
            and received_file_id != current.file_id
        ):
            self.fail_request(
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
            current.expected_size
            and current.received_size
            != current.expected_size
        ):
            self.fail_request(
                frame.transfer_id,
                (
                    f"Size mismatch for "
                    f"{current.relative_path}: received "
                    f"{current.received_size}, expected "
                    f"{current.expected_size}"
                ),
            )
            return

        if (
            current.expected_checksum
            and actual_checksum
            != current.expected_checksum
        ):
            self.fail_request(
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
            self.fail_request(
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
        transfer.last_activity = time.monotonic()

        self.logger.info(
            "Completed artifact file "
            "artifact_id=%s file_id=%s path=%s",
            transfer.artifact_id,
            current.file_id,
            current.final_path,
        )


    def _handle_complete(
        self,
        frame: ArtifactTransferFrame,
    ) -> None:
        transfer = self.active_downloads.get(
            frame.transfer_id
        )

        if transfer is None:
            self.fail_request(
                frame.transfer_id,
                "Received COMPLETE before START",
            )
            return

        if transfer.current_file is not None:
            self.fail_request(
                frame.transfer_id,
                "Received COMPLETE before the current file completed",
            )
            return

        metadata = frame.metadata or {}

        expected_file_count = int(
            metadata.get(
                "file_count",
                transfer.expected_file_count,
            )
            or transfer.expected_file_count
            or 0
        )

        expected_total_size = int(
            metadata.get(
                "total_size",
                transfer.expected_total_size,
            )
            or transfer.expected_total_size
            or 0
        )

        completed_file_count = len(
            transfer.completed_files
        )

        if (
            expected_file_count
            and completed_file_count
            != expected_file_count
        ):
            self.fail_request(
                frame.transfer_id,
                (
                    f"Artifact file-count mismatch: "
                    f"received {completed_file_count}, "
                    f"expected {expected_file_count}"
                ),
            )
            return

        if (
            expected_total_size
            and transfer.received_total_size
            != expected_total_size
        ):
            self.fail_request(
                frame.transfer_id,
                (
                    f"Artifact total-size mismatch: "
                    f"received {transfer.received_total_size}, "
                    f"expected {expected_total_size}"
                ),
            )
            return

        if completed_file_count <= 0:
            self.fail_request(
                frame.transfer_id,
                "Artifact completed without files",
            )
            return

        local_files = {
            file_id: file_record
            for file_id, file_record
            in transfer.completed_files.items()
        }

        if completed_file_count == 1:
            local_path = next(
                iter(local_files.values())
            )["local_path"]
        else:
            local_path = transfer.artifact_root

        self.local_cache[
            transfer.artifact_id
        ] = {
            "artifact_id": transfer.artifact_id,
            "source_id": transfer.source_id,
            "operation_id": transfer.operation_id,
            "artifact_name": transfer.artifact_name,
            "artifact_type": transfer.artifact_type,
            "file_count": completed_file_count,
            "total_size": transfer.received_total_size,
            "local_path": local_path,
            "artifact_root": transfer.artifact_root,
            "files": local_files,
            "completed_at": time.time(),
        }

        self._save_index()

        self.active_downloads.pop(
            frame.transfer_id,
            None,
        )
        self.pending_requests.pop(
            frame.transfer_id,
            None,
        )

        self.logger.info(
            "Artifact %s downloaded successfully: "
            "files=%s bytes=%s root=%s",
            transfer.artifact_id,
            completed_file_count,
            transfer.received_total_size,
            transfer.artifact_root,
        )

        self._show_status(
            "Artifact download complete"
        )

        self._set_download_button(
            False,
            "Download",
        )

        iq_select_artifact_id = str(
            getattr(
                self.frontend,
                "iq_record_select_after_download_id",
                "",
            )
            or ""
        ).strip()

        if (
            iq_select_artifact_id
            and iq_select_artifact_id
            == transfer.artifact_id
        ):
            try:
                from fissure.Dashboard.Slots import (
                    IQDataTabSlots,
                )

                IQDataTabSlots._slotIQ_ArtifactsRefreshClicked(
                    self.frontend
                )

                combo = (
                    self.frontend.ui.comboBox_iq_artifacts
                )

                matching_index = -1

                for index in range(
                    combo.count()
                ):
                    item_data = combo.itemData(
                        index,
                        QtCore.Qt.UserRole,
                    )

                    if not isinstance(
                        item_data,
                        dict,
                    ):
                        continue

                    candidate_artifact_id = str(
                        item_data.get(
                            "artifact_id",
                            "",
                        )
                        or ""
                    ).strip()

                    if (
                        candidate_artifact_id
                        == transfer.artifact_id
                    ):
                        matching_index = index
                        break

                if matching_index >= 0:
                    # Force currentIndexChanged even when the downloaded
                    # Artifact becomes row zero after refresh.
                    combo.setCurrentIndex(
                        -1
                    )
                    combo.setCurrentIndex(
                        matching_index
                    )

            except Exception as error:
                self.logger.warning(
                    "Could not refresh/select IQ Artifact "
                    "after download: %s",
                    error,
                )

            finally:
                self.frontend.iq_record_select_after_download_id = ""

        conditioner_artifact_id = str(
            getattr(
                self.frontend,
                "tsi_conditioner_last_artifact_id",
                "",
            )
            or (
                getattr(
                    self.frontend,
                    "tsi_conditioner_last_artifact_payload",
                    {},
                )
                or {}
            ).get(
                "artifact_id",
                "",
            )
            or ""
        ).strip()

        if conditioner_artifact_id == transfer.artifact_id:
            try:
                conditioner_button = (
                    self.frontend.ui
                    .pushButton_tsi_conditioner_run_download_artifact
                )
                conditioner_button.setText(
                    "Open Artifact"
                )
                conditioner_button.setEnabled(
                    True
                )
                conditioner_button.setToolTip(
                    str(local_path)
                )
            except Exception:
                pass

        if transfer.open_when_complete:
            subprocess.Popen(
                [
                    "xdg-open",
                    (
                        local_path
                        if os.path.isdir(local_path)
                        else os.path.dirname(local_path)
                    ),
                ]
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
        transfer: _ActiveDownload,
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

    def _load_index(
        self,
    ) -> Dict[str, Dict[str, object]]:
        try:
            with open(
                self.index_path,
                "r",
                encoding="utf-8",
            ) as index_file:
                loaded = json.load(index_file)

            return (
                loaded
                if isinstance(loaded, dict)
                else {}
            )

        except (OSError, ValueError):
            return {}

    def _save_index(self) -> None:
        os.makedirs(
            self.cache_root,
            exist_ok=True,
        )

        temporary_path = (
            self.index_path + ".part"
        )

        with open(
            temporary_path,
            "w",
            encoding="utf-8",
        ) as index_file:
            json.dump(
                self.local_cache,
                index_file,
                indent=2,
                sort_keys=True,
            )

        os.replace(
            temporary_path,
            self.index_path,
        )

    def _show_status(
        self,
        message: str,
    ) -> None:
        try:
            self.frontend.statusBar().showMessage(
                message,
                5000,
            )
        except Exception:
            pass

    
    def _set_download_button(
        self,
        active: bool,
        text: str,
    ) -> None:
        """
        Synchronize shared Artifact-transfer state across Tactical,
        Conditioner, and Feature Extractor.

        Only the control whose selected Artifact matches the active transfer is
        placed into the downloading state. When inactive, each control resolves
        independently from the shared local cache.
        """
        transfer_artifact_id = ""

        for request in self.pending_requests.values():
            if not isinstance(request, dict):
                continue

            transfer_artifact_id = str(
                request.get(
                    "artifact_id",
                    "",
                )
                or ""
            ).strip()

            if transfer_artifact_id:
                break

        if not transfer_artifact_id:
            for transfer in self.active_downloads.values():
                transfer_artifact_id = str(
                    getattr(
                        transfer,
                        "artifact_id",
                        "",
                    )
                    or ""
                ).strip()

                if transfer_artifact_id:
                    break

        # Tactical Artifact button.
        try:
            selected_artifact_id = str(
                getattr(
                    self.frontend,
                    "selected_tactical_node_artifact_id",
                    "",
                )
                or ""
            ).strip()

            button = (
                self.frontend.ui
                .pushButton_tactical_node_artifacts_download
            )

            matching_transfer = bool(
                active
                and selected_artifact_id
                and selected_artifact_id == transfer_artifact_id
            )

            if matching_transfer:
                button.setText(text)
                button.setEnabled(False)

            elif not active:
                local_path = self.get_local_path(
                    selected_artifact_id
                )

                button.setText(
                    "Open Folder"
                    if local_path
                    else "Download"
                )
                button.setEnabled(
                    bool(selected_artifact_id)
                )

        except Exception:
            pass

        # Conditioner Artifact button.
        try:
            selected_artifact_id = str(
                getattr(
                    self.frontend,
                    "tsi_conditioner_artifact_id",
                    "",
                )
                or ""
            ).strip()

            button = (
                self.frontend.ui
                .pushButton_tsi_conditioner_run_download_artifact
            )

            matching_transfer = bool(
                active
                and selected_artifact_id
                and selected_artifact_id == transfer_artifact_id
            )

            if matching_transfer:
                button.setText(text)
                button.setEnabled(False)

            elif not active:
                local_path = self.get_local_path(
                    selected_artifact_id
                )

                button.setText(
                    "Open Artifact"
                    if local_path
                    else "Download Artifact"
                )
                button.setEnabled(
                    bool(selected_artifact_id)
                )

        except Exception:
            pass

        # Feature Extractor analysis Artifact button.
        try:
            selected_artifact_id = str(
                getattr(
                    self.frontend,
                    "tsi_fe_artifact_id",
                    "",
                )
                or ""
            ).strip()

            button = (
                self.frontend.ui
                .pushButton_tsi_fe_run_download_artifact
            )

            matching_transfer = bool(
                active
                and selected_artifact_id
                and selected_artifact_id == transfer_artifact_id
            )

            if matching_transfer:
                button.setText(text)
                button.setEnabled(False)

            elif not active:
                local_path = self.get_local_path(
                    selected_artifact_id
                )

                button.setText(
                    "Open Artifact"
                    if local_path
                    else "Download Artifact"
                )
                button.setEnabled(
                    bool(selected_artifact_id)
                )

                button.setToolTip(
                    str(local_path)
                    if local_path
                    else (
                        f"Download analysis Artifact {selected_artifact_id}"
                        if selected_artifact_id
                        else (
                            "Run Feature Extractor with a managed Artifact "
                            "destination first."
                        )
                    )
                )

        except Exception:
            pass

        # IQ Record Artifact button.
        try:
            selected_artifact_id = str(
                getattr(
                    self.frontend,
                    "iq_record_artifact_id",
                    "",
                )
                or ""
            ).strip()

            button = (
                self.frontend.ui
                .pushButton_iq_record_download_artifact
            )

            matching_transfer = bool(
                active
                and selected_artifact_id
                and selected_artifact_id
                == transfer_artifact_id
            )

            if matching_transfer:
                button.setText(
                    text
                )
                button.setEnabled(
                    False
                )

            elif not active:
                local_path = self.get_local_path(
                    selected_artifact_id
                )

                button.setText(
                    "Open Artifact"
                    if local_path
                    else "Download Artifact"
                )
                button.setEnabled(
                    bool(
                        selected_artifact_id
                    )
                )
                button.setToolTip(
                    str(
                        local_path
                        or (
                            f"Download IQ recording Artifact "
                            f"{selected_artifact_id}"
                            if selected_artifact_id
                            else (
                                "No recording Artifact is available."
                            )
                        )
                    )
                )

        except Exception:
            pass