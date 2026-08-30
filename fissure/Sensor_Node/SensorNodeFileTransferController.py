"""Receive Dashboard-to-Sensor-Node files over the binary data plane."""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import time
from dataclasses import dataclass
from typing import Dict, Optional

import fissure.comms
import fissure.utils
from fissure.utils import plugin
from fissure.comms.ArtifactTransfer import (
    FRAME_CANCEL,
    FRAME_CHUNK,
    FRAME_COMPLETE,
    FRAME_ERROR,
    FRAME_FILE_COMPLETE,
    FRAME_START,
    ArtifactTransferFrame,
)


TRANSFER_TYPE_FILE_UPLOAD = "sensor_node_file_upload"
TRANSFER_TYPE_PLUGIN_PACKAGE = "plugin_package_upload"


@dataclass
class _IncomingFileUpload:
    transfer_id: str
    transfer_type: str
    plugin_name: str
    remote_filepath: str
    final_path: str
    part_path: str
    expected_size: int
    expected_checksum: str
    refresh_file_list: bool
    remote_folder: str
    started_at: float
    expected_sequence: int = 0
    received_size: int = 0
    chunks_received: int = 0
    file_handle: object = None
    hasher: object = None
    file_complete: bool = False


class SensorNodeFileTransferController:
    """Receive and atomically finalize generic Dashboard file uploads."""

    def __init__(self, component):
        self.component = component
        self.logger: logging.Logger = component.logger
        self.active_uploads: Dict[str, _IncomingFileUpload] = {}
        self.ignored_transfers: set[str] = set()

    async def receive_loop(self) -> None:
        """Continuously receive binary transfer frames for this Sensor Node."""
        try:
            while not self.component.shutdown:
                client = getattr(
                    self.component,
                    "artifact_transfer_client",
                    None,
                )

                if client is None:
                    return

                try:
                    frame = await client.receive()

                    if frame is not None:
                        await self.handle_frame(frame)

                except asyncio.CancelledError:
                    raise

                except Exception as exc:
                    if not self.component.shutdown:
                        self.logger.error(
                            "Sensor Node binary file-transfer receive error: %s",
                            exc,
                        )

                await asyncio.sleep(0)

        finally:
            for transfer_id in list(self.active_uploads):
                self._discard_transfer(transfer_id)

    async def handle_frame(
        self,
        frame: ArtifactTransferFrame,
    ) -> None:
        if frame.kind == FRAME_START:
            await self._handle_start(frame)
            return

        if frame.transfer_id in self.ignored_transfers:
            if frame.kind in (
                FRAME_COMPLETE,
                FRAME_CANCEL,
                FRAME_ERROR,
            ):
                self.ignored_transfers.discard(
                    frame.transfer_id
                )
            return

        if frame.kind == FRAME_CHUNK:
            await self._handle_chunk(frame)
        elif frame.kind == FRAME_FILE_COMPLETE:
            await self._handle_file_complete(frame)
        elif frame.kind == FRAME_COMPLETE:
            await self._handle_complete(frame)
        elif frame.kind in (FRAME_CANCEL, FRAME_ERROR):
            await self._handle_cancel(frame)

    async def _handle_start(
        self,
        frame: ArtifactTransferFrame,
    ) -> None:
        metadata = frame.metadata or {}

        transfer_type = str(
            metadata.get(
                "transfer_type",
                "",
            )
            or ""
        ).strip()

        if transfer_type not in {
            TRANSFER_TYPE_FILE_UPLOAD,
            TRANSFER_TYPE_PLUGIN_PACKAGE,
        }:
            self.logger.warning(
                "Ignoring unsupported Sensor Node transfer START "
                "transfer_id=%s transfer_type=%s",
                frame.transfer_id,
                transfer_type,
            )
            self.ignored_transfers.add(
                frame.transfer_id
            )
            return

        destination_node_uid = str(
            metadata.get(
                "destination_node_uid",
                "",
            )
            or ""
        ).strip()

        if (
            destination_node_uid
            and destination_node_uid != self.component.uuid
        ):
            await self._reject_start(
                frame,
                "File upload was routed to the wrong Sensor Node",
            )
            return

        plugin_name = ""

        if transfer_type == TRANSFER_TYPE_PLUGIN_PACKAGE:
            plugin_name = str(
                metadata.get(
                    "plugin_name",
                    "",
                )
                or ""
            ).strip()

            if (
                str(
                    getattr(
                        self.component,
                        "local_remote",
                        "",
                    )
                    or ""
                ).strip().lower()
                != "remote"
            ):
                await self._reject_start(
                    frame,
                    "Plugin packages may only be deployed to remote Sensor Nodes",
                )
                return

            if (
                str(
                    getattr(
                        self.component,
                        "network_type",
                        "",
                    )
                    or ""
                ).strip().lower()
                != "ip"
            ):
                await self._reject_start(
                    frame,
                    "Plugin package deployment requires an IP Sensor Node",
                )
                return

            reservations = getattr(
                self.component,
                "plugin_deployment_reservations",
                {},
            ) or {}

            if reservations.get(
                plugin_name
            ) != frame.transfer_id:
                await self._reject_start(
                    frame,
                    "Plugin package was not prepared/reserved by this Sensor Node",
                )
                return

            try:
                final_path = (
                    plugin.get_plugin_package_staging_path(
                        plugin_name,
                        frame.transfer_id,
                        create_folder=True,
                    )
                )
            except Exception as exc:
                await self._reject_start(
                    frame,
                    str(exc),
                )
                return

            remote_filepath = (
                f"/Plugins/.incoming/"
                f"{os.path.basename(final_path)}"
            )

        else:
            remote_filepath = str(
                metadata.get(
                    "remote_filepath",
                    "",
                )
                or ""
            ).strip()

            try:
                final_path = self._resolve_destination_path(
                    remote_filepath
                )
            except Exception as exc:
                await self._reject_start(
                    frame,
                    str(exc),
                )
                return

        parent_folder = os.path.dirname(final_path)

        if not os.path.isdir(parent_folder):
            await self._reject_start(
                frame,
                (
                    "Sensor Node destination folder does not exist: "
                    f"{parent_folder}"
                ),
            )
            return

        expected_size = int(
            metadata.get(
                "file_size",
                0,
            )
            or 0
        )

        expected_checksum = str(
            metadata.get(
                "sha256",
                "",
            )
            or ""
        ).strip().lower()

        if not expected_checksum:
            await self._reject_start(
                frame,
                "File upload is missing its SHA-256 checksum",
            )
            return

        self._discard_transfer(frame.transfer_id)

        basename = os.path.basename(final_path)
        part_path = os.path.join(
            parent_folder,
            f".{basename}.{frame.transfer_id}.part",
        )

        try:
            if os.path.exists(part_path):
                os.remove(part_path)

            file_handle = open(part_path, "wb")
        except OSError as exc:
            await self._reject_start(
                frame,
                f"Unable to open Sensor Node destination: {exc}",
            )
            return

        upload = _IncomingFileUpload(
            transfer_id=frame.transfer_id,
            transfer_type=transfer_type,
            plugin_name=plugin_name,
            remote_filepath=remote_filepath,
            final_path=final_path,
            part_path=part_path,
            expected_size=expected_size,
            expected_checksum=expected_checksum,
            refresh_file_list=bool(
                metadata.get(
                    "refresh_file_list",
                    False,
                )
            ),
            remote_folder=os.path.dirname(remote_filepath) or "/",
            started_at=time.monotonic(),
            file_handle=file_handle,
            hasher=hashlib.sha256(),
        )

        self.active_uploads[frame.transfer_id] = upload

        self.logger.info(
            "Starting binary Sensor Node file upload "
            "transfer_id=%s remote_filepath=%s bytes=%s",
            frame.transfer_id,
            remote_filepath,
            expected_size,
        )

    async def _handle_chunk(
        self,
        frame: ArtifactTransferFrame,
    ) -> None:
        upload = self.active_uploads.get(
            frame.transfer_id
        )

        if upload is None:
            return

        if frame.sequence != upload.expected_sequence:
            await self._fail_transfer(
                frame.transfer_id,
                (
                    "Unexpected file-transfer chunk sequence "
                    f"{frame.sequence}; expected "
                    f"{upload.expected_sequence}"
                ),
            )
            return

        data = frame.data or b""

        try:
            upload.file_handle.write(data)
        except OSError as exc:
            await self._fail_transfer(
                frame.transfer_id,
                f"Unable to write Sensor Node file: {exc}",
            )
            return

        upload.hasher.update(data)
        upload.received_size += len(data)
        upload.chunks_received += 1
        upload.expected_sequence += 1

        if (
            upload.expected_size >= 0
            and upload.received_size > upload.expected_size
        ):
            await self._fail_transfer(
                frame.transfer_id,
                "Received more file data than declared by the sender",
            )

    async def _handle_file_complete(
        self,
        frame: ArtifactTransferFrame,
    ) -> None:
        upload = self.active_uploads.get(
            frame.transfer_id
        )

        if upload is None:
            return

        self._close_handle(upload)

        actual_checksum = upload.hasher.hexdigest()

        if upload.received_size != upload.expected_size:
            await self._fail_transfer(
                frame.transfer_id,
                (
                    "Sensor Node file size mismatch: received "
                    f"{upload.received_size}, expected "
                    f"{upload.expected_size}"
                ),
            )
            return

        if actual_checksum != upload.expected_checksum:
            await self._fail_transfer(
                frame.transfer_id,
                "Sensor Node file SHA-256 verification failed",
            )
            return

        try:
            os.replace(
                upload.part_path,
                upload.final_path,
            )
        except OSError as exc:
            await self._fail_transfer(
                frame.transfer_id,
                f"Unable to finalize Sensor Node file: {exc}",
            )
            return

        upload.file_complete = True

    async def _handle_complete(
        self,
        frame: ArtifactTransferFrame,
    ) -> None:
        upload = self.active_uploads.pop(
            frame.transfer_id,
            None,
        )

        if upload is None:
            return

        if not upload.file_complete:
            self._discard_upload(upload)
            await self._send_status(
                frame.transfer_id,
                False,
                "Transfer completed before the file was verified",
                upload,
            )
            return

        elapsed = max(
            0.000001,
            time.monotonic() - upload.started_at,
        )
        mib_per_second = (
            upload.received_size
            / (1024.0 * 1024.0)
            / elapsed
        )

        self.logger.info(
            "Completed binary Sensor Node file upload "
            "transfer_id=%s path=%s bytes=%s elapsed=%.3fs rate=%.2f MiB/s",
            frame.transfer_id,
            upload.final_path,
            upload.received_size,
            elapsed,
            mib_per_second,
        )

        completion_message = (
            "Plugin package transfer completed"
            if upload.transfer_type
            == TRANSFER_TYPE_PLUGIN_PACKAGE
            else "File transfer completed"
        )

        await self._send_status(
            frame.transfer_id,
            True,
            completion_message,
            upload,
            elapsed_seconds=elapsed,
            mib_per_second=mib_per_second,
        )

    async def _handle_cancel(
        self,
        frame: ArtifactTransferFrame,
    ) -> None:
        upload = self.active_uploads.pop(
            frame.transfer_id,
            None,
        )

        if upload is None:
            return

        self._discard_upload(upload)

        message = str(
            (frame.metadata or {}).get(
                "message",
                "File transfer cancelled",
            )
            or "File transfer cancelled"
        )

        await self._send_status(
            frame.transfer_id,
            False,
            message,
            upload,
        )

    async def _reject_start(
        self,
        frame: ArtifactTransferFrame,
        message: str,
    ) -> None:
        metadata = frame.metadata or {}

        transfer_type = str(
            metadata.get(
                "transfer_type",
                "",
            )
            or ""
        ).strip()

        plugin_name = str(
            metadata.get(
                "plugin_name",
                "",
            )
            or ""
        ).strip()

        remote_filepath = str(
            metadata.get(
                "remote_filepath",
                "",
            )
            or ""
        ).strip()

        self.ignored_transfers.add(
            frame.transfer_id
        )

        await self._send_status(
            frame.transfer_id,
            False,
            message,
            None,
            transfer_type=transfer_type,
            plugin_name=plugin_name,
            remote_filepath=remote_filepath,
            refresh_file_list=bool(
                metadata.get(
                    "refresh_file_list",
                    False,
                )
            ),
            remote_folder=os.path.dirname(
                remote_filepath
            ) or "/",
        )

    async def _fail_transfer(
        self,
        transfer_id: str,
        message: str,
    ) -> None:
        upload = self.active_uploads.pop(
            transfer_id,
            None,
        )

        if upload is None:
            return

        self._discard_upload(upload)
        self.ignored_transfers.add(transfer_id)

        self.logger.error(
            "Binary Sensor Node file upload failed "
            "transfer_id=%s: %s",
            transfer_id,
            message,
        )

        await self._send_status(
            transfer_id,
            False,
            message,
            upload,
        )

    async def _send_status(
        self,
        transfer_id: str,
        success: bool,
        message: str,
        upload: Optional[_IncomingFileUpload],
        *,
        transfer_type: str = "",
        plugin_name: str = "",
        remote_filepath: str = "",
        refresh_file_list: bool = False,
        remote_folder: str = "",
        elapsed_seconds: float = 0.0,
        mib_per_second: float = 0.0,
    ) -> None:
        if upload is not None:
            transfer_type = upload.transfer_type
            plugin_name = upload.plugin_name
            remote_filepath = upload.remote_filepath
            refresh_file_list = upload.refresh_file_list
            remote_folder = upload.remote_folder
            bytes_received = upload.received_size
        else:
            bytes_received = 0

        parameters = {
            "transfer_id": transfer_id,
            "transfer_type": str(
                transfer_type
                or ""
            ),
            "plugin_name": str(
                plugin_name
                or ""
            ),
            "success": bool(success),
            "message": str(message),
            "remote_filepath": remote_filepath,
            "remote_folder": remote_folder,
            "bytes_received": int(bytes_received),
            "elapsed_seconds": float(elapsed_seconds),
            "mib_per_second": float(mib_per_second),
            "refresh_file_list": bool(refresh_file_list),
        }

        msg = {
            fissure.comms.MessageFields.IDENTIFIER:
                self.component.identifier,
            fissure.comms.MessageFields.MESSAGE_NAME:
                "sensorNodeFileTransferStatus",
            fissure.comms.MessageFields.PARAMETERS:
                parameters,
        }

        await self.component.hiprfisr_socket.send_msg(
            fissure.comms.MessageTypes.COMMANDS,
            msg,
        )

    @staticmethod
    def _close_handle(upload: _IncomingFileUpload) -> None:
        handle = upload.file_handle

        if handle is None:
            return

        try:
            handle.flush()
        except OSError:
            pass

        try:
            handle.close()
        except OSError:
            pass

        upload.file_handle = None

    def _discard_transfer(self, transfer_id: str) -> None:
        upload = self.active_uploads.pop(
            transfer_id,
            None,
        )

        if upload is not None:
            self._discard_upload(upload)

    def _discard_upload(
        self,
        upload: _IncomingFileUpload,
    ) -> None:
        self._close_handle(upload)

        if (
            upload.part_path
            and os.path.isfile(upload.part_path)
        ):
            try:
                os.remove(upload.part_path)
            except OSError:
                pass

    @staticmethod
    def _resolve_destination_path(
        remote_filepath: str,
    ) -> str:
        if not remote_filepath:
            raise ValueError(
                "Sensor Node destination filepath is empty"
            )

        if remote_filepath.startswith(
            "/IQ_Data_Playback"
        ):
            return os.path.join(
                fissure.utils.SENSOR_NODE_DIR,
                "IQ_Data_Playback",
                "playback.iq",
            )

        relative_path = os.path.normpath(
            remote_filepath.lstrip("/")
        )

        if (
            not relative_path
            or relative_path == "."
            or relative_path == ".."
            or relative_path.startswith("../")
        ):
            raise ValueError(
                "Invalid Sensor Node destination filepath"
            )

        sensor_node_root = os.path.abspath(
            fissure.utils.SENSOR_NODE_DIR
        )
        final_path = os.path.abspath(
            os.path.join(
                sensor_node_root,
                relative_path,
            )
        )

        if os.path.commonpath(
            [sensor_node_root, final_path]
        ) != sensor_node_root:
            raise ValueError(
                "Sensor Node destination escapes the managed node directory"
            )

        return final_path