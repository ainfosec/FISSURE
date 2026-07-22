"""Dedicated binary transport for managed FISSURE artifacts.

This module intentionally does not use :class:`FissureZMQNode`. Artifact bytes
must remain isolated from the heartbeat and JSON command channels.
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple
import asyncio

import zmq
import zmq.asyncio
import zmq.auth

import fissure.utils


ARTIFACT_TRANSFER_PORT = 6102
ARTIFACT_CHUNK_SIZE = 1024 * 1024
ARTIFACT_POLL_TIMEOUT_MS = 50

FRAME_REGISTER = b"REGISTER"
FRAME_REGISTERED = b"REGISTERED"
FRAME_START = b"START"
FRAME_CHUNK = b"CHUNK"
FRAME_COMPLETE = b"COMPLETE"
FRAME_ERROR = b"ERROR"
FRAME_CANCEL = b"CANCEL"

ROLE_DASHBOARD = "dashboard"
ROLE_SENSOR_NODE = "sensor_node"
ROLE_HIPRFISR = "hiprfisr"

_SERVER_CERT_DIR = "server"
_CLIENT_CERT_DIR = "clients"


@dataclass(frozen=True)
class ArtifactTransferFrame:
    """Decoded transfer-plane message."""

    kind: bytes
    transfer_id: str
    metadata: Optional[Dict[str, Any]] = None
    sequence: Optional[int] = None
    data: Optional[bytes] = None


def build_artifact_endpoint(host: str, port: int = ARTIFACT_TRANSFER_PORT) -> str:
    """Build the dedicated TCP endpoint used by artifact clients."""
    return f"tcp://{host}:{int(port)}"


def _encode_json(value: Dict[str, Any]) -> bytes:
    return json.dumps(value, separators=(",", ":")).encode("utf-8")


def _decode_json(value: bytes) -> Dict[str, Any]:
    decoded = json.loads(value.decode("utf-8"))
    if not isinstance(decoded, dict):
        raise ValueError("Artifact transfer metadata must be a JSON object")
    return decoded


class ArtifactTransferRouter:
    """HIPRFISR-side ROUTER for forwarding artifact transfer frames.

    The router never assembles an artifact. It only validates transfer IDs and
    forwards multipart frames between registered peers.
    """

    def __init__(
        self,
        bind_endpoint: str,
        logger: Optional[logging.Logger] = None,
        context: Optional[zmq.asyncio.Context] = None,
    ) -> None:
        self.logger = logger or logging.getLogger(__name__)
        self.context = context or fissure.utils.get_zmq_context()
        self.socket = self.context.socket(zmq.ROUTER)
        self.socket.setsockopt(zmq.LINGER, 0)
        self.socket.setsockopt(zmq.SNDHWM, 32)
        self.socket.setsockopt(zmq.RCVHWM, 32)
        self.socket.setsockopt(zmq.ROUTER_MANDATORY, 1)

        self.bind_endpoint = bind_endpoint
        self._registered: Dict[bytes, Dict[str, str]] = {}
        self._dashboard_identity: Optional[bytes] = None
        self._sensor_identities: Dict[str, bytes] = {}
        self._transfer_destinations: Dict[str, bytes] = {}
        self._local_transfers: set[str] = set()
        self._closed = False

        self._initialize_auth()

    def _initialize_auth(self) -> None:
        private_key = os.path.join(
            fissure.utils.CERT_DIR,
            _SERVER_CERT_DIR,
            "server.key_secret",
        )
        public_key, secret_key = zmq.auth.load_certificate(private_key)
        self.socket.curve_publickey = public_key
        self.socket.curve_secretkey = secret_key
        self.socket.curve_server = True

    def start(self) -> None:
        self.socket.bind(self.bind_endpoint)
        self.logger.info(
            "Artifact transfer router listening on %s",
            self.bind_endpoint,
        )

    def register_transfer(self, transfer_id: str, destination_role: str) -> bool:
        """Associate a transfer ID with its receiving peer."""
        if destination_role == ROLE_HIPRFISR:
            self._local_transfers.add(transfer_id)
            return True

        if destination_role == ROLE_DASHBOARD:
            destination = self._dashboard_identity
        else:
            destination = self._sensor_identities.get(destination_role)

        if destination is None:
            return False

        self._transfer_destinations[transfer_id] = destination
        return True

    def remove_transfer(self, transfer_id: str) -> None:
        self._transfer_destinations.pop(transfer_id, None)
        self._local_transfers.discard(transfer_id)

    def get_sensor_identity(self, node_uid: str) -> Optional[bytes]:
        return self._sensor_identities.get(node_uid)

    async def receive_and_route(self) -> Optional[Tuple[bytes, ArtifactTransferFrame]]:
        """Receive one frame and route it when it belongs to an active transfer.

        Registration frames are handled locally. Transfer frames are returned to
        HIPRFISR after forwarding so the coordinator can update transfer state.
        """
        if self._closed:
            return None

        events = await self.socket.poll(ARTIFACT_POLL_TIMEOUT_MS)
        if not events:
            return None

        frames = await self.socket.recv_multipart()
        if len(frames) < 2:
            self.logger.warning("Discarding malformed artifact transfer frame")
            return None

        sender_identity = frames[0]
        payload = frames[1:]
        kind = payload[0]

        if kind == FRAME_REGISTER:
            await self._handle_registration(sender_identity, payload)
            return None

        decoded = self._decode_transfer_frame(payload)
        is_local = decoded.transfer_id in self._local_transfers
        destination = self._transfer_destinations.get(decoded.transfer_id)
        if not is_local and destination is None:
            await self.send_error(
                sender_identity,
                decoded.transfer_id,
                "Unknown or inactive transfer ID",
            )
            return sender_identity, decoded

        if not is_local:
            try:
                await self.socket.send_multipart([destination, *payload])
            except zmq.ZMQError as exc:
                self.logger.error(
                    "Unable to route artifact transfer %s: %s",
                    decoded.transfer_id,
                    exc,
                )
                await self.send_error(
                    sender_identity,
                    decoded.transfer_id,
                    "Transfer destination is unavailable",
                )

        if kind in (FRAME_COMPLETE, FRAME_ERROR, FRAME_CANCEL):
            self.remove_transfer(decoded.transfer_id)

        return sender_identity, decoded

    async def _handle_registration(self, identity: bytes, payload: list[bytes]) -> None:
        if len(payload) != 2:
            self.logger.warning("Discarding malformed artifact registration")
            return

        metadata = _decode_json(payload[1])
        role = str(metadata.get("role", "")).strip()
        node_uid = str(metadata.get("node_uid", "")).strip()

        if role == ROLE_DASHBOARD:
            self._dashboard_identity = identity
        elif role == ROLE_SENSOR_NODE and node_uid:
            self._sensor_identities[node_uid] = identity
        else:
            await self.send_error(identity, "", "Invalid transfer registration")
            return

        self._registered[identity] = {"role": role, "node_uid": node_uid}
        await self.socket.send_multipart(
            [identity, FRAME_REGISTERED, _encode_json({"role": role, "node_uid": node_uid})]
        )
        self.logger.info(
            "Registered artifact transfer peer role=%s node_uid=%s",
            role,
            node_uid or "-",
        )

    @staticmethod
    def _decode_transfer_frame(payload: list[bytes]) -> ArtifactTransferFrame:
        kind = payload[0]

        if kind in (FRAME_START, FRAME_COMPLETE, FRAME_ERROR, FRAME_CANCEL):
            if len(payload) != 3:
                raise ValueError("Malformed artifact metadata frame")
            return ArtifactTransferFrame(
                kind=kind,
                transfer_id=payload[1].decode("utf-8"),
                metadata=_decode_json(payload[2]),
            )

        if kind == FRAME_CHUNK:
            if len(payload) != 4:
                raise ValueError("Malformed artifact chunk frame")
            return ArtifactTransferFrame(
                kind=kind,
                transfer_id=payload[1].decode("utf-8"),
                sequence=int.from_bytes(payload[2], "big", signed=False),
                data=payload[3],
            )

        raise ValueError(f"Unknown artifact transfer frame kind: {kind!r}")

    async def send_error(self, identity: bytes, transfer_id: str, message: str) -> None:
        await self.socket.send_multipart(
            [
                identity,
                FRAME_ERROR,
                transfer_id.encode("utf-8"),
                _encode_json({"message": message}),
            ]
        )

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self.socket.close(0)


class ArtifactTransferClient:
    """Dashboard/Sensor Node DEALER for binary artifact transfer."""

    REGISTRATION_INTERVAL_SECONDS = 5.0

    def __init__(
        self,
        endpoint: str,
        identity: str,
        role: str,
        node_uid: str = "",
        logger: Optional[logging.Logger] = None,
        context: Optional[zmq.asyncio.Context] = None,
    ) -> None:
        self.logger = logger or logging.getLogger(__name__)
        self.context = context or fissure.utils.get_zmq_context()
        self.socket = self.context.socket(zmq.DEALER)
        self.socket.setsockopt(zmq.LINGER, 0)
        self.socket.setsockopt(zmq.SNDHWM, 16)
        self.socket.setsockopt(zmq.RCVHWM, 32)
        self.socket.setsockopt(zmq.IMMEDIATE, 1)
        self.socket.setsockopt_string(zmq.IDENTITY, identity)

        self.endpoint = endpoint
        self.identity = identity
        self.role = role
        self.node_uid = node_uid
        self._closed = False
        self._send_lock = asyncio.Lock()
        self._registration_task: Optional[asyncio.Task] = None

        self._initialize_auth()

    def _initialize_auth(self) -> None:
        client_key = os.path.join(
            fissure.utils.CERT_DIR,
            _CLIENT_CERT_DIR,
            "client_0.key_secret",
        )
        server_key = os.path.join(
            fissure.utils.CERT_DIR,
            _SERVER_CERT_DIR,
            "server.key",
        )
        public_key, secret_key = zmq.auth.load_certificate(client_key)
        server_public_key, _ = zmq.auth.load_certificate(server_key)
        self.socket.curve_publickey = public_key
        self.socket.curve_secretkey = secret_key
        self.socket.curve_serverkey = server_public_key

    async def _send_multipart(self, frames: List[bytes]) -> None:
        """Serialize writes made by transfer and registration coroutines."""
        if self._closed:
            raise RuntimeError("Artifact transfer client is closed")

        async with self._send_lock:
            await self.socket.send_multipart(frames)

    async def _send_registration(self) -> None:
        await self._send_multipart(
            [
                FRAME_REGISTER,
                _encode_json(
                    {
                        "role": self.role,
                        "node_uid": self.node_uid,
                    }
                ),
            ]
        )

    async def _registration_loop(self) -> None:
        """
        Periodically refresh registration.

        A DEALER socket reconnects automatically after the HIPRFISR ROUTER
        restarts, but the new router has no memory of the client's prior
        REGISTER frame. Re-sending REGISTER rebuilds that peer mapping.
        """
        while not self._closed:
            try:
                await self._send_registration()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                if not self._closed:
                    self.logger.debug(
                        "Artifact transfer registration refresh failed: %s",
                        exc,
                    )

            await asyncio.sleep(self.REGISTRATION_INTERVAL_SECONDS)

    async def connect(self) -> None:
        self.socket.connect(self.endpoint)
        await self._send_registration()

        if (
            self._registration_task is None
            or self._registration_task.done()
        ):
            self._registration_task = asyncio.create_task(
                self._registration_loop()
            )
            self._registration_task.set_name(
                f"Artifact Registration {self.identity}"
            )

    async def receive(self) -> Optional[ArtifactTransferFrame]:
        if self._closed:
            return None

        events = await self.socket.poll(ARTIFACT_POLL_TIMEOUT_MS)
        if not events:
            return None

        payload = await self.socket.recv_multipart()
        if not payload:
            return None

        if payload[0] == FRAME_REGISTERED:
            metadata = _decode_json(payload[1]) if len(payload) > 1 else {}
            self.logger.info(
                "Artifact transfer client registered role=%s node_uid=%s",
                metadata.get("role", self.role),
                metadata.get("node_uid", self.node_uid) or "-",
            )
            return None

        return ArtifactTransferRouter._decode_transfer_frame(payload)

    async def send_start(
        self,
        transfer_id: str,
        metadata: Dict[str, Any],
    ) -> None:
        await self._send_multipart(
            [
                FRAME_START,
                transfer_id.encode("utf-8"),
                _encode_json(metadata),
            ]
        )

    async def send_chunk(
        self,
        transfer_id: str,
        sequence: int,
        data: bytes,
    ) -> None:
        await self._send_multipart(
            [
                FRAME_CHUNK,
                transfer_id.encode("utf-8"),
                int(sequence).to_bytes(8, "big", signed=False),
                data,
            ]
        )

    async def send_complete(
        self,
        transfer_id: str,
        metadata: Dict[str, Any],
    ) -> None:
        await self._send_multipart(
            [
                FRAME_COMPLETE,
                transfer_id.encode("utf-8"),
                _encode_json(metadata),
            ]
        )

    async def send_error(
        self,
        transfer_id: str,
        message: str,
    ) -> None:
        await self._send_multipart(
            [
                FRAME_ERROR,
                transfer_id.encode("utf-8"),
                _encode_json({"message": message}),
            ]
        )

    async def send_cancel(
        self,
        transfer_id: str,
        message: str = "Cancelled",
    ) -> None:
        await self._send_multipart(
            [
                FRAME_CANCEL,
                transfer_id.encode("utf-8"),
                _encode_json({"message": message}),
            ]
        )

    def close(self) -> None:
        if self._closed:
            return

        self._closed = True

        registration_task = self._registration_task
        if registration_task is not None and not registration_task.done():
            registration_task.cancel()
        self._registration_task = None

        self.socket.close(0)