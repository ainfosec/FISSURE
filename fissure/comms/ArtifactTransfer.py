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
from zmq.utils.monitor import parse_monitor_message

import fissure.utils


ARTIFACT_TRANSFER_PORT = 6102
ARTIFACT_CHUNK_SIZE = 1024 * 1024
ARTIFACT_POLL_TIMEOUT_MS = 50

FRAME_REGISTER = b"REGISTER"
FRAME_REGISTERED = b"REGISTERED"
FRAME_START = b"START"
FRAME_CHUNK = b"CHUNK"
FRAME_COMPLETE = b"COMPLETE"
FRAME_FILE_COMPLETE = b"FILE_COMPLETE"
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

    async def receive_and_route(
        self,
    ) -> Optional[Tuple[bytes, ArtifactTransferFrame]]:
        """
        Receive one transfer-plane frame and route it to its destination.

        Existing artifact downloads continue to use explicit transfer
        registration. Dashboard-to-Sensor-Node file uploads may instead
        declare ``destination_node_uid`` in their START metadata; the router
        resolves that already-registered IP Sensor Node and creates the route
        before forwarding the START frame.
        """
        if self._closed:
            return None

        events = await self.socket.poll(
            ARTIFACT_POLL_TIMEOUT_MS
        )

        if not events:
            return None

        frames = await self.socket.recv_multipart()

        if len(frames) < 2:
            self.logger.warning(
                "Discarding malformed artifact transfer frame"
            )
            return None

        sender_identity = frames[0]
        payload = frames[1:]
        kind = payload[0]

        if kind == FRAME_REGISTER:
            await self._handle_registration(
                sender_identity,
                payload,
            )
            return None

        decoded = self._decode_transfer_frame(
            payload
        )

        is_local = (
            decoded.transfer_id
            in self._local_transfers
        )

        destination = (
            self._transfer_destinations.get(
                decoded.transfer_id
            )
        )

        if (
            not is_local
            and destination is None
            and kind == FRAME_START
        ):
            sender_registration = self._registered.get(
                sender_identity,
                {},
            )

            metadata = decoded.metadata or {}
            destination_node_uid = str(
                metadata.get(
                    "destination_node_uid",
                    "",
                )
                or ""
            ).strip()

            if (
                sender_registration.get("role") == ROLE_DASHBOARD
                and destination_node_uid
            ):
                destination = self._sensor_identities.get(
                    destination_node_uid
                )

                if destination is None:
                    await self.send_error(
                        sender_identity,
                        decoded.transfer_id,
                        (
                            "Sensor Node binary transfer peer is unavailable. "
                            "Dashboard-to-node file upload requires an IP "
                            "Sensor Node connected to the data plane."
                        ),
                    )
                    return None

                self._transfer_destinations[
                    decoded.transfer_id
                ] = destination

                self.logger.info(
                    "Registered Dashboard file upload transfer_id=%s "
                    "destination_node_uid=%s",
                    decoded.transfer_id,
                    destination_node_uid,
                )

        if not is_local and destination is None:
            await self.send_error(
                sender_identity,
                decoded.transfer_id,
                "Unknown or inactive transfer ID",
            )
            return None

        if is_local:
            if kind in (
                FRAME_COMPLETE,
                FRAME_ERROR,
                FRAME_CANCEL,
            ):
                self.remove_transfer(
                    decoded.transfer_id
                )

            return sender_identity, decoded

        try:
            await self.socket.send_multipart(
                [
                    destination,
                    *payload,
                ]
            )

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

            self.remove_transfer(
                decoded.transfer_id
            )
            return None

        if kind in (
            FRAME_COMPLETE,
            FRAME_ERROR,
            FRAME_CANCEL,
        ):
            self.remove_transfer(
                decoded.transfer_id
            )

        return None

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
    def _decode_transfer_frame(
        payload: list[bytes],
    ) -> ArtifactTransferFrame:
        kind = payload[0]

        if kind in (
            FRAME_START,
            FRAME_FILE_COMPLETE,
            FRAME_COMPLETE,
            FRAME_ERROR,
            FRAME_CANCEL,
        ):
            if len(payload) != 3:
                raise ValueError(
                    "Malformed artifact metadata frame"
                )

            return ArtifactTransferFrame(
                kind=kind,
                transfer_id=payload[1].decode("utf-8"),
                metadata=_decode_json(payload[2]),
            )

        if kind == FRAME_CHUNK:
            if len(payload) != 4:
                raise ValueError(
                    "Malformed artifact chunk frame"
                )

            return ArtifactTransferFrame(
                kind=kind,
                transfer_id=payload[1].decode("utf-8"),
                sequence=int.from_bytes(
                    payload[2],
                    "big",
                    signed=False,
                ),
                data=payload[3],
            )

        raise ValueError(
            f"Unknown artifact transfer frame kind: {kind!r}"
        )

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
    """Dashboard/Sensor Node DEALER for binary artifact transfer.

    Registration is event-driven:
    - one REGISTER is sent when the client starts;
    - ZeroMQ reconnect events trigger a new REGISTER only after a real
      disconnect/reconnect cycle;
    - no periodic registration traffic is generated.
    """

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

        self._monitor_socket = None
        self._monitor_task: Optional[asyncio.Task] = None
        self._ignore_next_connected_event = False
        self._registered = False

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

    async def _monitor_connection(self) -> None:
        """
        Re-register only after ZeroMQ reports a real reconnect.

        DEALER sockets reconnect transparently when HIPRFISR restarts, but the
        replacement ROUTER has no peer-registration state. The monitor reports
        EVENT_CONNECTED again after that reconnect, which is the correct time
        to send a new REGISTER frame.
        """
        monitor_socket = self._monitor_socket
        if monitor_socket is None:
            return

        while not self._closed:
            try:
                frames = await monitor_socket.recv_multipart()
                monitor_event = parse_monitor_message(frames)
                event = int(monitor_event.get("event", 0))

                if event == zmq.EVENT_DISCONNECTED:
                    self._registered = False
                    continue

                if event == zmq.EVENT_CONNECTED:
                    if self._ignore_next_connected_event:
                        self._ignore_next_connected_event = False
                        continue

                    self.logger.debug(
                        "Artifact transfer connection restored; "
                        "re-registering role=%s node_uid=%s",
                        self.role,
                        self.node_uid or "-",
                    )

                    await self._send_registration()
                    continue

                if event == zmq.EVENT_MONITOR_STOPPED:
                    return

            except asyncio.CancelledError:
                raise
            except Exception as exc:
                if not self._closed:
                    self.logger.debug(
                        "Artifact transfer socket monitor failed: %s",
                        exc,
                    )
                return

    async def connect(self) -> None:
        if self._closed:
            raise RuntimeError("Artifact transfer client is closed")

        if self._monitor_task is None:
            self._monitor_socket = self.socket.get_monitor_socket(
                events=(
                    zmq.EVENT_CONNECTED
                    | zmq.EVENT_DISCONNECTED
                    | zmq.EVENT_MONITOR_STOPPED
                )
            )

            self._ignore_next_connected_event = True

            self._monitor_task = asyncio.create_task(
                self._monitor_connection()
            )
            self._monitor_task.set_name(
                f"Artifact Connection Monitor {self.identity}"
            )

        self.socket.connect(self.endpoint)

        # Initial registration is sent exactly once here. Because IMMEDIATE is
        # enabled, the send waits until the DEALER has a live ROUTER connection.
        await self._send_registration()

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

            was_registered = self._registered
            self._registered = True

            if not was_registered:
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

    async def send_file_complete(
        self,
        transfer_id: str,
        metadata: Dict[str, Any],
    ) -> None:
        """
        Finish one file within a multi-file artifact transfer.

        The transfer remains active until send_complete() sends the final
        artifact-level completion frame.
        """
        await self._send_multipart(
            [
                FRAME_FILE_COMPLETE,
                transfer_id.encode("utf-8"),
                _encode_json(metadata),
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

        monitor_task = self._monitor_task
        if monitor_task is not None and not monitor_task.done():
            monitor_task.cancel()
        self._monitor_task = None

        monitor_socket = self._monitor_socket
        if monitor_socket is not None:
            try:
                monitor_socket.close(0)
            except Exception:
                pass
        self._monitor_socket = None

        try:
            self.socket.disable_monitor()
        except Exception:
            pass

        self.socket.close(0)