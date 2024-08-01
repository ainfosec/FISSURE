from .Address import Address
from .constants import MessageFields, MessageTypes
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Set

import fissure.utils
import json
import logging
import os
import time
import zmq
import zmq.asyncio
import zmq.auth
import zmq.auth.asyncio
import asyncio

SERVER = "server"
CLIENTS = "clients"

POLL_TIMEOUT = 50


class FissureZMQNode(ABC):
    """Fissure ZMQ Node Base Class"""

    logger: logging.Logger
    certs: str = fissure.utils.CERT_DIR
    ctx: zmq.asyncio.Context
    heartbeat_channel: zmq.asyncio.Socket
    message_channel: zmq.asyncio.Socket
    sock_type: zmq.SocketType
    sockid: str
    parent_component: str
    name: str

    def __init__(
        self,
        sock_type: zmq.SocketType,
        name: str,
    ):
        """
        Fissure ZMQ Node

        :param sock_type: pairing type to use when creating the ZMQ socket
        :type sock_type: int
        :param name: name of the component to which the node belongs
        :type name: str
        """
        self.parent_component = name.split("::")[0] if "::" in name else name
        self.name = name.split("::")[1] if "::" in name else name

        # ZMQ Setup
        self.sock_type: zmq.SocketType = sock_type
        self.sockid = None
        self.ctx: zmq.Context = fissure.utils.get_zmq_context()
        self.heartbeat_channel = zmq.asyncio.Socket(self.ctx, socket_type=self.sock_type)
        self.message_channel = zmq.asyncio.Socket(self.ctx, socket_type=self.sock_type)

        # Initialize Logging
        self.logger = fissure.utils.get_logger(source=self.parent_component)

        # Setup Authentication
        self.initialize_auth()

    def __del__(self):
        """
        Cleanup ZMQ Context for GC
        """
        try:
            self.shutdown()  # in case not explicitly called
        except Exception:  # pragma: no cover
            pass

    @abstractmethod
    def initialize_auth(self):
        pass  # pragma: no cover

    @abstractmethod
    def shutdown(self):
        pass  # pragma: no cover

    async def send_heartbeat(self, msg: Dict, target_ids: Optional[List[str]] = None, **kwargs):
        """
        Send ZMQ Heartbeat message

        :param msg: heartbeat message
        :type msg_type: Dict
        :param target_ids: socket IDs of intended recipients, defaults to None (for sending from ROUTER sockets)
        :type target_ids: Optional[List[str]]
        """
        if self.sock_type == zmq.ROUTER:
            for id in target_ids:
                if id is not None:
                    encoded_id = id.encode()
                    encoded_msg = json.dumps(msg).encode()
                    await self.heartbeat_channel.send_multipart([encoded_id, encoded_msg])
        else:
            await self.heartbeat_channel.send_json(msg)

    async def send_msg(self, msg_type: str, msg: Dict, target_ids: Optional[List[str]] = None, **kwargs):
        """
        Send ZMQ message

        :param msg_type: message type to use for generating the message
        :type msg_type: str
        :param msg: message to send
        :type msg: Dict
        :param target_ids: socket IDs of intended recipients, defaults to None
        :type target_ids: Optional[List[str]]
        """
        msg[MessageFields.TYPE] = msg_type

        if self.sock_type == zmq.ROUTER:
            for id in target_ids:
                if id is not None:
                    encoded_id = id.encode()
                    encoded_msg = json.dumps(msg).encode()
                    await self.message_channel.send_multipart([encoded_id, encoded_msg])
                    self.logger.debug(f"[{self.name}] sent message: {msg}")
        else:
            await self.message_channel.send_json(msg)
            self.logger.debug(f"[{self.name}] sent message: {msg}")

    async def recv_heartbeat(self) -> Optional[Dict]:
        """
        Receive ZMQ Heartbeat

        :return: received heartbeat message or None if no message was received
        :rtype: Dict or None
        """
        msgrcvd = None
        if await self.heartbeat_channel.poll(POLL_TIMEOUT):
            if self.sock_type == zmq.ROUTER:
                rcvd = await self.heartbeat_channel.recv_multipart()
                sender_id, msgrcvd = rcvd[0], rcvd[1].decode()
                msgrcvd = json.loads(msgrcvd)
                if msgrcvd is not None and sender_id is not None:
                    msgrcvd[MessageFields.SENDER_ID] = sender_id.decode()
            else:
                msgrcvd = await self.heartbeat_channel.recv_json()
        return msgrcvd

    async def recv_heartbeats(self) -> List[Optional[Dict]]:
        """
        Receive multiple heartbeats (for ROUTER sockets that serve multiple clients)

        :return: received heartbeats
        :rtype: List[Optional[Dict]]
        """
        heartbeats = []
        rcvd = await self.recv_heartbeat()
        while rcvd is not None:
            heartbeats.append(rcvd)
            rcvd = await self.recv_heartbeat()
        return heartbeats

    async def recv_msg(self) -> Optional[Dict]:
        """
        Receive ZMQ message (non-blocking)

        :return: received message or None if no message was received
        :rtype: Dict or None
        """
        sender_id = None
        msgrcvd = None
        if await self.message_channel.poll(POLL_TIMEOUT):
            if self.sock_type == zmq.ROUTER:
                rcvd = await self.message_channel.recv_multipart()
                sender_id, msgrcvd = rcvd[0], json.loads(rcvd[1].decode())
                if msgrcvd is not None and sender_id is not None:
                    msgrcvd[MessageFields.SENDER_ID] = sender_id.decode()
            else:
                msgrcvd = await self.message_channel.recv_json()
            if msgrcvd is not None:
                if msgrcvd.get(MessageFields.TYPE) == MessageTypes.COMMANDS:
                    cb = msgrcvd.get(MessageFields.MESSAGE_NAME)
                    msgrcvd["callback"] = cb
                self.logger.debug(f"[{self.name}] received message: {msgrcvd}")
        return msgrcvd

    async def run_callback(self, context: object, parsed_command: Dict) -> Any:
        """
        Process and execute the callback with the provided parameters

        :param context: context to find the callback method
        :type context: object | Dict
        :param parsed_command: command containing the callback function to execute and (optional) parameters
        :type parsed_command: Dict
        :raises Exception: if the callback is not implemented in the provided context
        :return: result of the executed callback
        :rtype: any
        """
        cb_name = parsed_command["callback"]
        try:
            cb = context.callbacks.get(cb_name)
        except AttributeError:  # pragma: no cover
            cb = context.get(cb_name)
        if cb is None:  # pragma: no cover
            raise Exception(f"method {cb_name} not implemented in context {context}")

        params = parsed_command.get("Parameters")
        self.logger.debug(f"executing callback: {cb_name} with parameters: {params}")

        # Process parameters and execute callback functon
        if params is None:
            # No Parameters
            return await cb(context)
        elif len(params) == 0:
            # Empty Parameters
            return await cb(context, *params)
        else:
            if type(params) is dict:  # Dictionary Params
                return await cb(context, **params)
            elif type(params) is list:  # List Params
                return await cb(context, *params)
            elif type(params) is str:  # Space Separated String Params
                return await cb(context, *(params.split()))
            else:  # pragma: no cover
                self.warning.logger(
                    f"[{self.name}] received callback ({cb_name}) with unrecognized parameters: {params}"
                )


class Server(FissureZMQNode):
    """Fissure ZMQ Server"""

    address: Address = None
    authenticator: zmq.auth.asyncio.AsyncioAuthenticator = None
    allowed_keys: str = os.path.join(fissure.utils.CERT_DIR, CLIENTS)

    def __init__(
        self,
        address: Address,
        sock_type: zmq.SocketType,
        name: str,
    ):
        """
        Fissure ZMQ Server

        :param address: Address Data for the Server
        :type address: fissure.comms.Address
        :param sock_type: pairing type to use when creating the ZMQ socket
        :type sock_type: int
        :param name: server name
        :type name: str
        """
        self.address = address
        super().__init__(sock_type=sock_type, name=name)
        self.logger.debug(f"[{self.name}] initialized")

    def initialize_auth(self):
        """
        Create ZMQ Authenicator, configure to allow CURVE connections from ANY domain (subject to publickey auth)
        """
        self.authenticator = fissure.utils.get_authenticator(self.allowed_keys)

        private_key = os.path.join(self.certs, SERVER, "server.key_secret")

        self.heartbeat_channel.curve_publickey, self.heartbeat_channel.curve_secretkey = zmq.auth.load_certificate(
            private_key
        )
        self.message_channel.curve_publickey, self.message_channel.curve_secretkey = zmq.auth.load_certificate(
            private_key
        )
        self.heartbeat_channel.curve_server = True
        self.message_channel.curve_server = True

    def start(self):
        """
        Connect the ZMQ Socket to the server port
        """
        self.heartbeat_channel.bind(self.address.heartbeat_channel)
        self.message_channel.bind(self.address.message_channel)
        self.logger.debug(f"[{self.name}] started at {self.address}")

    def shutdown(self):
        """
        Close ZMQ sockets
        """
        if not (self.heartbeat_channel.closed or self.message_channel.closed):
            if self.heartbeat_channel.closed is False:
                self.heartbeat_channel.close()
            if self.message_channel.closed is False:
                self.message_channel.close()
            self.logger.debug(f"[{self.name}] shutdown ({self.address})")

        # Cleanup IPC sockets
        if self.address.protocol == "ipc":
            hb_socket_path = self.address.heartbeat_channel.lstrip("ipc://")
            msg_socket_path = self.address.message_channel.lstrip("ipc://")

            if os.path.exists(hb_socket_path):
                self.logger.debug(f"[{self.name}] removing ipc socket: {hb_socket_path}")
                os.remove(hb_socket_path)

            if os.path.exists(msg_socket_path):
                self.logger.debug(f"[{self.name}] removing ipc socket: {msg_socket_path}")
                os.remove(msg_socket_path)


class Listener(FissureZMQNode):
    """Fissure ZMQ Listener"""

    connections: Set[str]

    def __init__(
        self,
        sock_type: zmq.SocketType,
        name: str,
    ):
        """
        Fissure ZMQ Listener

        :param sock_type: pairing type to use when creating the ZMQ socket
        :type sock_type: int
        :param name: listener name
        :type name: str
        """
        self.connections = set()
        super().__init__(sock_type=sock_type, name=name)
        self.logger.debug(f"[{self.name}] initialized")

    def initialize_auth(self):
        """
        Configure ZMQ CURVE-Based Authentication

        :param certs: path containing server keys as well as client keys to allow connections from
        :type certs: str
        """
        client_private_key = os.path.join(self.certs, CLIENTS, "client_0.key_secret")
        server_public_key = os.path.join(self.certs, SERVER, "server.key")

        self.heartbeat_channel.curve_publickey, self.heartbeat_channel.curve_secretkey = zmq.auth.load_certificate(
            client_private_key
        )
        self.heartbeat_channel.curve_serverkey, _ = zmq.auth.load_certificate(server_public_key)
        self.message_channel.curve_publickey, self.message_channel.curve_secretkey = zmq.auth.load_certificate(
            client_private_key
        )
        self.message_channel.curve_serverkey, _ = zmq.auth.load_certificate(server_public_key)

        self.logger.debug(f"[{self.name}] loaded client private key = {client_private_key}")
        self.logger.debug(f"[{self.name}] loaded server public key = {server_public_key}")

    def set_identity(self, identity: str):
        """
        Set the socket ID - for Listeners that will connect to a ROUTER Server

        :param identity: identity string
        :type identity: str
        """
        self.sockid = identity
        self.heartbeat_channel.setsockopt_string(zmq.IDENTITY, identity)
        self.message_channel.setsockopt_string(zmq.IDENTITY, identity)

    async def connect(self, server_addr: Address, timeout: int = 5) -> bool:
        """
        Initiate connection to the ZMQ Server

        :param server_addr: Address Data of the server we're connecting to
        :type server_addr: fissure.comms.Address
        :param timeout: timeout (in seconds) for connection attempt. Default = 5 Seconds
        :type timeout: int
        :returns: result of the connection attempt
        :rtype: bool
        """
        if self.heartbeat_channel.getsockopt(zmq.TYPE) == zmq.SUB:
            self.heartbeat_channel.setsockopt_string(zmq.SUBSCRIBE, "")  # pragma: no cover

        if self.message_channel.getsockopt(zmq.TYPE) == zmq.SUB:
            self.message_channel.setsockopt_string(zmq.SUBSCRIBE, "")  # pragma: no cover

        self.heartbeat_channel.connect(server_addr.heartbeat_channel)
        self.message_channel.connect(server_addr.message_channel)

        # Send/recv connect message to confirm success
        connect_msg = {
            MessageFields.IDENTIFIER: self.parent_component,
            MessageFields.MESSAGE_NAME: "Connected",
        }
        await self.send_msg(MessageTypes.STATUS, connect_msg)
        self.connections.add(server_addr)
        self.logger.debug(f"[{self.name}] connected to {server_addr}")
        return True
        # now = time.time()
        # start_time = now
        # while timeout >= (now - start_time):
        #     response = await self.recv_msg()
        #     if (
        #         (response is not None)
        #         and (response.get(MessageFields.TYPE) == fissure.comms.MessageTypes.STATUS)
        #         and (response.get(MessageFields.MESSAGE_NAME) == "OK")
        #     ):
        #         self.connections.add(server_addr)
        #         self.logger.debug(f"[{self.name}] connected to {server_addr}")
        #         return True
        #     now = time.time()


    def disconnect(self, server_addr: Address):
        """
        Disconnect and close subscriber socket

        :param server: Address Data of the server connection
        :type server: fissure.comms.Address
        """
        if server_addr in self.connections:
            self.heartbeat_channel.disconnect(server_addr.heartbeat_channel)
            self.message_channel.disconnect(server_addr.message_channel)
            self.connections.remove(server_addr)
            self.logger.debug(f"[{self.name}] disconnected from {server_addr}")


    def shutdown(self):
        """
        Disconnect all open connections and close ZMQ Socket
        """
        for server in list(self.connections):  # Iterate over a copy of the set
            self.disconnect(server)  # pragma: no cover
        if not (self.heartbeat_channel.closed or self.message_channel.closed):
            if not self.heartbeat_channel.closed:
                self.heartbeat_channel.close()
            if not self.message_channel.closed:
                self.message_channel.close()
            self.logger.debug(f"[{self.name}] shutdown")
