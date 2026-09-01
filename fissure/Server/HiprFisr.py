from inspect import isfunction
from types import ModuleType
from typing import Dict, List, Union

import asyncio
import fissure.callbacks
import fissure.comms
import fissure.utils
import sys
import time
import uuid
import zmq
import subprocess
import os
import atexit
import ssl
from datetime import datetime, timezone, timedelta
from threading import Lock
from fissure.utils.tak_server import load_config as load_tak_config
from fissure.utils.tak_server import TakReceiver
import pytak
from fissure.utils.artifacts import ArtifactTracker
from fissure.Server.HiprFisrArtifactTransferController import HiprFisrArtifactTransferController
from fissure.ListeningPosts import ListeningPostManager


HEARTBEAT_LOOP_DELAY = 0.1  # Seconds
EVENT_LOOP_DELAY = 0.1


def run():
    asyncio.run(main())


async def main():
    """
    Server __main__.py does not call this function. Do not edit! Edit __init__() or begin().
    """
    # Initialize HIPFISR
    print("[FISSURE][HiprFisr] start")
    hiprfisr = HiprFisr()

    # Start Event Loop
    await hiprfisr.begin()

    # End and Clean Up
    print("[FISSURE][HiprFisr] end")
    fissure.utils.zmq_cleanup()


class HiprFisr:
    """Fissure HIPRFISR Class"""

    settings: Dict
    identifier: str = fissure.comms.Identifiers.HIPRFISR
    identifierLT: str = fissure.comms.Identifiers.HIPRFISR_LT
    # logger: logging.Logger = fissure.utils.get_logger(fissure.comms.Identifiers.HIPRFISR)
    ip_address: str
    session_active: bool
    dashboard_socket: fissure.comms.Server  # PAIR
    dashboard_connected: bool
    backend_router: fissure.comms.Server  # ROUTER-DEALER
    backend_id: str
    tsi_id: bytes
    tsi_connected: bool
    pd_id: bytes
    pd_connected: bool
    # sensor_nodes: List[SensorNode]
    heartbeats: Dict[str, Union[float, Dict[int, float]]]  # {name: time, name: time, ... sensor_nodes: {node_id: time}}
    callbacks: Dict = {}
    shutdown: bool
    tak_mode: str
    tak_connected: bool


    def __init__(self, address: fissure.comms.Address, dashboard_expected=True):
        self.logger = fissure.utils.get_logger(fissure.comms.Identifiers.HIPRFISR)
        self.logger.info("=== INITIALIZING ===")

        # Get IP Address
        self.ip_address = fissure.utils.get_ip_address()

        # TAK SOI Dictionary, # TODO: Replace with database lookup
        self.sois = {}  # key -> SOI record dict
        self.targets = {}
        self.targets = fissure.utils.load_yaml("targets.yaml")

        # Store Collected Wideband and Narrowband Signals in Lists
        self.wideband_list = []
        self.soi_list = []

        # SOI Blacklist
        self.soi_blacklist = []

        # Don't Process SOIs at Start
        self.process_sois = False

        # Create SOI sorting variables
        # SOI_priority = (0, 1, 2)
        # SOI_filter = ("Highest", "Highest", "Containing")
        self.soi_parameters = (None, None, "FSK")

        # Create the Variable
        self.auto_start_pd = False
        self.soi_manually_triggered = False

        # Initialize Connection/Heartbeat Variables
        self.heartbeats = {
            fissure.comms.Identifiers.HIPRFISR: None,
            fissure.comms.Identifiers.DASHBOARD: None,
            fissure.comms.Identifiers.PD: None,
            fissure.comms.Identifiers.TSI: None,
            fissure.comms.Identifiers.SENSOR_NODE: None,
        }
        self.session_active = False
        self.dashboard_connected = False
        self.pd_id = None
        self.pd_connected = False
        self.tsi_id = None
        self.tsi_connected = False
        self.connect_loop = True
        self.child_tasks = []
        self.sockets = []
        self.hiprfisr_serial_connected = False

        self.nodes = {}
        self.assigned_id_counter = 1  # TODO: make this persist, saving itself when updated

        # Load settings from Fissure Config YAML
        self.settings = fissure.utils.get_fissure_config()
        self.dashboard_expected = bool(dashboard_expected)

        # Update Logging Levels
        fissure.utils.update_logging_levels(
            self.logger, 
            self.settings["console_logging_level"], 
            self.settings["file_logging_level"]
        )

        # Detect Operating System
        self.os_info = fissure.utils.get_os_info()

        # Initialize Optional CoT Logging
        self.init_cot_logging()

        # Start the Database Docker Container (if not running)
        self.start_database_docker_container()
        tak_info = self.settings.get("tak")
        run_tak = tak_info.get("tak_on_startup")
        if str(run_tak).lower() == "true":
            self.start_tak_docker_container()

        # Create the HIPRFISR ZMQ Nodes
        listen_addr = self.initialize_comms(address)
        # self.initialize_sensor_nodes()
        self.message_counter = 0
        self.shutdown = False

        # Track Local Sensor Node UUID
        self.local_node_uuid = self.load_or_create_uuid()

        # Initialize TAK Variables
        self.tak_connected = False
        self.tak_task = None

        # Register Callbacks
        self.register_callbacks(fissure.callbacks.GenericCallbacks)
        self.register_callbacks(fissure.callbacks.HiprFisrCallbacks)
        self.register_callbacks(fissure.callbacks.HiprFisrCallbacksLT)

        # Initialize artifact tracker
        self.artifact_tracker = ArtifactTracker(logger=self.logger)

        # HIPRFISR owns persisted Listening Post definitions and runtime services.
        self.listening_post_manager = ListeningPostManager(self)

        # Dedicated binary artifact-transfer router. This is intentionally
        # separate from the normal command and heartbeat channels.
        self.artifact_transfer_router = fissure.comms.ArtifactTransferRouter(
            bind_endpoint=fissure.comms.build_artifact_endpoint("0.0.0.0"),
            logger=self.logger,
        )
        self.artifact_transfer_router.start()

        self.artifact_transfer_controller = HiprFisrArtifactTransferController(self)

        self.logger.info("=== READY ===")
        self.logger.info(f"Server listening @ {listen_addr}")


    def initialize_comms(self, frontend_address: fissure.comms.Address):
        comms_info = self.settings.get("hiprfisr")
        backend_address = fissure.comms.Address(address_config=comms_info.get("backend"))

        # 1) Frontend (unchanged)
        self.dashboard_socket = fissure.comms.Server(
            address=frontend_address,
            sock_type=zmq.PAIR,
            name=f"{self.identifier}::frontend",
        )
        self.dashboard_socket.start()
        self.sockets.append(self.dashboard_socket)

        # 2) Backend (unchanged)
        self.backend_id = f"{self.identifier}-{uuid.uuid4()}"
        self.backend_router = fissure.comms.Server(
            address=backend_address,
            sock_type=zmq.ROUTER,
            name=f"{self.identifier}::backend",
        )
        self.backend_router.start()
        self.sockets.append(self.backend_router)

        # 3) Single shared Sensor Node ROUTER on fixed ports
        self.sensor_node_router = fissure.comms.Server(
            address=fissure.comms.Address(
                protocol="tcp",
                address="0.0.0.0",
                hb_channel=6100,   # <-- Correct key  #TODO: get from YAML
                msg_channel=6101,     # <-- Correct key
            ),
            sock_type=zmq.ROUTER,
            name=f"{self.identifier}::sensor_node_router",
        )
        self.sensor_node_router.start()
        self.sockets.append(self.sensor_node_router)

        # Local IPC bind for Sensor Nodes
        try:
            self.sensor_node_router.message_channel.bind("ipc:///tmp/ipc-msg")
            self.sensor_node_router.heartbeat_channel.bind("ipc:///tmp/ipc-hb")
            self.logger.info("Sensor Node IPC endpoints bound successfully")
        except Exception as e:
            self.logger.warning(f"Could not bind IPC endpoints: {e}")
        
        # 4) Auto-connect to Meshtastic serial port
        mesh_cfg = self.settings.get("meshtastic", {}) or {}
        if mesh_cfg.get("auto_connect_meshtastic"):
            serial_port = mesh_cfg.get("meshtastic_serial_port")
            if serial_port:
                try:
                    self.meshtastic_node = fissure.comms.FissureMeshtasticNode(
                        serial_port=serial_port,
                        name=f"{self.identifier}::meshtastic",
                        context=self,   # <- where .callbacks lives
                    )
                    self.hiprfisr_serial_connected = True
                    self.logger.info(
                        f"Meshtastic auto-connect enabled, using serial port {serial_port}"
                    )
                    self.meshtastic_node.assigned_id = self.identifierLT
                except Exception as e:
                    self.logger.warning(
                        f"Failed to initialize Meshtastic on {serial_port}: {e}"
                    )

        return frontend_address


    def register_callbacks(self, ctx: ModuleType):
        """
        Register callbacks from the provided context

        :param ctx: context containing callbacks to register
        :type ctx: ModuleType
        """
        callbacks = [(f, getattr(ctx, f)) for f in dir(ctx) if isfunction(getattr(ctx, f))]
        for cb_name, cb_func in callbacks:
            self.callbacks[cb_name] = cb_func
        self.logger.debug(f"registered {len(callbacks)} callbacks from {ctx.__name__}")


    def load_or_create_uuid(self):
        # If the UUID file exists, reuse it
        UUID_PATH = os.path.expanduser("~/.fissure/local_sensor_node_uuid.uuid")
        if os.path.exists(UUID_PATH):
            with open(UUID_PATH, "r") as f:
                return f.read().strip()

        # Otherwise create a new one
        node_uuid = str(uuid.uuid4())

        # Ensure the folder exists
        os.makedirs(os.path.dirname(UUID_PATH), exist_ok=True)

        # Save it for future runs
        with open(UUID_PATH, "w") as f:
            f.write(node_uuid)

        return node_uuid


    async def shutdown_comms(self):
        """
        Cleanly shut down all ZMQ communications:
        - Close dashboard socket (PAIR)
        - Close backend router (ROUTER)
        - Close all PD/TSI comm sockets (DEALER)
        - Close all sensor-node listener sockets
        """
        # Mark state inactive
        self.dashboard_connected = False
        self.session_active = False
        
        # Close any sockets the component registered as a group
        for s in getattr(self, "sockets", []):
            try:
                s.close_sockets()
            except Exception:
                pass
        
        artifact_router = getattr(self, "artifact_transfer_router", None)
        if artifact_router is not None:
            try:
                artifact_router.close()
            except Exception:
                pass
            self.artifact_transfer_router = None

        # Stop ZAP authenticator (must run before ctx.destroy, does not work in zmq_cleanup, HIPRFISR is the last program that closes)
        try:
            from fissure.utils.common import authenticator_cleanup
            authenticator_cleanup()
        except Exception:
            pass


    async def artifact_transfer_loop(self):
            """Route dedicated binary artifact-transfer frames."""
            while not self.shutdown:
                try:
                    routed = await self.artifact_transfer_router.receive_and_route()
                    if routed is not None:
                        _sender_identity, frame = routed
                        await self.artifact_transfer_controller.handle_frame(frame)
                    self.artifact_transfer_controller.expire_stalled_transfers()
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    self.logger.error(f"Artifact transfer router error: {exc}")
                    await asyncio.sleep(EVENT_LOOP_DELAY)


    async def heartbeat_loop(self):
        while not self.shutdown:
            if not self.connect_loop:
                try:
                    await self.send_heartbeat()
                    await self.recv_heartbeats()
                    await self.check_heartbeats()
                except Exception as e:
                    self.logger.error(f"[HB] {e}")

            await asyncio.sleep(HEARTBEAT_LOOP_DELAY)

        self.logger.info("[HB] Heartbeat loop exiting cleanly")


    async def begin(self):
        """
        HIPRFISR main event loop with simplified & reliable TAK handling.
        TAK logic:
        auto  -> connect at start + reconnect on loss
        manual -> connect only when triggered by user (no reconnect)
        off   -> disabled
        """

        self.logger.info("=== STARTING HIPRFISR ===")

        # Ensure clean state
        self.tak_task = None
        self.clitool = None
        self.tak_mode = self.settings["tak"]["connect_mode"].lower()

        heartbeat_task = asyncio.create_task(self.heartbeat_loop())
        self.child_tasks.append(heartbeat_task)

        artifact_transfer_task = asyncio.create_task(self.artifact_transfer_loop())
        self.child_tasks.append(artifact_transfer_task)

        # Start persisted HIPRFISR-hosted Listening Posts marked for Auto Start.
        await self.listening_post_manager.start_autostart()

        # Load TAK config
        from fissure.utils.common import get_fissure_config
        fissure_config = get_fissure_config()
        tak_config = load_tak_config()

        tak_ip = fissure_config["tak"]["ip_addr"]
        tak_port = fissure_config["tak"]["port"]

        # ---------------------------------------------------------
        # AUTO MODE: non-blocking TAK startup
        # ---------------------------------------------------------
        if self.tak_mode == "auto":
            self.logger.info(f"TAK auto-connect enabled → {tak_ip}:{tak_port}")

            async def try_initial_connect():
                TIMEOUT = 5
                try:
                    await asyncio.wait_for(
                        asyncio.open_connection(tak_ip, tak_port),
                        timeout=TIMEOUT
                    )
                    self.logger.info("TAK server reachable at startup.")
                except Exception:
                    self.logger.warning(
                        f"TAK server not reachable within {TIMEOUT}s. "
                        "Continuing startup; pytak will reconnect automatically."
                    )

                # Launch pytak (handles its own reconnection)
                self.tak_task = asyncio.create_task(
                    self.run_tak_loop(tak_config, auto_reconnect=True)
                )
                self.child_tasks.append(self.tak_task)

            # Fire background task without blocking HIPRFISR startup
            asyncio.create_task(try_initial_connect())

        elif self.tak_mode == "manual":
            self.logger.info("TAK manual mode: waiting for user input")
        else:
            self.logger.info("TAK disabled in config")

        # ---------------------------------------------------------
        # Main HIPRFISR event loop
        # ---------------------------------------------------------
        loop = asyncio.get_event_loop()
        self.silence_asyncio_ssl_errors(loop)
        while not self.shutdown:
            if not self.connect_loop:
                if self.dashboard_connected:
                    await self.read_dashboard_messages()
                if self.pd_connected or self.tsi_connected:
                    await self.read_backend_messages()
                try:
                    await self.read_sensor_node_messages()
                except Exception as e:
                    self.logger.error(f"read_sensor_node_messages crashed: {e}")
                await asyncio.sleep(EVENT_LOOP_DELAY)
            else:
                await self.connect_components()

        self.logger.debug("Shutdown reached in HIPRFISR event loop")

        # ---------------------------------------------------------
        # Cleanup
        # ---------------------------------------------------------
        # Stop Listening Posts before tearing down component communications.
        await self.listening_post_manager.shutdown()

        # Stop TAK Client
        await self.stop_tak_client()

        # Stop Heartbeat Task
        heartbeat_task.cancel()  # Double cancel is needed to brute force close, faster
        await asyncio.sleep(0)
        heartbeat_task.cancel()  # Needs to happen after sleep
        try:
            await heartbeat_task
        except asyncio.CancelledError:
            pass

        # Close Running Tasks
        for task in self.child_tasks:
            if isinstance(task, asyncio.Task):
                task.cancel()
        await asyncio.gather(
            *[t for t in self.child_tasks if isinstance(t, asyncio.Task)],
            return_exceptions=True
        )

        # Extra cleanup for any pytak worker tasks still alive
        for t in asyncio.all_tasks():
            c = str(t.get_coro())
            if "pytak" in c or "RXWorker" in c or "TXWorker" in c or "TakReceiver" in c:
                t.cancel()

        # Shut Down Comms
        await self.shutdown_comms()
        await asyncio.sleep(0)

        self.logger.info("=== HIPRFISR SHUTDOWN COMPLETE ===")

        return


    async def run_tak_loop(self, tak_config, auto_reconnect=True):
        """
        Run pytak. Restart only if auto_reconnect=True.
        Never double-spawns.
        """

        while not self.shutdown:
            try:
                self.clitool = pytak.CLITool(tak_config)
                await self.clitool.setup()

                # Attach receiver once per loop
                self.clitool.add_tasks({
                    TakReceiver(self.clitool.rx_queue, tak_config, self, self.logger)
                })

                # Collect pytak-created asyncio tasks
                for t in getattr(self.clitool, "tasks", []):
                    if isinstance(t, asyncio.Task):
                        self.child_tasks.append(t)

                self.logger.info("Starting pytak client...")
                self.tak_connected = True
                await self.clitool.run()
                self.logger.warning("TAK connection ended")
                self.tak_connected = False

                if self.shutdown:
                    break

                if not auto_reconnect:
                    self.logger.info("TAK manual mode: not reconnecting")
                    break

                self.logger.warning("TAK connection lost. Reconnecting in 5 seconds...")
                await asyncio.sleep(5)

            except Exception as e:
                if self.shutdown:
                    break
                self.logger.error(f"pytak crashed: {e}")

            # auto reconnect delay
            if auto_reconnect and not self.shutdown:
                await asyncio.sleep(5)

        self.logger.info("Exiting Tak loop")


    async def stop_tak_client(self):
        """Cleanly stop pytak workers, receiver, and writer."""
        # No client running
        if not self.clitool:
            return

        # ----------------------------------------------
        # 1. Signal TX queue to stop
        # ----------------------------------------------
        try:
            self.clitool.tx_queue.put_nowait(None)
        except Exception:
            pass

        # ----------------------------------------------
        # 2. Signal RX queue to stop
        # ----------------------------------------------
        try:
            self.clitool.rx_queue.put_nowait(None)
        except Exception:
            pass

        # ----------------------------------------------
        # 3. Cancel pytak worker tasks explicitly
        # ----------------------------------------------
        worker_tasks = []

        for task in asyncio.all_tasks():
            coro = str(task.get_coro())
            if "RXWorker" in coro or "TXWorker" in coro or "Worker.run" in coro:
                task.cancel()
                worker_tasks.append(task)

        # Give them a moment to exit
        await asyncio.gather(*worker_tasks, return_exceptions=True)

        # ----------------------------------------------
        # 4. Cancel TakReceiver task
        # ----------------------------------------------
        if self.tak_task:
            self.tak_task.cancel()
            try:
                await self.tak_task
            except:
                pass

        # ----------------------------------------------
        # 5. Close TLS writer if it exists
        # ----------------------------------------------
        writer = getattr(self.clitool, "writer", None)
        if writer:
            try:
                writer.close()
                await writer.wait_closed()
            except:
                pass

        # Cleanup
        self.clitool = None
        self.tak_task = None


    async def start_tak_manual(self):
        if not self.tak_task:
            tak_config = load_tak_config()
            self.tak_task = asyncio.create_task(self.run_tak_loop(tak_config, auto_reconnect=False))
            self.logger.info("Manual TAK connection started")


    def silence_asyncio_ssl_errors(self, loop):
        """Ignore spurious SSL errors on shutdown (Python 3.8 TLS bug)."""
        orig_handler = loop.get_exception_handler()

        def handler(loop, context):
            msg = context.get("message", "")
            exc = context.get("exception")
            if (
                "Fatal error on SSL transport" in msg or
                (exc and isinstance(exc, OSError) and exc.errno == 9)
            ):
                # ignore bad fd & ssl closure errors
                return
            if orig_handler is not None:
                orig_handler(loop, context)
            else:
                loop.default_exception_handler(context)

        loop.set_exception_handler(handler)


    async def connect_components(self):
        self.logger.debug("Entering connect loop")

        while self.connect_loop is True:

            # Heartbeats (Dashboard + PD/TSI)
            await self.recv_heartbeats()
            await self.send_heartbeat()
            await self.check_heartbeats()

            # Dashboard first — user may press "Exit Connect Loop"
            await self.read_dashboard_messages()

            # Backend (PD/TSI)
            await self.read_backend_messages()

            # Dashboard expected only for normal Dashboard-launched operation
            if self.settings.get("auto_connect_hiprfisr", True) and self.dashboard_expected:
                if not self.dashboard_connected:
                    self.logger.warning("Dashboard lost during connect loop")
                    break

                # All components connected?
                if self.dashboard_connected and self.pd_connected and self.tsi_connected:
                    msg = {
                        fissure.comms.MessageFields.IDENTIFIER: self.identifier,
                        fissure.comms.MessageFields.MESSAGE_NAME: "Connected",
                        fissure.comms.MessageFields.PARAMETERS: [
                            fissure.comms.Identifiers.PD,
                            fissure.comms.Identifiers.TSI,
                        ],
                    }
                    await self.dashboard_socket.send_msg(
                        fissure.comms.MessageTypes.STATUS, msg
                    )
                       
                    # Send Meshtastic auto-connect serial connected message
                    if self.hiprfisr_serial_connected:
                        PARAMETERS = None
                        msg = {
                            fissure.comms.MessageFields.IDENTIFIER: self.identifier,
                            fissure.comms.MessageFields.MESSAGE_NAME: "hiprfisrConnectedSerial",
                            fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
                        }
                        await self.dashboard_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)

                    self.connect_loop = False

            # Headless/remote Dashboard
            else:
                # All components connected?
                if self.pd_connected and self.tsi_connected:
                    self.connect_loop = False

        self.logger.debug("Exiting connect loop")


    async def read_dashboard_messages(self):
        received_message = ""

        while received_message is not None and not self.shutdown:
            
            received_message = await self.dashboard_socket.recv_msg()
            if received_message is None:
                break

            self.dashboard_connected = True
            msg_type = received_message.get(fissure.comms.MessageFields.TYPE)

            # Heartbeats arriving on the message channel are ignored
            if msg_type == fissure.comms.MessageTypes.HEARTBEATS:
                self.logger.warning("received heartbeat on message channel [from Dashboard]")
                continue

            # COMMANDS
            if msg_type == fissure.comms.MessageTypes.COMMANDS:
                await self.dashboard_socket.run_callback(self, received_message)
                continue

            # STATUS
            if msg_type == fissure.comms.MessageTypes.STATUS:
                msg_name = received_message.get(fissure.comms.MessageFields.MESSAGE_NAME)

                if msg_name == "Connected":
                    response = {
                        fissure.comms.MessageFields.IDENTIFIER: self.identifier,
                        fissure.comms.MessageFields.MESSAGE_NAME: "OK",
                    }
                    await self.dashboard_socket.send_msg(
                        fissure.comms.MessageTypes.STATUS,
                        response
                    )
                    self.session_active = True
                    continue

                elif msg_name == "Exit Connect Loop":
                    self.connect_loop = False
                    continue

                # Unknown STATUS message: ignore
                continue


    async def read_backend_messages(self):
        received_message = ""

        while received_message is not None:
            received_message = await self.backend_router.recv_msg()

            if received_message is None:
                break

            sender_id = received_message.get(fissure.comms.MessageFields.SENDER_ID)
            component = received_message.get(fissure.comms.MessageFields.IDENTIFIER)
            msg_type = received_message.get(fissure.comms.MessageFields.TYPE)

            # ------------------------------------------------------------------
            # Register backend DEALER identities (PD, TSI)
            # ------------------------------------------------------------------
            if component == fissure.comms.Identifiers.PD:
                self.pd_id = sender_id

            elif component == fissure.comms.Identifiers.TSI:
                self.tsi_id = sender_id

            # ------------------------------------------------------------------
            # Heartbeats should NOT arrive on the message channel
            # ------------------------------------------------------------------
            if msg_type == fissure.comms.MessageTypes.HEARTBEATS:
                self.logger.warning(f"received backend heartbeat on message channel from {component}")
                continue

            # ------------------------------------------------------------------
            # COMMANDS
            # ------------------------------------------------------------------
            if msg_type == fissure.comms.MessageTypes.COMMANDS:
                await self.backend_router.run_callback(self, received_message)
                continue

            # ------------------------------------------------------------------
            # STATUS messages
            # ------------------------------------------------------------------
            if msg_type == fissure.comms.MessageTypes.STATUS:
                msg_name = received_message.get(fissure.comms.MessageFields.MESSAGE_NAME)

                if msg_name == "Connected":
                    response = {
                        fissure.comms.MessageFields.IDENTIFIER: self.identifier,
                        fissure.comms.MessageFields.MESSAGE_NAME: "OK",
                    }
                    await self.backend_router.send_msg(
                        fissure.comms.MessageTypes.STATUS,
                        response,
                        target_ids=[sender_id]
                    )
                continue


    async def read_sensor_node_messages(self):
        """
        Reads inbound messages from Sensor Nodes (ROUTER socket).

        Responsibilities:
        - Identify the sender identity (ROUTER identity)
        - Parse JSON message
        - Register/update node entries for sensorNodeHello
        - Only update runtime fields for non-HELLO messages
        - Dispatch callbacks for COMMAND messages
        - Log STATUS messages
        """

        while not self.shutdown:

            # # Don't block if no data is ready
            # if not self.sensor_node_router.poll(0):
            #     await asyncio.sleep(0)
            #     continue

            received = await self.sensor_node_router.recv_msg()
            if received is None:
                return  # socket was shut down

            sender_id = received.get(fissure.comms.MessageFields.SENDER_ID)
            uuid = received.get(fissure.comms.MessageFields.IDENTIFIER)
            msg_type  = received.get(fissure.comms.MessageFields.TYPE)
            msg_name  = received.get(fissure.comms.MessageFields.MESSAGE_NAME)
            params    = received.get(fissure.comms.MessageFields.PARAMETERS, {})


            if not uuid:
                self.logger.warning(
                    f"[ROUTER] Message '{msg_name}' from {sender_id} missing UUID; ignoring."
                )
                continue

            node = self.nodes.get(uuid)

            # ===============================================================
            # Update identity, last_seen from UUID
            # ===============================================================
            if node is None:
                self.logger.warning(
                    f"Message '{msg_name}' from unknown uuid={uuid}"
                )
                continue

            node["identity"]  = sender_id  # sensor-node-sensor node 9221cf85-87215684-ac17-43e4-9aad-ad33c9f14815
            node["connected"] = True
            node["last_seen"] = time.time()

            # ===============================================================
            # DISPATCH MESSAGE TYPES
            # ===============================================================

            # COMMANDS ------------------------------------------------------
            if msg_type == fissure.comms.MessageTypes.COMMANDS:
                try:
                    params = received.get("Parameters", {})

                    # AUTO-INJECT UUID so all callbacks can access it
                    if isinstance(params, dict):
                        params.setdefault("uuid", uuid)

                        await self.sensor_node_router.run_callback(self, received)

                except Exception as e:
                    self.logger.error(
                        f"Callback failed for node uuid={uuid}, msg={msg_name}: {e}"
                    )
                continue

            # STATUS --------------------------------------------------------
            if msg_type == fissure.comms.MessageTypes.STATUS:
                self.logger.info(f"STATUS from node {uuid}: {msg_name}")  # TODO: remove status message type?
                continue

            # UNKNOWN -------------------------------------------------------
            self.logger.warning(
                f"Unknown msg_type={msg_type} from node uuid={uuid}"
            )
            continue


    async def send_heartbeat(self):
        last_heartbeat = self.heartbeats[self.identifier]
        now = time.time()

        if (last_heartbeat is None) or (
            now - last_heartbeat >= float(self.settings.get("heartbeat_interval"))
        ):
            node_times = []
            node_intervals = []

            hb_record = self.heartbeats[fissure.comms.Identifiers.SENSOR_NODE]

            if hb_record is None:
                node_times.append(None)
                node_intervals.append(None)
            else:
                timestamp = hb_record.get("time")
                interval = hb_record.get("interval")
                node_times.append(timestamp)
                node_intervals.append(interval)

            heartbeat = {
                fissure.comms.MessageFields.IDENTIFIER: self.identifier,
                fissure.comms.MessageFields.MESSAGE_NAME: fissure.comms.MessageFields.HEARTBEAT,
                fissure.comms.MessageFields.TIME: now,
                fissure.comms.MessageFields.PARAMETERS: {
                    fissure.comms.Identifiers.PD: self.heartbeats.get(fissure.comms.Identifiers.PD),
                    fissure.comms.Identifiers.TSI: self.heartbeats.get(fissure.comms.Identifiers.TSI),
                    fissure.comms.Identifiers.SENSOR_NODE: {
                        fissure.comms.MessageFields.TIME: node_times,
                        fissure.comms.MessageFields.INTERVAL: node_intervals,
                    },
                },
            }

            # -------------------------------------------------------------
            # DASHBOARD HEARTBEAT
            # -------------------------------------------------------------
            if self.dashboard_connected:
                await self.dashboard_socket.send_heartbeat(heartbeat)
            else:
                if self.settings.get("auto_connect_hiprfisr", True) and self.dashboard_expected:
                    print(self.dashboard_expected)
                    self.logger.error("[HIPRFISR][HB] Dashboard not connected.")

            # -------------------------------------------------------------
            # PD / TSI HEARTBEAT
            # -------------------------------------------------------------
            if self.pd_connected or self.tsi_connected:
                heartbeat_with_ip = dict(heartbeat)
                heartbeat_with_ip[fissure.comms.MessageFields.IP] = "localhost"

                await self.backend_router.send_heartbeat(
                    heartbeat_with_ip,
                    target_ids=[self.pd_id, self.tsi_id],
                )
            else:
                self.logger.error("[HIPRFISR][HB] PD/TSI not connected.")

            # -------------------------------------------------------------
            # SENSOR NODE HEARTBEAT (Don't heartbeat to nodes)
            # -------------------------------------------------------------
            # target_ids = []

            # for uuid in self.dashboard_node_map:

            #     # Skip unassigned slots
            #     if uuid is None:
            #         continue

            #     node_entry = self.nodes.get(uuid)
            #     if not node_entry:
            #         continue

            #     # Skip nodes not marked connected
            #     if not node_entry.get("connected", False):
            #         continue

            #     identity = node_entry.get("identity")
            #     if identity:
            #         target_ids.append(identity)

            # if target_ids:
            #     try:
            #         await self.sensor_node_router.send_heartbeat(
            #             heartbeat,
            #             target_ids=target_ids
            #         )
            #     except Exception as e:
            #         self.logger.error(f"[HB] Failed sending SN heartbeat: {e}")
            # else:
            #     pass
            #     # self.logger.debug("[HB] No connected dashboard nodes — skipping SN heartbeat.")

            # -------------------------------------------------------------
            # SELF/HIPRFISR
            # -------------------------------------------------------------
            # Update HIPRFISR's own heartbeat timestamp
            self.heartbeats[self.identifier] = now


    async def recv_heartbeats(self):
        """
        Receive heartbeats from:
        • Dashboard (PAIR)
        • PD / TSI (backend_router ROUTER)
        • Sensor Nodes (sensor_node_router ROUTER)
        """
        # -------------------------
        # Dashboard heartbeat (PAIR)
        # -------------------------
        dashboard_hb = await self.dashboard_socket.recv_heartbeat()
        if dashboard_hb:
            t = float(dashboard_hb[fissure.comms.MessageFields.TIME])
            self.heartbeats[fissure.comms.Identifiers.DASHBOARD] = t
            # self.logger.debug(f"received Dashboard heartbeat ({fissure.utils.get_timestamp(t)})")

        # -----------------------------
        # Backend PD / TSI (ROUTER)
        # -----------------------------
        backend_hbs = await self.backend_router.recv_heartbeats()
        if backend_hbs:
            for hb in backend_hbs:
                sender_id = hb.get(fissure.comms.MessageFields.SENDER_ID)
                ident     = hb.get(fissure.comms.MessageFields.IDENTIFIER)
                t         = float(hb[fissure.comms.MessageFields.TIME])

                if ident == fissure.comms.Identifiers.PD and self.pd_id is None:
                    self.pd_id = sender_id

                if ident == fissure.comms.Identifiers.TSI and self.tsi_id is None:
                    self.tsi_id = sender_id

                self.heartbeats[ident] = t
                # self.logger.debug(
                #     f"received backend heartbeat from {ident} "
                #     f"({fissure.utils.get_timestamp(t)})"
                # )

        # ---------------------------------------------------
        # Sensor Node heartbeat handling (IP-only)
        # ---------------------------------------------------
        await self.recv_sensor_node_heartbeats()


    async def recv_sensor_node_heartbeats(self):
        """
        Reads heartbeats from Sensor Nodes via the heartbeat channel.

        Heartbeat is the authoritative liveness path. For IP nodes, it may
        also carry cached node status and cached GPS state.
        """
        hbs = await self.sensor_node_router.recv_heartbeats()
        if not hbs:
            return

        for hb in hbs:
            self.logger.info(
                f"received {hb.get('SenderID')} heartbeat "
                f"({fissure.utils.get_timestamp(hb.get('Time'))})"
            )

        for hb in hbs:
            sn_time = float(hb.get(fissure.comms.MessageFields.TIME))
            sn_int = hb.get(fissure.comms.MessageFields.INTERVAL, 5)
            sn_uuid = hb.get(fissure.comms.MessageFields.IDENTIFIER)

            params = hb.get(fissure.comms.MessageFields.PARAMETERS, {}) or {}

            # Node IP address reported by the Sensor Node.
            # Prefer explicit parameter, then fallback to the top-level heartbeat IP field.
            sn_ip = (
                params.get("node_ip_address")
                or hb.get(fissure.comms.MessageFields.IP)
                or "unknown"
            )

            # HIPRFISR IP address the Sensor Node is configured to connect to.
            sn_hiprfisr_ip = params.get("hiprfisr_ip_address", "")

            sn_nickname = params.get("nickname", "-")
            sn_nettype = params.get("network_type", "IP")
            sn_id_zmq = hb.get(fissure.comms.MessageFields.SENDER_ID)
            sn_assigned_id = -1  # For Meshtastic handshake

            # Optional unified node state from heartbeat.
            # These are cached values from the Sensor Node; heartbeat receive
            # should never block on GPS lookup.
            sn_state = {
                "status": params.get("status"),
                "autorun_state": params.get("autorun_state"),
                "version": params.get("version"),
                "gps_source": params.get("gps_source"),
                "gps_valid": fissure.utils.common.safe_bool(params.get("gps_valid"), default=False),
                "gps_time": params.get("gps_time"),
                "gps_stale": fissure.utils.common.safe_bool(params.get("gps_stale"), default=False),
                "lat": fissure.utils.common.safe_float(params.get("lat")),
                "lon": fissure.utils.common.safe_float(params.get("lon")),
                "alt": fissure.utils.common.safe_float(params.get("alt"), default=0.0),
            }

            await self.node_heartbeat_updates(
                sn_time,
                sn_int,
                sn_uuid,
                sn_ip,
                sn_hiprfisr_ip,
                sn_nickname,
                sn_nettype,
                sn_id_zmq,
                sn_assigned_id,
                sn_state,
            )


    async def node_heartbeat_updates(
        self,
        sn_time,
        sn_int,
        sn_uuid,
        sn_ip,
        sn_hiprfisr_ip,
        sn_nickname,
        sn_nettype,
        sn_id_zmq,
        sn_assigned_id: int,
        sn_state: dict = None,
    ):
        """
        Updates HIPRFISR's sensor node registry from heartbeat data.
        """
        sn_state = sn_state or {}

        # Validate input variables
        if not sn_uuid:
            self.logger.error("Heartbeat missing UUID — ignoring.")
            return

        try:
            sn_assigned_id = int(sn_assigned_id)
        except (ValueError, TypeError):
            sn_assigned_id = 0

        callsign_prefix = self.settings.get("callsign_prefix", "FTN")

        # ---------------------------------------------------------
        # LOOKUP NODE BY UUID
        # ---------------------------------------------------------
        node = self.nodes.get(sn_uuid)
        is_new_node = node is None

        # ---------------------------------------------------------
        # HANDLE ASSIGNED ID LOGIC
        # ---------------------------------------------------------
        final_assigned_id = None
        send_handshake = False

        if sn_nettype == "IP":
            # IP nodes do not participate in the short-ID scheme
            final_assigned_id = -1

        else:  # Meshtastic ID-handling logic
            if is_new_node:
                # ---------------------------
                # FIRST TIME SEEING THIS UUID
                # ---------------------------
                if sn_assigned_id == 0:

                    # Fresh registration request → assign a new one
                    final_assigned_id = self.assigned_id_counter
                    self.assigned_id_counter += 1

                    # We must send the handshake message
                    send_handshake = True

                else:
                    # Hub reboot recovery → accept the node's stored ID
                    final_assigned_id = sn_assigned_id
                    self.assigned_id_counter = max(self.assigned_id_counter, sn_assigned_id + 1)
                    send_handshake = False

            else:
                # ---------------------------
                # EXISTING NODE (UUID known)
                # ---------------------------
                stored_id = node.get("assigned_id", 0)

                if sn_assigned_id == 0:
                    # Node reboot OR stale 0 message → keep stored ID
                    final_assigned_id = stored_id
                    send_handshake = True

                else:
                    # Node claims an ID
                    # If stored_id is >0, we keep that (stale protection)
                    # If stored_id is 0, accept the node’s value
                    if stored_id > 0:
                        final_assigned_id = stored_id
                    else:
                        final_assigned_id = sn_assigned_id

                    self.assigned_id_counter = max(self.assigned_id_counter, final_assigned_id + 1)
                    send_handshake = False
        
        # ---------------------------------------------------------
        # NORMALIZE OPTIONAL NODE STATE FROM HEARTBEAT
        # ---------------------------------------------------------
        incoming_status = sn_state.get("status")
        if incoming_status is not None:
            incoming_status = str(incoming_status).strip()
            if not incoming_status:
                incoming_status = None
        
        incoming_autorun_state = sn_state.get("autorun_state")
        if incoming_autorun_state is not None:
            incoming_autorun_state = str(incoming_autorun_state).strip() or "Idle"

        incoming_version = sn_state.get("version")
        if incoming_version is not None:
            incoming_version = str(incoming_version).strip()

        incoming_gps_source = sn_state.get("gps_source")
        if incoming_gps_source is not None:
            incoming_gps_source = str(incoming_gps_source).strip()

        incoming_lat = sn_state.get("lat")
        incoming_lon = sn_state.get("lon")
        incoming_alt = sn_state.get("alt")

        incoming_gps_valid = bool(sn_state.get("gps_valid", False))
        incoming_gps_stale = bool(sn_state.get("gps_stale", False))
        incoming_gps_time = sn_state.get("gps_time")

        # ---------------------------------------------------------
        # CREATE OR UPDATE NODE ENTRY
        # ---------------------------------------------------------
        if is_new_node:
            node = {
                "uuid": sn_uuid,
                "identity": sn_id_zmq,
                "callsign": f"{callsign_prefix}-{sn_nickname}",

                # Backward-compatible display field used by Dashboard.
                # This is now the Sensor Node IP, not the HIPRFISR IP.
                "ip": sn_ip,

                # Explicit fields for clarity/debugging.
                "node_ip_address": sn_ip,
                "hiprfisr_ip_address": sn_hiprfisr_ip,

                "network_type": sn_nettype,
                "nickname": sn_nickname,
                "settings": {},
                "last_seen": sn_time,
                "interval": sn_int,
                "connected": True,
                "assigned_id": final_assigned_id,

                # Unified node state from heartbeat.
                "status": incoming_status or "unknown",
                "autorun_state": incoming_autorun_state or "Idle",
                "version": incoming_version or "",
                "gps_source": incoming_gps_source or "",
                "gps_valid": incoming_gps_valid,
                "gps_stale": incoming_gps_stale,
                "gps_time": incoming_gps_time,

                # Position is independent from liveness. A node can be alive
                # without a valid GPS fix.
                "lat": incoming_lat,
                "lon": incoming_lon,
                "alt": incoming_alt if incoming_alt is not None else 0.0,
            }
            self.nodes[sn_uuid] = node

        else:
            node["identity"] = sn_id_zmq
            node["callsign"] = f"{callsign_prefix}-{sn_nickname}"

            # Backward-compatible display field used by Dashboard.
            # This is now the Sensor Node IP, not the HIPRFISR IP.
            node["ip"] = sn_ip

            # Explicit fields for clarity/debugging.
            node["node_ip_address"] = sn_ip
            node["hiprfisr_ip_address"] = sn_hiprfisr_ip

            node["network_type"] = sn_nettype
            node["nickname"] = sn_nickname
            node["last_seen"] = sn_time
            node["interval"] = sn_int
            node["connected"] = True
            node["assigned_id"] = final_assigned_id

            # Unified node state from heartbeat.
            # Only overwrite optional string fields when the heartbeat provides them.
            if incoming_status is not None:
                node["status"] = incoming_status
            
            if incoming_autorun_state is not None:
                node["autorun_state"] = incoming_autorun_state

            if incoming_version is not None:
                node["version"] = incoming_version

            if incoming_gps_source is not None:
                node["gps_source"] = incoming_gps_source

            node["gps_valid"] = incoming_gps_valid
            node["gps_stale"] = incoming_gps_stale

            if incoming_gps_time is not None:
                node["gps_time"] = incoming_gps_time

            # Only update position when heartbeat provides coordinates.
            # This avoids erasing a prior valid position if a later heartbeat omits GPS fields.
            if incoming_lat is not None:
                node["lat"] = incoming_lat

            if incoming_lon is not None:
                node["lon"] = incoming_lon

            if incoming_alt is not None:
                node["alt"] = incoming_alt

        # ---------------------------------------------------------
        # SEND HANDSHAKE MESSAGE IF NEEDED (Meshtastic only)
        # ---------------------------------------------------------
        if sn_nettype != "IP" and send_handshake:
            PARAMETERS = {"assigned_id": final_assigned_id}

            msg = {
                fissure.comms.MessageFields.SOURCE: self.identifierLT,
                fissure.comms.MessageFields.DESTINATION: sn_uuid,
                fissure.comms.MessageFields.MESSAGE_NAME: "completeMeshtasticHandshakeLT",
                fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
            }

            await self.meshtastic_node.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)
            # print(f"Handshake sent → assigned_id={final_assigned_id}")

        # ---------------------------------------------------------
        # SEND NORMALIZED NODE STATE TO DASHBOARD
        # ---------------------------------------------------------
        await self.send_node_state_update_to_dashboard(sn_uuid)

        # ---------------------------------------------------------
        # PUBLISH NODE TRACK COT FROM NORMALIZED HEARTBEAT STATE
        # ---------------------------------------------------------
        if sn_nettype == "IP":
            await self.publish_node_track_from_state(sn_uuid)


    async def send_node_state_update_to_dashboard(self, node_uid: str):
        """
        Send the latest normalized node registry record to the Dashboard.

        This is intentionally separate from CoT/TAK publication. Heartbeat
        receipt should update Dashboard node state immediately, even if a
        later CoT/TAK sender suppresses duplicate map tracks.
        """
        if not self.dashboard_connected:
            return

        node = self.nodes.get(node_uid)
        if not node:
            return

        # Avoid sending ROUTER identity bytes or internal/private publish state
        # directly to the Dashboard.
        public_node = {
            "uuid": node.get("uuid", node_uid),
            "callsign": node.get("callsign"),
            "ip": node.get("ip"),
            "node_ip_address": node.get("node_ip_address"),
            "hiprfisr_ip_address": node.get("hiprfisr_ip_address"),
            "network_type": node.get("network_type"),
            "nickname": node.get("nickname"),
            "last_seen": node.get("last_seen"),
            "interval": node.get("interval"),
            "connected": node.get("connected", False),
            "assigned_id": node.get("assigned_id"),

            # Unified node state from heartbeat.
            "status": node.get("status", "unknown"),
            "autorun_state": node.get("autorun_state", "Idle"),
            "version": node.get("version", ""),
            "gps_source": node.get("gps_source", ""),
            "gps_valid": node.get("gps_valid", False),
            "gps_stale": node.get("gps_stale", False),
            "gps_time": node.get("gps_time"),
            "lat": node.get("lat"),
            "lon": node.get("lon"),
            "alt": node.get("alt"),
        }

        PARAMETERS = {
            "node_uid": node_uid,
            "node": public_node,
        }

        msg = {
            fissure.comms.MessageFields.IDENTIFIER: self.identifier,
            fissure.comms.MessageFields.MESSAGE_NAME: "nodeStateUpdate",
            fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
        }

        await self.dashboard_socket.send_msg(
            fissure.comms.MessageTypes.COMMANDS,
            msg
        )


    async def send_node_state_remove_to_dashboard(self, node_uid: str):
        """
        Tell Dashboard that a node was explicitly removed from HIPRFISR.

        This is different from disconnected/stale. Removed means the node
        should be deleted from Dashboard-side node caches/placeholders.
        """
        if not self.dashboard_connected:
            return

        PARAMETERS = {
            "node_uid": node_uid,
        }

        msg = {
            fissure.comms.MessageFields.IDENTIFIER: self.identifier,
            fissure.comms.MessageFields.MESSAGE_NAME: "nodeStateRemove",
            fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
        }

        await self.dashboard_socket.send_msg(
            fissure.comms.MessageTypes.COMMANDS,
            msg
        )


    async def publish_node_track_from_state(self, node_uid: str):
        """
        Publish a node CoT track from the normalized HIPRFISR node state.

        This is intentionally sender-side behavior. The heartbeat capture path
        has already updated self.nodes[node_uid] and Dashboard nodeStateUpdate.
        """
        node = self.nodes.get(node_uid)
        if not node:
            return

        # IP-first for this refactor. Leave Meshtastic on the existing path.
        if node.get("network_type") != "IP":
            return

        lat = node.get("lat")
        lon = node.get("lon")
        alt = node.get("alt", 0.0)

        if not fissure.utils.common.is_valid_lat_lon(lat, lon):
            self.logger.debug(
                f"Skipping node CoT publish for {node_uid}: invalid lat/lon "
                f"lat={lat}, lon={lon}"
            )
            return

        status = str(node.get("status") or "unknown")
        status_lc = status.lower()
        version = str(node.get("version") or "")

        if status_lc in {"idle", "unknown", "disconnected"}:
            tak_icon = self.settings["tak"]["node_idle_icon"]
        else:
            tak_icon = self.settings["tak"]["node_busy_icon"]

        # Match TAK stale time to the node-reported heartbeat interval.
        # This avoids hardcoding 30/60 seconds and keeps the node config authoritative.
        try:
            interval = float(node.get("interval"))
        except (TypeError, ValueError):
            interval = float(self.settings.get("heartbeat_interval", 5))

        if interval <= 0:
            interval = float(self.settings.get("heartbeat_interval", 5))

        try:
            failure_multiple = float(self.settings.get("failure_multiple", 3))
        except (TypeError, ValueError):
            failure_multiple = 3.0

        stale_seconds = int(max(30.0, interval * failure_multiple + interval))

        payload = {
            "msg_type": "track",
            "uid": node_uid,
            "lat": float(lat),
            "lon": float(lon),
            "alt": float(alt or 0.0),
            "time": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
            "remarks": "HEARTBEAT UPDATE",
            "node_uid": node_uid,
            "opid": "heartbeat_state",
            "status": status,
            "version": version,
            "tak_icon": tak_icon,
            "stale": stale_seconds,
        }

        node["tak_icon"] = tak_icon

        await fissure.utils.tak_messages.send(self, payload)


    async def check_heartbeats(self):
        """
        Check heartbeat timestamps for Dashboard, PD, TSI, and Sensor Nodes,
        and update connection state accordingly.
        """
        current_time = time.time()

        # HIPRFISR global heartbeat interval (used for Dashboard, PD, TSI)
        global_interval = float(self.settings.get("heartbeat_interval"))
        failure_multiple = float(self.settings.get("failure_multiple"))

        # -----------------------------------------------------------------
        # Dashboard check
        # -----------------------------------------------------------------
        cutoff_dashboard = current_time - (global_interval * failure_multiple)
        last_dashboard = self.heartbeats.get(fissure.comms.Identifiers.DASHBOARD)

        if last_dashboard is not None:
            if self.dashboard_connected and (last_dashboard < cutoff_dashboard):
                self.dashboard_connected = False
                self.logger.warning("lost dashboard connection")

            elif (not self.dashboard_connected) and (last_dashboard > cutoff_dashboard):
                msg = {
                    fissure.comms.MessageFields.IDENTIFIER: self.identifier,
                    fissure.comms.MessageFields.MESSAGE_NAME: "componentConnected",
                    fissure.comms.MessageFields.PARAMETERS: fissure.comms.Identifiers.DASHBOARD,
                }
                await self.dashboard_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)
                self.dashboard_connected = True

        # -----------------------------------------------------------------
        # PD check
        # -----------------------------------------------------------------
        cutoff_pd = current_time - (global_interval * failure_multiple)
        last_pd = self.heartbeats.get(fissure.comms.Identifiers.PD)

        if last_pd is not None:
            if self.pd_connected and (last_pd < cutoff_pd):
                msg = {
                    fissure.comms.MessageFields.IDENTIFIER: self.identifier,
                    fissure.comms.MessageFields.MESSAGE_NAME: "componentDisconnected",
                    fissure.comms.MessageFields.PARAMETERS: fissure.comms.Identifiers.PD,
                }
                if self.dashboard_connected:
                    await self.dashboard_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)
                self.pd_connected = False

            elif (not self.pd_connected) and (last_pd > cutoff_pd):
                msg = {
                    fissure.comms.MessageFields.IDENTIFIER: self.identifier,
                    fissure.comms.MessageFields.MESSAGE_NAME: "componentConnected",
                    fissure.comms.MessageFields.PARAMETERS: fissure.comms.Identifiers.PD,
                }
                if self.dashboard_connected:
                    await self.dashboard_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)
                self.pd_connected = True

        # -----------------------------------------------------------------
        # TSI check
        # -----------------------------------------------------------------
        cutoff_tsi = current_time - (global_interval * failure_multiple)
        last_tsi = self.heartbeats.get(fissure.comms.Identifiers.TSI)

        if last_tsi is not None:
            if self.tsi_connected and (last_tsi < cutoff_tsi):
                msg = {
                    fissure.comms.MessageFields.IDENTIFIER: self.identifier,
                    fissure.comms.MessageFields.MESSAGE_NAME: "componentDisconnected",
                    fissure.comms.MessageFields.PARAMETERS: fissure.comms.Identifiers.TSI,
                }
                if self.dashboard_connected:
                    await self.dashboard_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)
                self.tsi_connected = False

            elif (not self.tsi_connected) and (last_tsi > cutoff_tsi):
                msg = {
                    fissure.comms.MessageFields.IDENTIFIER: self.identifier,
                    fissure.comms.MessageFields.MESSAGE_NAME: "componentConnected",
                    fissure.comms.MessageFields.PARAMETERS: fissure.comms.Identifiers.TSI,
                }
                if self.dashboard_connected:
                    await self.dashboard_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)
                self.tsi_connected = True

        # ---------------------------------------------------------
        # SENSOR NODE CHECKS
        # ---------------------------------------------------------
        sensor_nodes = getattr(self, "nodes", {}) or {}

        for node_uid, node in sensor_nodes.items():
            # IP-first for this refactor. Leave Meshtastic behavior alone here.
            if node.get("network_type") != "IP":
                continue

            last_seen = node.get("last_seen")
            if last_seen is None:
                continue

            try:
                last_seen = float(last_seen)
            except (TypeError, ValueError):
                continue

            # Use the interval reported by the node. Fall back to the global
            # heartbeat interval only if the node has not reported one.
            try:
                node_interval = float(node.get("interval"))
            except (TypeError, ValueError):
                node_interval = float(self.settings.get("heartbeat_interval", 5))

            if node_interval <= 0:
                node_interval = float(self.settings.get("heartbeat_interval", 5))

            failure_multiple = float(self.settings.get("failure_multiple", 3))
            cutoff = current_time - (node_interval * failure_multiple)

            if node.get("connected", False) and last_seen < cutoff:
                node["connected"] = False
                node["status"] = "Disconnected"

                self.logger.warning(
                    f"Sensor node disconnected: {node_uid} "
                    f"last_seen={fissure.utils.get_timestamp(last_seen)} "
                    f"interval={node_interval}"
                )

                await self.send_node_state_update_to_dashboard(node_uid)


    def resolve_uuid_from_assigned_id(self, assigned_id: int):
        """
        Given an assigned_id, return the corresponding UUID and node entry.

        Returns:
            (uuid, node_entry)
            OR (None, None) if no node has this assigned_id.
        """
        # Normalize assigned_id (handle strings, None, etc.)
        try:
            assigned_id = int(assigned_id)
        except (ValueError, TypeError):
            self.logger.error(f"[resolve] Invalid assigned_id={assigned_id}")
            return None, None

        # Search self.nodes (keyed by UUID)
        for uuid, node in self.nodes.items():
            if node.get("assigned_id") == assigned_id:
                return uuid, node

        # Not found
        self.logger.warning(f"[resolve] No node found with assigned_id={assigned_id}")
        return None, None
    

    async def updateLoggingLevels(self, new_console_level="", new_file_level=""):
        """Update the logging levels on the HIPRFISR and forward to all components."""
        # Update New Levels for the HIPRFISR
        fissure.utils.update_logging_levels(self.logger, new_console_level, new_file_level)

        # Update Other Components
        PARAMETERS = {
            "new_console_level": new_console_level,
            "new_file_level": new_file_level,
        }

        msg = {
            fissure.comms.MessageFields.IDENTIFIER: self.identifier,
            fissure.comms.MessageFields.MESSAGE_NAME: "updateLoggingLevels",
            fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
        }

        if (self.pd_connected is True) and (self.tsi_connected is True):
            await self.backend_router.send_msg(
                fissure.comms.MessageTypes.COMMANDS,
                msg,
                target_ids=[self.pd_id, self.tsi_id],
            )

        # -----------------------------------------
        # Send to all connected IP Sensor Nodes
        # -----------------------------------------
        for node_uid, node_entry in self.nodes.items():
            if not node_entry:
                continue

            # Only send to IP-based nodes. Skip Meshtastic, etc.
            network_type = node_entry.get("network_type", "IP")
            if network_type != "IP":
                continue

            # ROUTER identity for this node
            identity = (
                node_entry.get("identity")
                or node_entry.get("router_identity")
            )

            if identity is None:
                self.logger.warning(
                    f"Skipping logging-level update for node {node_uid}: no ROUTER identity found."
                )
                continue

            try:
                await self.sensor_node_router.send_msg(
                    fissure.comms.MessageTypes.COMMANDS,
                    msg,
                    target_ids=[identity],
                )

            except Exception as e:
                self.logger.error(
                    f"Failed sending logging-level update to node {node_uid} ({network_type}): {e}"
                )


    def start_database_docker_container(self):
        """
        Starts the database Docker container if it is not already running.
        """
        def run_docker_command(command, use_sudo=False, cwd=None):
            """ Helper to run Docker commands with optional sudo and working directory. """
            if use_sudo:
                command.insert(0, "sudo")
            return subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, cwd=cwd)

        try:
            # Define the Docker image to check
            image_name = "postgres:13"

            # Check if the Docker container is running
            result = run_docker_command(['docker', 'ps', '--filter', f'ancestor={image_name}', '--format', '{{.Image}}'])

            # If the command failed due to permissions, retry with sudo
            if result.returncode != 0 and "permission denied" in result.stderr.lower():
                self.logger.info("Docker requires sudo. Retrying with sudo.")
                result = run_docker_command(['docker', 'ps', '--filter', f'ancestor={image_name}', '--format', '{{.Image}}'], use_sudo=True)

            # Check if the container is already running
            if image_name in result.stdout.strip():
                self.logger.info("Database Docker container is already running.")
                return

            # Container not running, start it
            self.logger.info("Database Docker container not found. Starting it...")

            # Define the start command
            start_command = ["docker", "compose", "up", "-d"]
            docker_compose_directory = fissure.utils.FISSURE_ROOT

            # Attempt to start without sudo
            start_result = run_docker_command(start_command, cwd=docker_compose_directory)
            if start_result.returncode != 0 and "permission denied" in start_result.stderr.lower():
                self.logger.info("Starting Docker with sudo.")
                start_result = run_docker_command(start_command, use_sudo=True, cwd=docker_compose_directory)

            if start_result.returncode == 0:
                self.logger.info("Docker container started successfully.")
            else:
                self.logger.error(f"Failed to start Docker container: {start_result.stderr.strip()}")

        except Exception as e:
            self.logger.error(f"Error: {e}")


    def start_tak_docker_container(self):
        """
        Starts the TAK Docker containers (DB and server) if not already running.
        Handles versioned container names dynamically.
        """
        def run_docker_command(command, use_sudo=False, cwd=None):
            """ Helper to run Docker commands with optional sudo and working directory. """
            if use_sudo:
                command.insert(0, "sudo")
            return subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, cwd=cwd)


        def get_matching_containers(name_prefix):
            """ Returns a list of container names matching a given prefix. """
            cmd = ["docker", "ps", "-a", "--filter", f"name={name_prefix}", "--format", "{{.Names}}"]
            result = run_docker_command(cmd)
            if result.returncode != 0 and "permission denied" in result.stderr.lower():
                result = run_docker_command(cmd, use_sudo=True)
            if result.returncode == 0:
                return result.stdout.strip().splitlines()
            else:
                self.logger.error(f"Failed to list containers with prefix '{name_prefix}': {result.stderr.strip()}")
                return []


        def start_container(name):
            """ Starts a container by name, handling sudo if needed. """
            start_cmd = ["docker", "start", name]
            result = run_docker_command(start_cmd)
            if result.returncode != 0 and "permission denied" in result.stderr.lower():
                result = run_docker_command(start_cmd, use_sudo=True)
            return result

        try:
            db_containers = get_matching_containers("takserver-db-")
            server_containers = get_matching_containers("takserver-")

            # Remove DB containers from the server list (avoid duplication)
            server_containers = [c for c in server_containers if not c.startswith("takserver-db-")]

            if not db_containers and not server_containers:
                self.logger.warning("No TAK Docker containers found.")
                return

            for container in db_containers:
                result = start_container(container)
                if result.returncode == 0:
                    self.logger.info(f"Started TAK DB container: {container}")
                else:
                    self.logger.error(f"Failed to start TAK DB container {container}: {result.stderr.strip()}")

            for container in server_containers:
                result = start_container(container)
                if result.returncode == 0:
                    self.logger.info(f"Started TAK Server container: {container}")
                else:
                    self.logger.error(f"Failed to start TAK Server container {container}: {result.stderr.strip()}")

        except Exception as e:
            self.logger.error(f"Exception while starting TAK containers: {e}")
 

    def init_cot_logging(self):
        cfg = self.settings.get("cot_logging", {}) or {}

        enabled = cfg.get("cot_log_enabled", False)
        self.cot_log_enabled_runtime = bool(enabled)

        self.cot_log_lock = Lock()
        self.cot_log_session_dir = None
        self.cot_log_file_index = 1
        self.cot_log_file_path = None
        self.cot_log_max_file_size_bytes = int(cfg.get("max_file_size_mb", 10) * 1024 * 1024)
        self.cot_log_max_file_count = int(cfg.get("max_file_count", 20))

        if not self.cot_log_enabled_runtime:
            return

        base_dir = cfg.get("cot_log_directory", "./Logs/CoT_Logs")
        if not base_dir:
            base_dir = "./Logs/CoT_Logs"

        # Resolve relative path from FISSURE root if you have it
        try:
            if not os.path.isabs(base_dir):
                base_dir = os.path.join(fissure.utils.FISSURE_ROOT, base_dir)
        except Exception:
            base_dir = os.path.abspath(base_dir)

        os.makedirs(base_dir, exist_ok=True)

        session_name = datetime.now(timezone.utc).strftime("%Y-%m-%d_%H-%M-%S")
        session_dir = os.path.join(base_dir, session_name)
        os.makedirs(session_dir, exist_ok=True)

        self.cot_log_session_dir = session_dir
        self.cot_log_file_path = os.path.join(session_dir, "cot_0001.xml")

        self.logger.info(f"CoT logging enabled. Session directory: {session_dir}")


    def rotate_cot_log_file(self):
        self.cot_log_file_index += 1

        if self.cot_log_file_index > self.cot_log_max_file_count:
            self.logger.warning(
                "CoT logging reached max file count. Disabling CoT logging for this session."
            )
            self.cot_log_enabled_runtime = False
            return False

        self.cot_log_file_path = os.path.join(
            self.cot_log_session_dir,
            f"cot_{self.cot_log_file_index:04d}.xml"
        )

        self.logger.info(f"Rotated CoT log file to: {self.cot_log_file_path}")
        return True


    def write_cot_log(self, msg_bytes):
        if not getattr(self, "cot_log_enabled_runtime", False):
            return

        if not getattr(self, "cot_log_file_path", None):
            return

        try:
            with self.cot_log_lock:

                logged_ts = datetime.now(timezone.utc).isoformat()
                xml_text = msg_bytes.decode("utf-8").strip()

                record = (
                    f"<!-- logged_ts={logged_ts} -->\n"
                    f"{xml_text}\n\n"
                )

                record_bytes = record.encode("utf-8")

                # Check if file rotation is needed
                if os.path.exists(self.cot_log_file_path):
                    current_size = os.path.getsize(self.cot_log_file_path)

                    if current_size + len(record_bytes) > self.cot_log_max_file_size_bytes:
                        if not self.rotate_cot_log_file():
                            return

                with open(self.cot_log_file_path, "ab") as f:
                    f.write(record_bytes)

        except Exception as e:
            self.logger.error(f"Failed to write CoT log: {e}")
    

if __name__ == "__main__":
    rc = 0
    try:
        run()
    except Exception:
        rc = 1

    sys.exit(rc)
