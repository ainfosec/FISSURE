# from .Signals import DashboardSignals
from inspect import isfunction
from PyQt5 import QtCore
from types import ModuleType
from typing import Dict, List, Tuple

import asyncio
import fissure.comms
import fissure.utils
import logging
import multiprocessing
import time
import zmq
import signal

EVENT_LOOP_DELAY = 0.1  # Seconds


def run():
    asyncio.run(main())


async def main():
    print("[FISSURE][Dashboard] start")
    dashboard = DashboardBackend()

    await dashboard.begin()
    dashboard.shutdown()

    print("[FISSURE][Dashboard] end")
    fissure.utils.zmq_cleanup()


# Ignore SIGINT in the secondary process
def run_server():
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    fissure.Server.run()


class DashboardBackend:
    callbacks: Dict = {}
    logger: logging.Logger = fissure.utils.get_logger(f"{fissure.comms.Identifiers.DASHBOARD}.backend")
    frontend: QtCore.QObject
    settings: Dict
    ip_address: str
    os_info: Tuple[str, str, str]
    heartbeats: Dict[str, float]  # {name: time, name: time, ...}
    hiprfisr_address: fissure.comms.Address
    hiprfisr_connected: bool
    pd_connected: bool
    tsi_connected: bool
    sensor_node_connected: List[bool]
    session_active: bool
    shutdown: bool


    def __init__(self, frontend: QtCore.QObject):
        self.logger.info("=== INITIALIZING ===")
        self.settings = fissure.utils.get_fissure_config()
        self.ip_address = fissure.utils.get_ip_address()
        self.initialize_comms()
        self.os_info = fissure.utils.get_os_info()

        # Initialize Connection/Heartbeat Variables
        self.heartbeats = {
            fissure.comms.Identifiers.DASHBOARD: None,
            fissure.comms.Identifiers.HIPRFISR: None,
            fissure.comms.Identifiers.PD: None,
            fissure.comms.Identifiers.TSI: None,
            fissure.comms.Identifiers.SENSOR_NODE: [None] * 5,
        }
        self.hiprfisr_address = None
        self.hiprfisr_connected = False
        self.pd_connected = False
        self.tsi_connected = False
        self.sensor_node_connected = [False, False, False, False, False]
        self.session_active = False
        self.shutdown = False
        self.shutting_down_message_received = False

        # Load Library
        self.library = fissure.utils.load_library(self.os_info)

        self.frontend = frontend

        # Register Callbacks
        self.register_callbacks(fissure.callbacks.GenericCallbacks)
        self.register_callbacks(fissure.callbacks.DashboardCallbacks)

        self.logger.info("=== READY ===")


    def initialize_comms(self):
        # Create HiprFisr Listener
        self.hiprfisr_socket = fissure.comms.Listener(
            sock_type=zmq.PAIR, name=f"{fissure.comms.Identifiers.DASHBOARD}::backend"
        )


    async def shutdown_comms(self):
        if self.hiprfisr_connected is True:
            if self.__local_hiprfisr_process is not None:
                await self.shutdown_hiprfisr()
            else:
                await self.disconnect_from_hiprfisr()
        self.hiprfisr_socket.shutdown()


    def start(self):
        """
        Run the backend in the shared Qt/asyncio eventLoop
        """
        asyncio.ensure_future(self.__eventLoop__(), loop=asyncio.get_event_loop()).set_name("Dashboard Backend")


    def stop(self) -> bool:
        """
        Set the shutdown flag to stop the backend
        """
        if self.hiprfisr_connected is False:
            self.shutdown = True

        return not self.hiprfisr_connected


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


    # async def heartbeat_loop(self):
    #     """
    #     Sends and reads heartbeat messages, separate from event loop to prevent freezing on blocking events.
    #     """
    #     while self.shutdown is False:
    #         await self.send_heartbeat()
    #         await self.recv_heartbeat()
    #         self.check_heartbeats()

    #         await asyncio.sleep(EVENT_LOOP_DELAY)


    async def __eventLoop__(self):
        """
        DO NOT CALL DIRECTLY \\
        Instead call `DashboardBackend.start()` to run in the Qt/asyncio Event Loop
        """
        # Start Heartbeat Loop
        # loop = asyncio.get_event_loop()
        # heartbeat_task = loop.create_task(self.heartbeat_loop())

        while self.shutdown is False:
            await self.send_heartbeat()
            await self.recv_heartbeat()
            self.check_heartbeats()

            if self.hiprfisr_connected:
                await self.read_hiprfisr_messages()
            else:
                # yield to pass control flow back to event loop
                await asyncio.sleep(1)
            
            await asyncio.sleep(0.1)

        # # Ensure the Heartbeat Loop is Stopped
        # heartbeat_task.cancel()
        # await heartbeat_task

        # Shut Down Comms
        await self.shutdown_comms()
        fissure.utils.save_fissure_config(data=self.settings)  # Check is in save_fissure_config
        self.logger.info("=== SHUTDOWN ===")
        self.session_active = None


    async def send_heartbeat(self):
        last_heartbeat = self.heartbeats.get(fissure.comms.Identifiers.DASHBOARD)
        now = time.time()
        if (last_heartbeat is None) or (now - last_heartbeat) >= float(self.settings.get("heartbeat_interval")):
            heartbeat = {
                fissure.comms.MessageFields.IDENTIFIER: fissure.comms.Identifiers.DASHBOARD,
                fissure.comms.MessageFields.MESSAGE_NAME: fissure.comms.MessageFields.HEARTBEAT,
                fissure.comms.MessageFields.TIME: now,
                fissure.comms.MessageFields.IP: self.ip_address,
            }
            if self.hiprfisr_connected:
                await self.hiprfisr_socket.send_heartbeat(heartbeat)
                self.heartbeats[fissure.comms.Identifiers.DASHBOARD] = now
                self.logger.debug(f"sent heartbeat ({fissure.utils.get_timestamp(now)})")


    async def recv_heartbeat(self):
        heartbeat = await self.hiprfisr_socket.recv_heartbeat()

        if heartbeat is not None:
            heartbeat_time = float(heartbeat.get(fissure.comms.MessageFields.TIME))
            params = heartbeat.get(fissure.comms.MessageFields.PARAMETERS)
            self.heartbeats[fissure.comms.Identifiers.HIPRFISR] = heartbeat_time
            self.logger.debug(f"received HiprFisr heartbeat ({fissure.utils.get_timestamp(heartbeat_time)})")

            if params is not None:
                self.heartbeats[fissure.comms.Identifiers.PD] = params.get(fissure.comms.Identifiers.PD)
                self.heartbeats[fissure.comms.Identifiers.TSI] = params.get(fissure.comms.Identifiers.TSI)
                self.heartbeats[fissure.comms.Identifiers.SENSOR_NODE] = params.get(
                    fissure.comms.Identifiers.SENSOR_NODE
                )


    def check_heartbeats(self):
        current_time = time.time()
        cutoff_interval = float(self.settings.get("failure_multiple")) * float(self.settings.get("heartbeat_interval"))
        cutoff_time = current_time - cutoff_interval

        # HiprFisr Check
        last_hiprfisr_heartbeat = self.heartbeats.get(fissure.comms.Identifiers.HIPRFISR)
        if last_hiprfisr_heartbeat is not None:
            if self.hiprfisr_connected and (last_hiprfisr_heartbeat < cutoff_time):
                self.hiprfisr_connected = False
                if self.session_active:
                    self.logger.warning("hiprfisr connection lost")
                    # self.frontend.statusBar.hiprfisr.setText("HIPRFISR: OK")  # FIX: Causes error on HIPRFISR connect
                    self.frontend.signals.ComponentStatus.emit(
                        fissure.comms.Identifiers.HIPRFISR, False, self.frontend.statusBar()
                    )

            elif (not self.hiprfisr_connected) and (last_hiprfisr_heartbeat > cutoff_time):
                self.hiprfisr_connected = True
                if self.session_active:
                    self.logger.warning("hiprfisr connection restored")
                    self.frontend.signals.ComponentStatus.emit(
                        fissure.comms.Identifiers.HIPRFISR, True, self.frontend.statusBar()
                    )
                else:
                    self.session_active = True

        # PD Check
        last_pd_heartbeat = self.heartbeats.get(fissure.comms.Identifiers.PD)
        if last_pd_heartbeat is not None:
            if self.pd_connected and (last_pd_heartbeat < cutoff_time):
                self.pd_connected = False
                self.frontend.signals.ComponentStatus.emit(
                    fissure.comms.Identifiers.PD, False, self.frontend.statusBar()
                )

            elif (not self.pd_connected) and (last_pd_heartbeat > cutoff_time):
                self.pd_connected = True
                self.frontend.signals.ComponentStatus.emit(
                    fissure.comms.Identifiers.PD, True, self.frontend.statusBar()
                )

        # TSI Check
        last_tsi_heartbeat = self.heartbeats.get(fissure.comms.Identifiers.TSI)
        if last_tsi_heartbeat is not None:
            if self.tsi_connected and (last_tsi_heartbeat < cutoff_time):
                self.tsi_connected = False
                self.frontend.signals.ComponentStatus.emit(
                    fissure.comms.Identifiers.TSI, False, self.frontend.statusBar()
                )

            elif (not self.tsi_connected) and (last_tsi_heartbeat > cutoff_time):
                self.tsi_connected = True
                self.frontend.signals.ComponentStatus.emit(
                    fissure.comms.Identifiers.TSI, True, self.frontend.statusBar()
                )

        # Sensor Node Checks
        sensor_node_heartbeats = self.heartbeats.get(fissure.comms.Identifiers.SENSOR_NODE)
        for idx in range(0, 5):
            last_sensor_node_heartbeat = sensor_node_heartbeats[idx]
            if last_sensor_node_heartbeat is not None:
                if self.sensor_node_connected[idx] and (last_sensor_node_heartbeat < cutoff_time):
                    self.sensor_node_connected[idx] = False
                    self.frontend.signals.ComponentStatus.emit(
                        f"fissure.comms.Identifiers.SENSOR_NODE_{idx+1}", False, self.frontend.statusBar()
                    )
                elif (not self.sensor_node_connected[idx]) and (last_sensor_node_heartbeat > cutoff_time):
                    self.sensor_node_connected[idx] = True
                    self.frontend.signals.ComponentStatus.emit(
                        f"fissure.comms.Identifiers.SENSOR_NODE_{idx+1}", False, self.frontend.statusBar()
                    )
            else:
                self.frontend.signals.ComponentStatus.emit(
                    f"fissure.comms.Identifiers.SENSOR_NODE_{idx+1}", False, self.frontend.statusBar()
                )


    async def read_hiprfisr_messages(self):
        # TODO
        msg = await self.hiprfisr_socket.recv_msg()
        if msg is not None:
            msg_type = msg.get(fissure.comms.MessageFields.TYPE)
            if msg_type == fissure.comms.MessageTypes.HEARTBEATS:
                self.logger.warning(
                    f"received heartbeat on message channel (from {msg.get(fissure.comms.MessageFields.IDENTIFIER)})"
                )
            elif msg_type == fissure.comms.MessageTypes.COMMANDS:
                await self.hiprfisr_socket.run_callback(self, msg)
            elif msg_type == fissure.comms.MessageTypes.STATUS:
                msg_name = msg.get(fissure.comms.MessageFields.MESSAGE_NAME)
                if msg_name == "Disconnect OK":
                    self.session_active = False
                elif msg_name == "Shutting Down":
                    self.shutting_down_message_received = True


    async def start_local_hiprfisr(self):
        """
        Spawn Local HiprFisr Process
        """
        try:
            multiprocessing.set_start_method("spawn")  # The default `fork` start method causes ZMQ problems
        except RuntimeError:
            pass

        # Run
        self.__local_hiprfisr_process = multiprocessing.Process(target=run_server, name="FISSURE Server")
        self.__local_hiprfisr_process.start()

        # Give HiprFisr some time to spin up
        await asyncio.sleep(1)


    async def connect_to_hiprfisr(self, addr: fissure.comms.Address = None):
        """
        Connect Dashboard to a HiprFisr instance at the specified address

        :param addr: address of the HiprFisr instance
        :type addr: fissure.comms.Address
        """
        self.hiprfisr_address = addr
        if await self.hiprfisr_socket.connect(server_addr=self.hiprfisr_address, timeout=15):  # Small timeout affects connection on startup
            self.logger.info(f"connected to HiprFisr @ {self.hiprfisr_address}")
            self.hiprfisr_connected = True

            # Set Session Flag
            self.session_active = True

            # Send first Heartbeat
            await self.send_heartbeat()


    async def disconnect_from_hiprfisr(self):
        disconnect_notice = {
            fissure.comms.MessageFields.IDENTIFIER: fissure.comms.Identifiers.DASHBOARD,
            fissure.comms.MessageFields.MESSAGE_NAME: "disconnect",
        }
        await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, disconnect_notice)
        while self.session_active is not False:
            msg = await self.hiprfisr_socket.recv_msg()
            if (
                msg is not None
                and msg.get(fissure.comms.MessageFields.IDENTIFIER) == fissure.comms.Identifiers.HIPRFISR
                and msg.get(fissure.comms.MessageFields.TYPE) == fissure.comms.MessageTypes.STATUS
                and msg.get(fissure.comms.MessageFields.MESSAGE_NAME) == "Disconnect OK"
            ):
                self.logger.info("=== DISCONNECT ===")
                self.close_session()


    async def shutdown_hiprfisr(self):
        shutdown_cmd = {
            fissure.comms.MessageFields.IDENTIFIER: fissure.comms.Identifiers.DASHBOARD,
            fissure.comms.MessageFields.MESSAGE_NAME: "shutdown",
            fissure.comms.MessageFields.PARAMETERS: {
                fissure.comms.Parameters.IDENTIFIERS: [fissure.comms.Identifiers.HIPRFISR]
            },
        }
        await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, shutdown_cmd)

        while self.session_active is not False:
            if self.shutting_down_message_received == True:
                self.logger.warning("received shutdown notice from HiprFisr")
                self.close_session()
            await asyncio.sleep(.1)


    def close_session(self):
        self.hiprfisr_socket.disconnect(self.hiprfisr_address)
        self.heartbeats.update(
            {
                fissure.comms.Identifiers.DASHBOARD: 0,
                fissure.comms.Identifiers.HIPRFISR: 0,
                fissure.comms.Identifiers.PD: 0,
                fissure.comms.Identifiers.TSI: 0,
                fissure.comms.Identifiers.SENSOR_NODE: [None] * 5,
            }
        )
        self.hiprfisr_address = None
        self.hiprfisr_connected = False
        self.hiprfisr_connected = False
        self.pd_connected = False
        self.tsi_connected = False
        self.sensor_node_connected = [False, False, False, False, False]
        self.session_active = False


    async def launch_local_sensor_node(self, sensor_node_id, ip_address, msg_port, hb_port, recall_settings):
        PARAMETERS = {
            "sensor_node_id": str(sensor_node_id),
            "ip_address": ip_address,
            "msg_port": msg_port,
            "hb_port": hb_port,
            "recall_settings": recall_settings,
        }
        launch_cmd = {
            fissure.comms.MessageFields.IDENTIFIER: fissure.comms.Identifiers.DASHBOARD,
            fissure.comms.MessageFields.MESSAGE_NAME: "connectToSensorNode",
            fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
        }
        await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, launch_cmd)


    async def connect_remote_sensor_node(self, sensor_node_id, ip_address, msg_port, hb_port, recall_settings):
        PARAMETERS = {
            "sensor_node_id": str(sensor_node_id),
            "ip_address": ip_address,
            "msg_port": msg_port,
            "hb_port": hb_port,
            "recall_settings": recall_settings,
        }
        launch_cmd = {
            fissure.comms.MessageFields.IDENTIFIER: fissure.comms.Identifiers.DASHBOARD,
            fissure.comms.MessageFields.MESSAGE_NAME: "connectToSensorNode",
            fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
        }
        await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, launch_cmd)


    async def disconnect_local_sensor_node(self, sensor_node_id):
        """
        Forwards the terminate sensor node message to the HIPRFISR/Sensor Node.
        """
        PARAMETERS = {"sensor_node_id": str(sensor_node_id)}
        terminate_cmd = {
            fissure.comms.MessageFields.IDENTIFIER: fissure.comms.Identifiers.DASHBOARD,
            fissure.comms.MessageFields.MESSAGE_NAME: "terminateSensorNode",
            fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
        }
        await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, terminate_cmd)


    async def disconnect_remote_sensor_node(self, sensor_node_id, ip_address, msg_port, hb_port, delete_node):
        PARAMETERS = {
            "sensor_node_id": str(sensor_node_id),
            "ip_address": ip_address,
            "msg_port": msg_port,
            "hb_port": hb_port,
            "delete_node": delete_node,
        }
        disconnect_cmd = {
            fissure.comms.MessageFields.IDENTIFIER: fissure.comms.Identifiers.DASHBOARD,
            fissure.comms.MessageFields.MESSAGE_NAME: "disconnectFromSensorNode",
            fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
        }
        await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, disconnect_cmd)


    async def scan_sensor_node(self, tab_index, hardware_list):
        PARAMETERS = {"tab_index": tab_index, "hardware_list": hardware_list}
        scan_cmd = {
            fissure.comms.MessageFields.IDENTIFIER: fissure.comms.Identifiers.DASHBOARD,
            fissure.comms.MessageFields.MESSAGE_NAME: "scanHardware",
            fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
        }
        await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, scan_cmd)


    async def probe_sensor_node(self, tab_index, table_row_text):
        PARAMETERS = {"tab_index": tab_index, "table_row_text": table_row_text}
        probe_cmd = {
            fissure.comms.MessageFields.IDENTIFIER: fissure.comms.Identifiers.DASHBOARD,
            fissure.comms.MessageFields.MESSAGE_NAME: "probeHardware",
            fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
        }
        await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, probe_cmd)


    async def guess_sensor_node(self, tab_index, table_row, table_row_text, guess_index):
        PARAMETERS = {
            "tab_index": tab_index,
            "table_row": table_row,
            "table_row_text": table_row_text,
            "guess_index": guess_index,
        }
        guess_cmd = {
            fissure.comms.MessageFields.IDENTIFIER: fissure.comms.Identifiers.DASHBOARD,
            fissure.comms.MessageFields.MESSAGE_NAME: "guessHardware",
            fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
        }
        await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, guess_cmd)


    async def updateFISSURE_Configuration(self, settings_dict={}):
        """
        Updates the FISSURE settings for all components.
        """
        # Send the Message
        if self.hiprfisr_connected is True:
            PARAMETERS = {"settings_dict": settings_dict}
            msg = {
                fissure.comms.MessageFields.IDENTIFIER: fissure.comms.Identifiers.DASHBOARD,
                fissure.comms.MessageFields.MESSAGE_NAME: "updateFISSURE_Configuration",
                fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
            }
            await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


    async def updateLoggingLevels(self, new_console_level, new_file_level):
        """
        Updates the console and file logging levels for all components.
        """
        # Update New Levels for the Dashboard
        for n in range(0, len(self.logger.handlers)):
            if self.logger.handlers[n].name == "console":
                if new_console_level == "DEBUG":
                    self.logger.handlers[n].level = 10
                elif new_console_level == "INFO":
                    self.logger.handlers[n].level = 20
                elif new_console_level == "WARNING":
                    self.logger.handlers[n].level = 30
                elif new_console_level == "ERROR":
                    self.logger.handlers[n].level = 40
            elif self.logger.handlers[n].name == "file":
                if new_file_level == "DEBUG":
                    self.logger.handlers[n].level = 10
                elif new_file_level == "INFO":
                    self.logger.handlers[n].level = 20
                elif new_file_level == "WARNING":
                    self.logger.handlers[n].level = 30
                elif new_file_level == "ERROR":
                    self.logger.handlers[n].level = 40

        # self.logger.debug("=== debug ===")
        # self.logger.info("=== info ===")
        # self.logger.warning("=== warning ===")
        # self.logger.error("=== error ===")

        # Send the Message
        if self.hiprfisr_connected is True:
            PARAMETERS = {"new_console_level": new_console_level, "new_file_level": new_file_level}
            msg = {
                fissure.comms.MessageFields.IDENTIFIER: fissure.comms.Identifiers.DASHBOARD,
                fissure.comms.MessageFields.MESSAGE_NAME: "updateLoggingLevels",
                fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
            }
            await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


    async def archivePlaylistStart(
        self,
        sensor_node_id,
        flow_graph,
        filenames,
        frequencies,
        sample_rates,
        formats,
        channels,
        gains,
        durations,
        repeat,
        ip_address,
        serial,
        trigger_values,
    ):
        """
        Starts Archive Playlist in response to button press.
        """
        # Send the Message
        if self.hiprfisr_connected is True:
            PARAMETERS = {
                "sensor_node_id": sensor_node_id,
                "flow_graph": flow_graph,
                "filenames": filenames,
                "frequencies": frequencies,
                "sample_rates": sample_rates,
                "formats": formats,
                "channels": channels,
                "gains": gains,
                "durations": durations,
                "repeat": repeat,
                "ip_address": ip_address,
                "serial": serial,
                "trigger_values": trigger_values,
            }
            msg = {
                fissure.comms.MessageFields.IDENTIFIER: fissure.comms.Identifiers.DASHBOARD,
                fissure.comms.MessageFields.MESSAGE_NAME: "archivePlaylistStart",
                fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
            }
            await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


    async def archivePlaylistStop(self, sensor_node_id):
        """
        Stops Archive Playlist in response to button press.
        """
        # Send the Message
        if self.hiprfisr_connected is True:
            PARAMETERS = {"sensor_node_id": sensor_node_id}
            msg = {
                fissure.comms.MessageFields.IDENTIFIER: fissure.comms.Identifiers.DASHBOARD,
                fissure.comms.MessageFields.MESSAGE_NAME: "archivePlaylistStop",
                fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
            }
            await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


    async def attackFlowGraphStart(self, sensor_node_id, flow_graph_filepath, variable_names, variable_values, file_type, run_with_sudo, autorun_index, trigger_values):
        """
        Sends a message to start a single-stage attack.
        """
        # Send the Message
        if self.hiprfisr_connected is True:
            PARAMETERS = {"sensor_node_id": sensor_node_id, "flow_graph_filepath": flow_graph_filepath, "variable_names": variable_names, "variable_values": variable_values, "file_type": file_type, "run_with_sudo": run_with_sudo, "autorun_index": autorun_index, "trigger_values": trigger_values}
            msg = {
                    fissure.comms.MessageFields.IDENTIFIER: fissure.comms.Identifiers.DASHBOARD,
                    fissure.comms.MessageFields.MESSAGE_NAME: "attackFlowGraphStart",
                    fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
            }
            await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


    async def attackFlowGraphStop(self, sensor_node_id, parameter, autorun_index):
        """
        Sends a message to stop a single-stage attack.
        """
        # Send the Message
        if self.hiprfisr_connected is True:
            PARAMETERS = {"sensor_node_id": sensor_node_id, "parameter": parameter, "autorun_index": autorun_index}
            msg = {
                    fissure.comms.MessageFields.IDENTIFIER: fissure.comms.Identifiers.DASHBOARD,
                    fissure.comms.MessageFields.MESSAGE_NAME: "attackFlowGraphStop",
                    fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
            }
            await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


    async def multiStageAttackStart(
        self, 
        sensor_node_id=0,
        filenames=[],
        variable_names=[],
        variable_values=[],
        durations=[],
        repeat=False,
        file_types=[],
        autorun_index=0,
        trigger_values=[]
    ):
        """
        Sends a message to start a multi-stage attack.
        """
        # Send the Message
        if self.hiprfisr_connected is True:
            PARAMETERS = {
                "sensor_node_id": sensor_node_id,
                "filenames": filenames,
                "variable_names": variable_names,
                "variable_values": variable_values,
                "durations": durations,
                "repeat": repeat,
                "file_types": file_types,
                "autorun_index": autorun_index,
                "trigger_values": trigger_values
            }
            msg = {
                    fissure.comms.MessageFields.IDENTIFIER: fissure.comms.Identifiers.DASHBOARD,
                    fissure.comms.MessageFields.MESSAGE_NAME: "multiStageAttackStart",
                    fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
            }
            await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


    async def multiStageAttackStop(self, sensor_node_id=0, autorun_index=0):
        """
        Sends a message to stop a multi-stage attack.
        """
        # Send the Message
        if self.hiprfisr_connected is True:
            PARAMETERS = {
                "sensor_node_id": sensor_node_id,
                "autorun_index": autorun_index,
            }
            msg = {
                    fissure.comms.MessageFields.IDENTIFIER: fissure.comms.Identifiers.DASHBOARD,
                    fissure.comms.MessageFields.MESSAGE_NAME: "multiStageAttackStop",
                    fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
            }
            await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


    async def autorunPlaylistStart(self, sensor_node_id, playlist_dict, trigger_values):
        """
        Sends a message to stop a multi-stage attack.
        """
        # Send the Message
        if self.hiprfisr_connected is True:
            PARAMETERS = {
                "sensor_node_id": sensor_node_id,
                "playlist_dict": playlist_dict,
                "trigger_values": trigger_values,
            }
            msg = {
                    fissure.comms.MessageFields.IDENTIFIER: fissure.comms.Identifiers.DASHBOARD,
                    fissure.comms.MessageFields.MESSAGE_NAME: "autorunPlaylistStart",
                    fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
            }
            await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


    async def autorunPlaylistStop(self, sensor_node_id=0):
        """
        Sends a message to stop a multi-stage attack.
        """
        # Send the Message
        if self.hiprfisr_connected is True:
            PARAMETERS = {
                "sensor_node_id": sensor_node_id,
            }
            msg = {
                    fissure.comms.MessageFields.IDENTIFIER: fissure.comms.Identifiers.DASHBOARD,
                    fissure.comms.MessageFields.MESSAGE_NAME: "autorunPlaylistStop",
                    fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
            }
            await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


    async def overwriteDefaultAutorunPlaylist(self, sensor_node_id=0, playlist_dict={}):
        """
        Sends a message to overwrite the default autorun playlist on the sensor node.
        """
        # Send the Message
        if self.hiprfisr_connected is True:
            PARAMETERS = {
                "sensor_node_id": sensor_node_id,
                "playlist_dict": playlist_dict
            }
            msg = {
                    fissure.comms.MessageFields.IDENTIFIER: fissure.comms.Identifiers.DASHBOARD,
                    fissure.comms.MessageFields.MESSAGE_NAME: "overwriteDefaultAutorunPlaylist",
                    fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
            }
            await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


    async def refreshSensorNodeFiles(self, sensor_node_id=0, sensor_node_folder=""):
        """
        Sends a message to get the sensor node folder contents and return to the Dashboard.
        """
        # Send the Message
        if self.hiprfisr_connected is True:
            PARAMETERS = {
                "sensor_node_id": sensor_node_id,
                "sensor_node_folder": sensor_node_folder
            }
            msg = {
                    fissure.comms.MessageFields.IDENTIFIER: fissure.comms.Identifiers.DASHBOARD,
                    fissure.comms.MessageFields.MESSAGE_NAME: "refreshSensorNodeFiles",
                    fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
            }
            await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


    async def deleteSensorNodeFile(self, sensor_node_id=0, sensor_node_file=""):
        """
        Deletes a file/folder on the sensor node.
        """
        # Send the Message
        if self.hiprfisr_connected is True:
            PARAMETERS = {
                "sensor_node_id": sensor_node_id,
                "sensor_node_file": sensor_node_file
            }
            msg = {
                    fissure.comms.MessageFields.IDENTIFIER: fissure.comms.Identifiers.DASHBOARD,
                    fissure.comms.MessageFields.MESSAGE_NAME: "deleteSensorNodeFile",
                    fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
            }
            await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


    async def downloadSensorNodeFile(self, sensor_node_id=0, sensor_node_file="", download_folder=""):
        """
        Signals to sensor node to transfer a copy of a file or folder for saving it to a specified file path.
        """
        # Send the Message
        if self.hiprfisr_connected is True:
            PARAMETERS = {
                "sensor_node_id": sensor_node_id,
                "sensor_node_file": sensor_node_file,
                "download_folder": download_folder
            }
            msg = {
                    fissure.comms.MessageFields.IDENTIFIER: fissure.comms.Identifiers.DASHBOARD,
                    fissure.comms.MessageFields.MESSAGE_NAME: "downloadSensorNodeFile",
                    fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
            }
            await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


    async def transferSensorNodeFile(self, sensor_node_id=0, local_file="", remote_folder="", refresh_file_list=False):
        """
        Loads a local file and transfers the data to a remote sensor node.
        """
        # Send the Message
        if self.hiprfisr_connected is True:
            PARAMETERS = {
                "sensor_node_id": sensor_node_id,
                "local_file": local_file,
                "remote_folder": remote_folder,
                "refresh_file_list": refresh_file_list
            }
            msg = {
                    fissure.comms.MessageFields.IDENTIFIER: fissure.comms.Identifiers.DASHBOARD,
                    fissure.comms.MessageFields.MESSAGE_NAME: "transferSensorNodeFile",
                    fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
            }
            await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg) 


    async def searchLibrary(self, soi_data="", field_data=""):
        """
        Sends message to search library.yaml for occurences of hex_str.
        """
        # Send the Message
        if self.hiprfisr_connected is True:
            PARAMETERS = {
                "soi_data": soi_data,
                "field_data": field_data,
            }
            msg = {
                    fissure.comms.MessageFields.IDENTIFIER: fissure.comms.Identifiers.DASHBOARD,
                    fissure.comms.MessageFields.MESSAGE_NAME: "searchLibrary",
                    fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
            }
            await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg) 


    async def addToLibrary(
        self,
        protocol_name="",
        packet_name="",
        packet_data="",
        soi_data="",
        statistical_data="",
        modulation_type="",
        demodulation_fg_data="",
        attack="",
        dissector="",
    ):
        """
        Adds new data to the library.
        """
        # Send the Message
        if self.hiprfisr_connected is True:
            PARAMETERS = {
                "protocol_name": protocol_name,
                "packet_name": packet_name,
                "packet_data": packet_data,
                "soi_data": soi_data,
                "statistical_data": statistical_data,
                "modulation_type": modulation_type,
                "demodulation_fg_data": demodulation_fg_data,
                "attack": attack,
                "dissector": dissector,
            }
            msg = {
                    fissure.comms.MessageFields.IDENTIFIER: fissure.comms.Identifiers.DASHBOARD,
                    fissure.comms.MessageFields.MESSAGE_NAME: "addToLibrary",
                    fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
            }
            await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


    async def removeAttackFromLibrary(
        self,
        protocol_name="",
        attacks=[],
        modulations=[],
        hardware=[],
        all_content=False,
        remove_flow_graphs=False,
    ):
        """
        Removes attacks from the library.
        """
        # Send the Message
        if self.hiprfisr_connected is True:
            PARAMETERS = {
                "protocol_name": protocol_name,
                "attacks": attacks,
                "modulations": modulations,
                "hardware": hardware,
                "all_content": all_content,
                "remove_flow_graphs": remove_flow_graphs,
            }
            msg = {
                    fissure.comms.MessageFields.IDENTIFIER: fissure.comms.Identifiers.DASHBOARD,
                    fissure.comms.MessageFields.MESSAGE_NAME: "removeAttackFromLibrary",
                    fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
            }
            await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


    async def removeDemodulationFlowGraph(
        self,
        protocol_name="", 
        modulation_type="", 
        hardware="", 
        demodulation_fg=""
    ):
        """
        Removes demodulation flow graph from the library.
        """
        # Send the Message
        if self.hiprfisr_connected is True:
            PARAMETERS = {
                "protocol_name": protocol_name,
                "modulation_type": modulation_type,
                "hardware": hardware,
                "demodulation_fg": demodulation_fg,
            }
            msg = {
                    fissure.comms.MessageFields.IDENTIFIER: fissure.comms.Identifiers.DASHBOARD,
                    fissure.comms.MessageFields.MESSAGE_NAME: "removeDemodulationFlowGraph",
                    fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
            }
            await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


    async def removeSOI(self, protocol_name="", soi=""):
        """
        Removes SOI from the library.
        """
        # Send the Message
        if self.hiprfisr_connected is True:
            PARAMETERS = {
                "protocol_name": protocol_name,
                "soi": soi,
            }
            msg = {
                    fissure.comms.MessageFields.IDENTIFIER: fissure.comms.Identifiers.DASHBOARD,
                    fissure.comms.MessageFields.MESSAGE_NAME: "removeSOI",
                    fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
            }
            await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


    async def removePacketType(self, protocol_name="", packet_type=""):
        """
        Removes packet type from the library.
        """
        # Send the Message
        if self.hiprfisr_connected is True:
            PARAMETERS = {
                "protocol_name": protocol_name,
                "packet_type": packet_type,
            }
            msg = {
                    fissure.comms.MessageFields.IDENTIFIER: fissure.comms.Identifiers.DASHBOARD,
                    fissure.comms.MessageFields.MESSAGE_NAME: "removePacketType",
                    fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
            }
            await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)

    
    async def removeModulationType(self, protocol_name="", modulation_type=""):
        """
        Removes modulation type from the library.
        """
        # Send the Message
        if self.hiprfisr_connected is True:
            PARAMETERS = {
                "protocol_name": protocol_name,
                "modulation_type": modulation_type,
            }
            msg = {
                    fissure.comms.MessageFields.IDENTIFIER: fissure.comms.Identifiers.DASHBOARD,
                    fissure.comms.MessageFields.MESSAGE_NAME: "removeModulationType",
                    fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
            }
            await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


    async def iqFlowGraphStart(self, sensor_node_id=0, flow_graph_filepath="", variable_names=[], variable_values=[], file_type=""):
        """
        Command for running an IQ flow graph.
        """
        # Send the Message
        if self.hiprfisr_connected is True:
            PARAMETERS = {
                "sensor_node_id": sensor_node_id,
                "flow_graph_filepath": flow_graph_filepath,
                "variable_names": variable_names,
                "variable_values": variable_values,
                "file_type": file_type,
            }
            msg = {
                    fissure.comms.MessageFields.IDENTIFIER: fissure.comms.Identifiers.DASHBOARD,
                    fissure.comms.MessageFields.MESSAGE_NAME: "iqFlowGraphStart",
                    fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
            }
            await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


    async def iqFlowGraphStop(self, sensor_node_id=0, parameter=""):
        """
        Command for stopping an IQ flow graph.
        """
        # Send the Message
        if self.hiprfisr_connected is True:
            PARAMETERS = {
                "sensor_node_id": sensor_node_id,
                "parameter": parameter,
            }
            msg = {
                    fissure.comms.MessageFields.IDENTIFIER: fissure.comms.Identifiers.DASHBOARD,
                    fissure.comms.MessageFields.MESSAGE_NAME: "iqFlowGraphStop",
                    fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
            }
            await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


    async def inspectionFlowGraphStart(
        self, 
        sensor_node_id=0, 
        flow_graph_filepath="", 
        variable_names=[], 
        variable_values=[], 
        file_type=""
    ):
        """
        Command for starting an inspection flow graph.
        """
        # Send the Message
        if self.hiprfisr_connected is True:
            PARAMETERS = {
                "sensor_node_id": sensor_node_id,
                "flow_graph_filepath": flow_graph_filepath,
                "variable_names": variable_names,
                "variable_values": variable_values,
                "file_type": file_type,
            }
            msg = {
                    fissure.comms.MessageFields.IDENTIFIER: fissure.comms.Identifiers.DASHBOARD,
                    fissure.comms.MessageFields.MESSAGE_NAME: "inspectionFlowGraphStart",
                    fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
            }
            await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


    async def inspectionFlowGraphStop(self, sensor_node_id=0, parameter=""):
        """
        Command for stopping an inspection flow graph.
        """
        # Send the Message
        if self.hiprfisr_connected is True:
            PARAMETERS = {
                "sensor_node_id": sensor_node_id,
                "parameter": parameter,
            }
            msg = {
                    fissure.comms.MessageFields.IDENTIFIER: fissure.comms.Identifiers.DASHBOARD,
                    fissure.comms.MessageFields.MESSAGE_NAME: "inspectionFlowGraphStop",
                    fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
            }
            await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


    async def findEntropy(self, message_length=0, preamble=""):
        """
        Sends a message to Protocol Discovery to find the entropy for the bit positions of fixed-length messages.
        """
        # Send the Message
        if self.hiprfisr_connected is True:
            PARAMETERS = {
                "message_length": message_length,
                "preamble": preamble,
            }
            msg = {
                    fissure.comms.MessageFields.IDENTIFIER: fissure.comms.Identifiers.DASHBOARD,
                    fissure.comms.MessageFields.MESSAGE_NAME: "findEntropy",
                    fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
            }
            await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)

    
    async def setBufferSize(self, min_buffer_size=0, max_buffer_size=0):
        """
        Sends a message to Protocol Discovery to find the entropy for the bit positions of fixed-length messages.
        """
        # Send the Message
        if self.hiprfisr_connected is True:
            PARAMETERS = {
                "min_buffer_size": min_buffer_size,
                "max_buffer_size": max_buffer_size,
            }
            msg = {
                    fissure.comms.MessageFields.IDENTIFIER: fissure.comms.Identifiers.DASHBOARD,
                    fissure.comms.MessageFields.MESSAGE_NAME: "setBufferSize",
                    fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
            }
            await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


    async def clearPD_Buffer(self):
        """
        Sends a message to Protocol Discovery to clear its buffer.
        """
        # Send the Message
        if self.hiprfisr_connected is True:
            msg = {
                    fissure.comms.MessageFields.IDENTIFIER: fissure.comms.Identifiers.DASHBOARD,
                    fissure.comms.MessageFields.MESSAGE_NAME: "clearPD_Buffer",
            }
            await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


    async def stopPD(self, sensor_node_id=0):
        """
        Signals to PD to stop protocol discovery.
        """
        # Send the Message
        if self.hiprfisr_connected is True:
            PARAMETERS = {
                "sensor_node_id": sensor_node_id,
            }
            msg = {
                    fissure.comms.MessageFields.IDENTIFIER: fissure.comms.Identifiers.DASHBOARD,
                    fissure.comms.MessageFields.MESSAGE_NAME: "stopPD",
                    fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
            }
            await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)

    
    async def startPD(self, sensor_node_id=0):
        """
        Signals to PD and sensor node to start protocol discovery.
        """
        # Send the Message
        if self.hiprfisr_connected is True:
            PARAMETERS = {
                "sensor_node_id": sensor_node_id,
            }
            msg = {
                    fissure.comms.MessageFields.IDENTIFIER: fissure.comms.Identifiers.DASHBOARD,
                    fissure.comms.MessageFields.MESSAGE_NAME: "startPD",
                    fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
            }
            await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)
            

    async def setAutoStartPD(self, value=False):
        """
        Controls whether Protocol Discovery will begin immediately when a target signal is selected.
        """
        # Send the Message
        if self.hiprfisr_connected is True:
            PARAMETERS = {
                "value": value,
            }
            msg = {
                    fissure.comms.MessageFields.IDENTIFIER: fissure.comms.Identifiers.DASHBOARD,
                    fissure.comms.MessageFields.MESSAGE_NAME: "setAutoStartPD",
                    fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
            }
            await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


    async def addPubSocket(self, ip_address="", port=0):
        """
        Signals to Protocol Discovery to add an additional ZMQ PUB for reading bits.
        """
        # Send the Message
        if self.hiprfisr_connected is True:
            PARAMETERS = {
                "ip_address": ip_address,
                "port": port,
            }
            msg = {
                    fissure.comms.MessageFields.IDENTIFIER: fissure.comms.Identifiers.DASHBOARD,
                    fissure.comms.MessageFields.MESSAGE_NAME: "addPubSocket",
                    fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
            }
            await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


    async def removePubSocket(self, address=""):
        """
        Signals to Protocol Discovery to remove a ZMQ PUB.
        """
        # Send the Message
        if self.hiprfisr_connected is True:
            PARAMETERS = {"address": address}
            msg = {
                    fissure.comms.MessageFields.IDENTIFIER: fissure.comms.Identifiers.DASHBOARD,
                    fissure.comms.MessageFields.MESSAGE_NAME: "removePubSocket",
                    fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
            }
            await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


    async def searchLibraryForFlowGraphs(self, soi_data=[], hardware=""):
        """
        Queries protocol discovery to look in its version of the library to recommend flow graphs for the SOI.
        """
        # Send the Message
        if self.hiprfisr_connected is True:
            PARAMETERS = {
                "soi_data": soi_data,
                "hardware": hardware
            }
            msg = {
                    fissure.comms.MessageFields.IDENTIFIER: fissure.comms.Identifiers.DASHBOARD,
                    fissure.comms.MessageFields.MESSAGE_NAME: "searchLibraryForFlowGraphs",
                    fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
            }
            await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


    async def protocolDiscoveryFG_Stop(self, sensor_node_id=0):
        """
        Sends message to Sensor Node to stop a running flow graph.
        """
        # Send the Message
        if self.hiprfisr_connected is True:
            PARAMETERS = {
                "sensor_node_id": sensor_node_id,
            }
            msg = {
                    fissure.comms.MessageFields.IDENTIFIER: fissure.comms.Identifiers.DASHBOARD,
                    fissure.comms.MessageFields.MESSAGE_NAME: "protocolDiscoveryFG_Stop",
                    fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
            }
            await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


    async def protocolDiscoveryFG_Start(self, sensor_node_id=0, flow_graph_filepath="", variable_names=[], variable_values=[]):
        """
        Sends message to Sensor Node to run a flow graph.
        """
        # Send the Message
        if self.hiprfisr_connected is True:
            PARAMETERS = {
                "sensor_node_id": sensor_node_id,
                "flow_graph_filepath": flow_graph_filepath,
                "variable_names": variable_names,
                "variable_values": variable_values
            }
            msg = {
                    fissure.comms.MessageFields.IDENTIFIER: fissure.comms.Identifiers.DASHBOARD,
                    fissure.comms.MessageFields.MESSAGE_NAME: "protocolDiscoveryFG_Start",
                    fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
            }
            await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


    async def setVariable(self, sensor_node_id=0, flow_graph="", variable="", value=""):
        """
        Sends a message to Sensor Node to change the variable of the running flow graph.
        """
        # Send the Message
        if self.hiprfisr_connected is True:
            PARAMETERS = {
                "sensor_node_id": sensor_node_id,
                "flow_graph": flow_graph,
                "variable": variable,
                "value": value
            }
            msg = {
                    fissure.comms.MessageFields.IDENTIFIER: fissure.comms.Identifiers.DASHBOARD,
                    fissure.comms.MessageFields.MESSAGE_NAME: "setVariable",
                    fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
            }
            await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)
            
    
    async def findPreambles(self, window_min=0, window_max=0, ranking=0, std_deviations=0):
        """
        Sends message to PD to search the buffer for preambles.
        """
        # Send the Message
        if self.hiprfisr_connected is True:
            PARAMETERS = {
                "window_min": window_min,
                "window_max": window_max,
                "ranking": ranking,
                "std_deviations": std_deviations
            }
            msg = {
                    fissure.comms.MessageFields.IDENTIFIER: fissure.comms.Identifiers.DASHBOARD,
                    fissure.comms.MessageFields.MESSAGE_NAME: "findPreambles",
                    fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
            }
            await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)
            

    async def sliceByPreamble(self, preamble="", first_n=0, estimated_length=0):
        """
        Sends message to PD to slice the data by a single preamble.
        """
        # Send the Message
        if self.hiprfisr_connected is True:
            PARAMETERS = {
                "preamble": preamble,
                "first_n": first_n,
                "estimated_length": estimated_length,
            }
            msg = {
                    fissure.comms.MessageFields.IDENTIFIER: fissure.comms.Identifiers.DASHBOARD,
                    fissure.comms.MessageFields.MESSAGE_NAME: "sliceByPreamble",
                    fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
            }
            await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


    async def snifferFlowGraphStart(self, sensor_node_id=0, flow_graph_filepath="", variable_names=[], variable_values=[]):
        """
        Starts a sniffer flow graph.
        """
        # Send the Message
        if self.hiprfisr_connected is True:
            PARAMETERS = {
                "sensor_node_id": sensor_node_id,
                "flow_graph_filepath": flow_graph_filepath,
                "variable_names": variable_names,
                "variable_values": variable_values,
            }
            msg = {
                    fissure.comms.MessageFields.IDENTIFIER: fissure.comms.Identifiers.DASHBOARD,
                    fissure.comms.MessageFields.MESSAGE_NAME: "snifferFlowGraphStart",
                    fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
            }
            await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


    async def snifferFlowGraphStop(self, sensor_node_id=0, parameter=""):
        """
        Stops a sniffer flow graph.
        """
        # Send the Message
        if self.hiprfisr_connected is True:
            PARAMETERS = {
                "sensor_node_id": sensor_node_id,
                "parameter": parameter,
            }
            msg = {
                    fissure.comms.MessageFields.IDENTIFIER: fissure.comms.Identifiers.DASHBOARD,
                    fissure.comms.MessageFields.MESSAGE_NAME: "snifferFlowGraphStop",
                    fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
            }
            await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


    async def physicalFuzzingStop(self, sensor_node_id=0):
        """
        Sends message to Sensor Node to stop the physical fuzzing being performed on a running flow graph.
        """
        # Send the Message
        if self.hiprfisr_connected is True:
            PARAMETERS = {
                "sensor_node_id": sensor_node_id,
            }
            msg = {
                    fissure.comms.MessageFields.IDENTIFIER: fissure.comms.Identifiers.DASHBOARD,
                    fissure.comms.MessageFields.MESSAGE_NAME: "physicalFuzzingStop",
                    fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
            }
            await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)

    
    async def physicalFuzzingStart(
        self, 
        sensor_node_id=0,
        fuzzing_variables=[],
        fuzzing_type="",
        fuzzing_min=0,
        fuzzing_max=0,
        fuzzing_update_period=0,
        fuzzing_seed_step=0,
    ):
        """
        Command for starting physical fuzzing on a running flow graph.
        """
        # Send the Message
        if self.hiprfisr_connected is True:
            PARAMETERS = {
                "sensor_node_id": sensor_node_id,
                "fuzzing_variables": fuzzing_variables,
                "fuzzing_type": fuzzing_type,
                "fuzzing_min": fuzzing_min,
                "fuzzing_max": fuzzing_max,
                "fuzzing_update_period": fuzzing_update_period,
                "fuzzing_seed_step": fuzzing_seed_step,
            }
            msg = {
                    fissure.comms.MessageFields.IDENTIFIER: fissure.comms.Identifiers.DASHBOARD,
                    fissure.comms.MessageFields.MESSAGE_NAME: "physicalFuzzingStart",
                    fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
            }
            await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


    async def clearWidebandList(self):
        """
        Clears the Wideband List.
        """
        # Send the Message
        if self.hiprfisr_connected is True:
            msg = {
                    fissure.comms.MessageFields.IDENTIFIER: fissure.comms.Identifiers.DASHBOARD,
                    fissure.comms.MessageFields.MESSAGE_NAME: "clearWidebandList",
            }
            await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)

    
    async def updateConfiguration(
        self, 
        sensor_node_id=0, 
        start_frequency=0, 
        end_frequency=0, 
        step_size=0, 
        dwell_time=0,
        detector_port=0
    ):
        """
        Forwards the Update Configuration message to a sensor node.
        """
        # Send the Message
        if self.hiprfisr_connected is True:
            PARAMETERS = {
                "sensor_node_id": sensor_node_id,
                "start_frequency": start_frequency,
                "end_frequency": end_frequency,
                "step_size": step_size,
                "dwell_time": dwell_time,
                "detector_port": detector_port,
            }
            msg = {
                    fissure.comms.MessageFields.IDENTIFIER: fissure.comms.Identifiers.DASHBOARD,
                    fissure.comms.MessageFields.MESSAGE_NAME: "updateConfiguration",
                    fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
            }
            await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


    async def addBlacklist(self, start_frequency=0, end_frequency=0):
        """
        Forwards Add Blacklist message to TSI.
        """
        # Send the Message
        if self.hiprfisr_connected is True:
            PARAMETERS = {
                "start_frequency": start_frequency,
                "end_frequency": end_frequency,
            }
            msg = {
                    fissure.comms.MessageFields.IDENTIFIER: fissure.comms.Identifiers.DASHBOARD,
                    fissure.comms.MessageFields.MESSAGE_NAME: "addBlacklist",
                    fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
            }
            await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


    async def removeBlacklist(self, start_frequency=0, end_frequency=0):
        """
        Forwards Remove Blacklist message to TSI.
        """
        # Send the Message
        if self.hiprfisr_connected is True:
            PARAMETERS = {
                "start_frequency": start_frequency,
                "end_frequency": end_frequency,
            }
            msg = {
                    fissure.comms.MessageFields.IDENTIFIER: fissure.comms.Identifiers.DASHBOARD,
                    fissure.comms.MessageFields.MESSAGE_NAME: "removeBlacklist",
                    fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
            }
            await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)

    
    async def startTSI_Detector(self, sensor_node_id=0, detector="", variable_names=[], variable_values=[], detector_port=0):
        """
        Signals to sensor node to start TSI detector.
        """
        # Send the Message
        if self.hiprfisr_connected is True:
            PARAMETERS = {
                "sensor_node_id": sensor_node_id,
                "detector": detector,
                "variable_names": variable_names,
                "variable_values": variable_values,
                "detector_port": detector_port,
            }
            msg = {
                    fissure.comms.MessageFields.IDENTIFIER: fissure.comms.Identifiers.DASHBOARD,
                    fissure.comms.MessageFields.MESSAGE_NAME: "startTSI_Detector",
                    fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
            }
            await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


    async def stopTSI_Detector(self, sensor_node_id=0):
        """
        Signals to sensor node to stop TSI detector.
        """
        # Send the Message
        if self.hiprfisr_connected is True:
            PARAMETERS = {
                "sensor_node_id": sensor_node_id,
            }
            msg = {
                    fissure.comms.MessageFields.IDENTIFIER: fissure.comms.Identifiers.DASHBOARD,
                    fissure.comms.MessageFields.MESSAGE_NAME: "stopTSI_Detector",
                    fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
            }
            await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)

    
    async def startTSI_Conditioner(
        self,
        sensor_node_id=0,
        common_parameter_names=[],
        common_parameter_values=[],
        method_parameter_names=[],
        method_parameter_values=[],
    ):
        """
        Signals to TSI to start TSI Conditioner.
        """
        # Send the Message
        if self.hiprfisr_connected is True:
            PARAMETERS = {
                "sensor_node_id": sensor_node_id,
                "common_parameter_names": common_parameter_names,
                "common_parameter_values": common_parameter_values,
                "method_parameter_names": method_parameter_names,
                "method_parameter_values": method_parameter_values,
            }
            msg = {
                    fissure.comms.MessageFields.IDENTIFIER: fissure.comms.Identifiers.DASHBOARD,
                    fissure.comms.MessageFields.MESSAGE_NAME: "startTSI_Conditioner",
                    fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
            }
            await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


    async def stopTSI_Conditioner(self, sensor_node_id=0):
        """
        Signals to TSI to stop TSI conditioner.
        """
        # Send the Message
        if self.hiprfisr_connected is True:
            PARAMETERS = {
                "sensor_node_id": sensor_node_id,
            }
            msg = {
                    fissure.comms.MessageFields.IDENTIFIER: fissure.comms.Identifiers.DASHBOARD,
                    fissure.comms.MessageFields.MESSAGE_NAME: "stopTSI_Conditioner",
                    fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
            }
            await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


    async def startTSI_FE(self, common_parameter_names=[], common_parameter_values=[]):
        """
        Signals to TSI to start TSI feature extractor.
        """
        # Send the Message
        if self.hiprfisr_connected is True:
            PARAMETERS = {
                "common_parameter_names": common_parameter_names,
                "common_parameter_values": common_parameter_values,
            }
            msg = {
                    fissure.comms.MessageFields.IDENTIFIER: fissure.comms.Identifiers.DASHBOARD,
                    fissure.comms.MessageFields.MESSAGE_NAME: "startTSI_FE",
                    fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
            }
            await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


    async def stopTSI_FE(self):
        """
        Signals to TSI to stop TSI feature extractor.
        """
        # Send the Message
        if self.hiprfisr_connected is True:
            msg = {
                    fissure.comms.MessageFields.IDENTIFIER: fissure.comms.Identifiers.DASHBOARD,
                    fissure.comms.MessageFields.MESSAGE_NAME: "stopTSI_FE",
            }
            await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


    async def startScapy(self, sensor_node_id=0, interface="", interval=0, loop=False, operating_system=""):
        """
        Signals to Sensor Node to start Scapy.
        """
        # Send the Message
        if self.hiprfisr_connected is True:
            PARAMETERS = {
                "sensor_node_id": sensor_node_id,
                "interface": interface,
                "interval": interval,
                "loop": loop,
                "operating_system": operating_system,
            }
            msg = {
                    fissure.comms.MessageFields.IDENTIFIER: fissure.comms.Identifiers.DASHBOARD,
                    fissure.comms.MessageFields.MESSAGE_NAME: "startScapy",
                    fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
            }
            await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


    async def stopScapy(self, sensor_node_id=0):
        """
        Signals to Sensor Node to stop Scapy.
        """
        # Send the Message
        if self.hiprfisr_connected is True:
            PARAMETERS = {
                "sensor_node_id": sensor_node_id,
            }
            msg = {
                    fissure.comms.MessageFields.IDENTIFIER: fissure.comms.Identifiers.DASHBOARD,
                    fissure.comms.MessageFields.MESSAGE_NAME: "stopScapy",
                    fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
            }
            await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


    async def deleteArchiveReplayFiles(self, sensor_node_id=0):
        """
        Deletes all the files in the Archive_Replay folder on the sensor node ahead of file transfer for replay.
        """
        # Send the Message
        if self.hiprfisr_connected is True:
            PARAMETERS = {
                "sensor_node_id": sensor_node_id,
            }
            msg = {
                    fissure.comms.MessageFields.IDENTIFIER: fissure.comms.Identifiers.DASHBOARD,
                    fissure.comms.MessageFields.MESSAGE_NAME: "deleteArchiveReplayFiles",
                    fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
            }
            await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)

