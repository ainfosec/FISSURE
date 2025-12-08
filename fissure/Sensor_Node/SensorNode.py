#!/usr/bin/env python3

import argparse
import importlib.util
import time
import random
import yaml
import zmq
import os
import threading
import sys
from tempfile import mkstemp
from shutil import move, make_archive
from os import remove, close
import inspect,sys,types
import subprocess
import binascii
from dateutil import parser
import csv
import signal
import json

from inspect import isfunction
from types import ModuleType
from typing import Dict, List, Union, Callable, Optional, Any

import asyncio
import fissure.callbacks
import fissure.comms
import fissure.utils
from fissure.utils import PLUGIN_DIR

import uuid
import logging

from concurrent.futures import ThreadPoolExecutor

from fissure.utils.alert_sender import alertSender
from datetime import datetime, timezone

import warnings
import traceback
warnings.filterwarnings("ignore", category=DeprecationWarning)  # Scapy warnings

IP_ADDRESS = "127.0.0.1"
CERT_DIR = "certificates"

DELAY = 0.02  # Seconds


def add_subdirectories_to_path(base_path):
    """
    Add all subdirectories of a base path to sys.path.
    """
    for root, dirs, files in os.walk(base_path):
        sys.path.insert(0, root)  # Add each subdirectory to sys.path


if "maint-3.8" in fissure.utils.get_fg_library_dir(fissure.utils.get_os_info()):
    sys.path.insert(0, os.path.join(fissure.utils.FISSURE_ROOT, "Flow Graph Library", "maint-3.8", "PD Flow Graphs"))
    sys.path.insert(0, os.path.join(fissure.utils.FISSURE_ROOT, "Flow Graph Library", "maint-3.8", "Single-Stage Flow Graphs"))
    sys.path.insert(0, os.path.join(fissure.utils.FISSURE_ROOT, "Flow Graph Library", "maint-3.8", "Fuzzing Flow Graphs"))
    sys.path.insert(0, os.path.join(fissure.utils.FISSURE_ROOT, "Flow Graph Library", "maint-3.8", "IQ Flow Graphs"))
    sys.path.insert(0, os.path.join(fissure.utils.FISSURE_ROOT, "Flow Graph Library", "maint-3.8", "Archive Flow Graphs"))
    sys.path.insert(0, os.path.join(fissure.utils.FISSURE_ROOT, "Flow Graph Library", "maint-3.8", "Sniffer Flow Graphs"))
    add_subdirectories_to_path(os.path.join(fissure.utils.FISSURE_ROOT, "Flow Graph Library", "maint-3.8", "TSI Flow Graphs"))
elif "maint-3.10" in fissure.utils.get_fg_library_dir(fissure.utils.get_os_info()):
    sys.path.insert(0, os.path.join(fissure.utils.FISSURE_ROOT, "Flow Graph Library", "maint-3.10", "PD Flow Graphs"))
    sys.path.insert(0, os.path.join(fissure.utils.FISSURE_ROOT, "Flow Graph Library", "maint-3.10", "Single-Stage Flow Graphs"))
    sys.path.insert(0, os.path.join(fissure.utils.FISSURE_ROOT, "Flow Graph Library", "maint-3.10", "Fuzzing Flow Graphs"))
    sys.path.insert(0, os.path.join(fissure.utils.FISSURE_ROOT, "Flow Graph Library", "maint-3.10", "IQ Flow Graphs"))
    sys.path.insert(0, os.path.join(fissure.utils.FISSURE_ROOT, "Flow Graph Library", "maint-3.10", "Archive Flow Graphs"))
    sys.path.insert(0, os.path.join(fissure.utils.FISSURE_ROOT, "Flow Graph Library", "maint-3.10", "Sniffer Flow Graphs"))
    add_subdirectories_to_path(os.path.join(fissure.utils.FISSURE_ROOT, "Flow Graph Library", "maint-3.10", "TSI Flow Graphs"))
sys.path.insert(0, '/tmp')


def parse_args():
    parser = argparse.ArgumentParser(description="Start the Sensor Node.")
    parser.add_argument("--local", action="store_true", help="Run in local mode.")
    return parser.parse_args()


def run(local_flag):
    try:
        asyncio.run(main(local_flag))
    except KeyboardInterrupt:
        print("[FISSURE][Sensor Node] KeyboardInterrupt - exiting cleanly")
    except SystemExit:
        pass


async def main(local_flag):
    print("[FISSURE][Sensor Node] start")

    # ---------------------------------------------------------
    # Initialize Sensor Node
    # ---------------------------------------------------------
    sensor_node = SensorNode(local_flag)

    # ---------------------------------------------------------
    # Initialize communications (async DEALER connect)
    # ---------------------------------------------------------
    await sensor_node.initialize_comms()

    # ---------------------------------------------------------
    # Start Heartbeat Loop
    # ---------------------------------------------------------
    # heartbeat_task = asyncio.create_task(sensor_node.heartbeat_loop())

    # ---------------------------------------------------------
    # Start GPS Loop (if enabled)
    # ---------------------------------------------------------
    gps_task = None
    gps_manager = None

    if sensor_node.gps_autostart:
        gps_manager = GPSManager(
            sensor_node.logger,
            gps_update_interval_seconds=sensor_node.gps_update_interval_seconds,
            gps_callback=sensor_node.gpsUpdate,
            gpsd_serial_port=sensor_node.gpsd_serial_port,
            settings=sensor_node.settings_dict['Sensor Node']['gps'],
            meshtastic_lock=sensor_node.meshtastic_lock
        )

        # Meshtastic GPS special handling
        if sensor_node.gps_source == "Meshtastic":
            if sensor_node.network_type == "Meshtastic":
                gps_task = asyncio.create_task(
                    gps_manager.periodic_gps_update("Meshtastic", sensor_node.hiprfisr_socket)
                )
            else:
                gps_task = asyncio.create_task(
                    gps_manager.periodic_gps_update("Meshtastic New Connection", sensor_node.meshtastic_serial_port)
                )
        else:
            # GPSD, saved position, or online IP lookup
            gps_task = asyncio.create_task(
                gps_manager.periodic_gps_update(sensor_node.gps_source, None)
            )

    # ---------------------------------------------------------
    # Start Sensor Node Main Loop
    # ---------------------------------------------------------
    try:
        await sensor_node.begin()

    finally:
        # -----------------------------------------------------
        # Stop GPS Task
        # -----------------------------------------------------
        if gps_task:
            gps_task.cancel()
            try:
                await gps_task
            except asyncio.CancelledError:
                pass

        # -----------------------------------------------------
        # Stop GPS Manager
        # -----------------------------------------------------
        if gps_manager:
            gps_manager.stop()

        # -----------------------------------------------------
        # Cleanup ZMQ
        # -----------------------------------------------------
        if not local_flag:
            fissure.utils.zmq_cleanup()

        print("[FISSURE][Sensor Node] end")
        return


class SensorNode(object):
    """ 
    Class that contains the functions for the sensor node.
    """
    
    # settings: Dict
    # identifier: str = "sensor node " + str(uuid.uuid4())[:8]  #fissure.comms.Identifiers.SENSOR_NODE_0
    #logger: logging.Logger = fissure.utils.get_logger(fissure.comms.Identifiers.SENSOR_NODE_0)
    # logger: logging.Logger = fissure.utils.get_logger(identifier)
    # ip_address: str
    # hiprfisr_socket: fissure.comms.Server  # PAIR
    #hiprfisr_connected: bool
    # sensor_nodes: List[Listener]  # DEALER/DEALER
    # heartbeats: Dict[str, Union[float, Dict[int, float]]]  # {name: time, name: time, ... sensor_nodes: {node_id: time}}
    callbacks: Dict = {}
    # shutdown: bool
    
    #######################  FISSURE Functions  ########################

    def __init__(self, local_flag):
        # self.hiprfisr_connected = False
        self.local_remote = "local" if local_flag else "remote"
        

        self.os_info = fissure.utils.get_os_info()
        filename = os.path.join(fissure.utils.SENSOR_NODE_DIR, "Sensor_Node_Config", "default.yaml")
        with open(filename) as yaml_library_file:
            self.settings_dict = yaml.load(yaml_library_file, yaml.FullLoader)

        if self.local_remote == "local":
            self.network_type = "IP"
            self.ip_address = "ipc"
        else:
            self.network_type = str(self.settings_dict['Sensor Node']['network_type'])
            self.ip_address = str(self.settings_dict['Sensor Node']['ip_address'])
        
        self.child_tasks = []
        self.sockets = []

        # Load UUIDs, big for IP, assigned ID for Meshtastic
        self.uuid = self.load_or_create_uuid()  # Read from file

        self.identifier = self.uuid  # IP source ID (full UUID)
        self.assigned_id = 0  # Meshtastic source ID (temporary hub ID)

        self.logger = fissure.utils.get_logger("sensor node " + self.uuid[:8])

        fissure.utils.init_logging()
        self.updateLoggingLevels(
            self.settings_dict['Sensor Node']['console_logging_level'],
            self.settings_dict['Sensor Node']['file_logging_level']
        )

        self.gpsd_serial_port = str(self.settings_dict['Sensor Node']['gps']['gpsd_serial_port'])
        self.meshtastic_serial_port = str(self.settings_dict['Sensor Node']['meshtastic_serial_port'])
        self.meshtastic_serial_baud_rate = str(self.settings_dict['Sensor Node']['meshtastic_serial_baud_rate'])

        self.heartbeats = {
            "self": 0.0,          # last time this node SENT a heartbeat
            fissure.comms.Identifiers.HIPRFISR: 0.0       # last time this node RECEIVED a HIPRFISR heartbeat
        }

        self.heartbeat_interval = int(self.settings_dict['Sensor Node']['heartbeat_interval'])
        self.heartbeat_interval_connected = int(self.settings_dict['Sensor Node']['heartbeat_interval_connected'])
        self.sensor_node_heartbeat_time = 0
        self.attack_flow_graph_loaded = False
        self.archive_flow_graph_loaded = False
        self.physical_fuzzing_stop_event = False
        self.attack_script_name = ""
        self.inspection_script_name = ""
        self.triggers_running = False
        self.alert_senders = {}

        self.tsi_detector_socket = None
        self.running_TSI = False
        self.running_TSI_simulator = False
        self.blacklist = []
        self.running_TSI_wideband = False
        self.configuration_update = False
        self.detector_script_name = ""

        self.running_PD = False
        self.pd_bits_socket = None

        self.autorun_playlist_thread = None
        if self.settings_dict['Sensor Node']['autorun'] is True:
            filename = os.path.join(fissure.utils.SENSOR_NODE_DIR, "Autorun_Playlists", "default.yaml")
            with open(filename) as yaml_library_file:
                playlist_dict = yaml.load(yaml_library_file, yaml.FullLoader)
                trigger_dict = playlist_dict['trigger_values']
            self.autorunPlaylistStart('', playlist_dict, trigger_dict)

        # ZMQ DEALER/ROUTER fields
        self.listener = None
        self.connected = False
        self.terminated = False  # TODO: not used?
        self.shutdown = False

        self.register_callbacks(fissure.callbacks.GenericCallbacks)
        self.register_callbacks(fissure.callbacks.SensorNodeCallbacks)
        self.register_callbacks(fissure.callbacks.SensorNodeCallbacksLT)

        self.callbacks['run_plugin_operation'] = self.run_plugin_operation
        self.callbacks['stop_plugin_operation'] = self.stop_plugin_operation
        self.callbacks['stop_all_plugin_operations'] = self.stop_all_plugin_operations
        self.callbacks['plugin_action'] = self.plugin_action

        self.gps_autostart = self.settings_dict['Sensor Node']['gps']['gps_autostart']
        self.gps_tak_beacon = self.settings_dict['Sensor Node']['gps']['gps_tak_beacon']
        self.gps_source = self.settings_dict['Sensor Node']['gps']['gps_source']
        self.gps_update_interval_seconds = self.settings_dict['Sensor Node']['gps']['gps_update_interval_seconds']

        self.meshtastic_lock = asyncio.Lock()

        self.gps_position = self.settings_dict['Sensor Node']['gps']['gps_position']
        self.gps_position['latitude_ddm'], self.gps_position['longitude_ddm'] = \
            fissure.utils.common.decimal_to_ddm(
                self.gps_position['latitude'], self.gps_position['longitude']
            )

        self.operations = {}


    async def initialize_comms(self):
        if self.network_type == "IP":

            # Build HIPRFISR address
            if self.local_remote == "remote":
                network_protocol = "tcp"
            else:
                network_protocol = "ipc"

            self.hiprfisr_address = fissure.comms.Address(
                protocol=network_protocol,
                address=self.ip_address,
                hb_channel=6100,  # TODO: pull from YAML anyway in case default is changed
                msg_channel=6101,
            )

            # Single DEALER exactly like PD/TSI
            self.hiprfisr_socket = fissure.comms.Listener(
                sock_type=zmq.DEALER,
                name=f"{self.identifier}::sensor_node",
            )

            # Unique stable identity
            identity = f"sensor-node-{self.identifier}-{uuid.uuid4()}"
            self.socket_id = identity
            self.hiprfisr_socket.set_identity(identity)

            self.sockets.append(self.hiprfisr_socket)

            # self.hiprfisr_connected = False

        elif self.network_type == "Meshtastic":
            self.hiprfisr_socket = None
            self.pending_meshtastic_params = {
                "serial_port": self.meshtastic_serial_port,
                "name": f"{self.identifier}::sensor_node",
                "context": self
            }


    def register_callbacks(self, ctx: ModuleType):
        """
        Register callbacks from the provided context

        :param ctx: context containing callbacks to register
        :type ctx: ModuleType
        """
        callbacks = [(f, getattr(ctx, f)) for f in dir(ctx) if isfunction(getattr(ctx, f))]
        for cb_name, cb_func in callbacks:
            self.logger.debug(f"registered callback: {cb_name} (from {cb_func.__module__})")
            self.callbacks[cb_name] = cb_func
    

    def load_or_create_uuid(self):
        # If the UUID file exists, reuse it
        if self.local_remote == "local":
            UUID_PATH = os.path.expanduser("~/.fissure/local_sensor_node_uuid.uuid")
        else:
            UUID_PATH = os.path.expanduser("~/.fissure/sensor_node_uuid.uuid")
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


    async def send_alert(self, sensor_node_id: Union[int, str], opid: str, message: str, logger: None = None) -> None:
        """
        Send an alert message.

        This method is meant to be provided as a callback for plugin operations to send alert messages.

        Parameters
        ----------
        sensor_node_id : Union[int, str]
            Sensor node ID
        opid : str
            The operation ID. Unused placeholder for future use.
        message : str
            The alert message.
        logger : None
            Unused placeholder for debugging.
        """
        PARAMETERS = {
            "sensor_node_id": sensor_node_id,
            "alert_text": message
        }
        if self.network_type == "IP":
            msg = {
                fissure.comms.MessageFields.IDENTIFIER: self.identifier,
                fissure.comms.MessageFields.MESSAGE_NAME: "alertReturn",
                fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
            }
        elif self.network_type == "Meshtastic":
            msg = {
                fissure.comms.MessageFields.SOURCE: self.assigned_id,
                fissure.comms.MessageFields.MESSAGE_NAME: "alertReturnLT",
                fissure.comms.MessageFields.PARAMETERS: {
                    "sensor_node_id": sensor_node_id,
                    "alert_text": PARAMETERS["alert_text"][:100]
                }
            }
        await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


    async def send_tak_cot(self, sensor_node_id: Union[int, str], opid: str, uid: str, remarks: str, lat: Union[float, bool] = True, lon: Union[float, bool] = True, alt: Union[float, bool] = True, time: Union[float, bool] = True, type: str="a-f-G-U-H", logger: None = None) -> None:
        """Send a TAK message.

        Parameters
        ----------
        sensor_node_id : Union[int, str]
            Sensor node ID
        opid : str
            Operation ID
        uid : str
            Unique ID for the TAK message.
        remarks : str
            Remarks to include in the TAK message.
        lat : Union[float, bool], optional
            Latitude in decimal degrees, by default True to use current Sensor Node GPS position. False to omit.
        lon : Union[float, bool], optional
            Longitude in decimal degrees, by default True to use current Sensor Node GPS position. False to omit.
        alt : Union[float, bool], optional
            Altitude in meters, by default True to use current Sensor Node GPS position. False to omit.
        time : Union[float, bool], optional
            Timestamp as a Unix epoch float, by default True to use current time. False to omit.
        type : str, optional
            Type of the TAK message, by default "a-f-G-U-H" for assumed friendly ground unit headquarters.
        logger : None, optional
            Unused placeholder for debugging.
        """
        # Prepare inputs
        if lat is True:
            lat = self.gps_position.get('latitude', 0.0)
        if lon is True:
            lon = self.gps_position.get('longitude', 0.0)
        if alt is True:
            alt = self.gps_position.get('altitude', 0.0)
        if time is True:
            time = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%fZ')
        if remarks == "GPS UPDATE":
            msg_name = "takPlotGpsUpdate"
        else:
            msg_name = "takPlot"

        # Prepare values
        if self.network_type == "IP":
            PARAMETERS = {
                "uid": uid,
                "lat": lat,
                "lon": lon,
                "alt": alt,
                "time": time,
                "type": type,
                "remarks": remarks
            }
        elif self.network_type == "Meshtastic":
            if lat is False or lon is False or alt is False:
                self.logger.error("TAK message requires latitude, longitude, and altitude.")
                return
            if time is False:
                time = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%fZ')
            msg_name += "LT"
            PARAMETERS = {
                "msg": [
                    PARAMETERS["uid"],
                    PARAMETERS["lat"],
                    PARAMETERS["lon"],
                    PARAMETERS["alt"],
                    PARAMETERS["time"],
                    PARAMETERS["remarks"][:20] if PARAMETERS["remarks"] else None
                ]
            }

        # Send message
        msg = {
            fissure.comms.MessageFields.IDENTIFIER: self.identifier,
            fissure.comms.MessageFields.MESSAGE_NAME: msg_name,
            fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
        }
        await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


    async def run_plugin_operation(self, component: object, plugin: str, operation: str, parameters: Dict[str, Any], sensor_node_id: Union[int, str] = 0) -> None:
        """
        Runs a plugin operation on the Sensor Node

        Parameters
        ----------
        plugin : str
            The name of the plugin.
        operation : str
            The plugin filename to run relative to the plugin directory.
        parameters : dict
            The operation parameters.
        
        Returns
        -------
        None
        """
        self.logger.info(f"Running plugin operation: {plugin} - {operation} with parameters: {parameters}")

        # Get the plugin path using the plugin name
        plugin_path = os.path.join(PLUGIN_DIR, plugin)
        if not os.path.exists(plugin_path):
            self.logger.error(f"Plugin path does not exist: {plugin_path}")
            return        
        self.logger.info(f"Plugin path resolved: {plugin_path}")
        
        # Get the plugin script path using the plugin name and operation
        plugin_script_path = os.path.join(plugin_path, 'install_files', operation)
        if not os.path.exists(plugin_script_path):
            self.logger.error(f"Plugin script does not exist: {plugin_script_path}")
            return
        self.logger.info(f"Plugin script resolved: {plugin_script_path}")

        # Import and run the main function from the plugin script
        spec = importlib.util.spec_from_file_location("plugin_module", plugin_script_path)
        plugin_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(plugin_module)

        # Get the main operation class
        operation_main = getattr(plugin_module, "OperationMain", None)
        if operation_main is None:
            self.logger.error(f"No OperationMain class found in {plugin_script_path}")
            return
        if not inspect.isclass(operation_main):
            self.logger.error(f"OperationMain is not a class in {plugin_script_path}")
            return

        # Get the resources required by the plugin script
        if not hasattr(operation_main, "get_resources") or not callable(getattr(operation_main, "get_resources")):
            self.logger.error(f"No callable get_resources() found in {plugin_script_path} OperationMain class")
            return
        resources = operation_main.get_resources()
        if not isinstance(resources, dict):
            self.logger.error(f"get_resources() did not return a dictionary: {resources}")
            return
        self.logger.info(f"Plugin operation resources: {resources}")

        # Record user parameters
        user_parameters = parameters.copy()

        # Add the logger and alert callback to the parameters
        parameters["sensor_node_id"] = sensor_node_id
        parameters["alert_callback"] = self.send_alert
        parameters["tak_cot_callback"] = self.send_tak_cot
        parameters["logger"] = self.logger

        # Initialize the operation class instance
        try:
            operation_inst = operation_main(**parameters)
        except Exception as e:
            tb_str = traceback.format_exc()
            self.logger.error(f"Error initializing operation class from {plugin_script_path}: {e}\n{tb_str}")
            return
        self.logger.info(f"Plugin operation initialized: {operation}")

        # Check that the plugin has operation ID attribute
        if not hasattr(operation_inst, "opid"):
            self.logger.error(f"No operation ID (opid) found in {plugin_script_path}")
            return

        # Check that the plugin script class has the running flag
        if not hasattr(operation_inst, "running") or not callable(operation_inst.running):
            self.logger.error(f"No running flag found in {plugin_script_path}")
            return

        # Check that the plugin script class has the stop method
        if not hasattr(operation_inst, "stop") or not callable(operation_inst.stop):
            self.logger.error(f"No callable stop() method found in {plugin_script_path}")
            return

        # Run the plugin script
        if hasattr(operation_inst, "run") and callable(operation_inst.run):
            try:
                # Set up the operation environment
                env_ready = await operation_inst.setup()
                if not env_ready:
                    self.logger.error(f"Plugin operation {operation} setup failed.")
                    return
                self.logger.info(f"Plugin operation environment for {operation} is ready.")

                # Register the operation in the operations dictionary
                operation_id = operation_inst.opid
                self.operations[operation_id] = {
                    "plugin": plugin,
                    "operation": operation,
                    "parameters": parameters,
                    "resources": resources,
                    "status": operation_inst.running,
                    "stop": operation_inst.stop,
                    "teardown": operation_inst.teardown,
                    "start_time": time.time(),
                }

                # Run the plugin operation in the background
                self.logger.info(f"Starting plugin operation {operation_id}")
                asyncio.create_task(operation_inst.run())

                self.logger.info(f"Plugin operation {operation_id} starting...")

                # Check if the operation is running
                while operation_inst.running() is None:
                    await asyncio.sleep(0.1)
                if not operation_inst.running():
                    self.logger.error(f"Plugin operation {operation} did not start successfully.")
                    await operation_inst.stop()
                    await operation_inst.teardown()
                    return
                self.logger.info(f"Plugin operation {operation_id} running.")

                # Send a message to the Dashboard indicating the operation has started
                PARAMETERS = {
                    "sensor_node_id": sensor_node_id,
                    "operation_id": operation_id,
                    "plugin": plugin,
                    "operation": operation,
                    "parameters": user_parameters,
                }
                msg = {
                    fissure.comms.MessageFields.IDENTIFIER: self.identifier,
                    fissure.comms.MessageFields.MESSAGE_NAME: "pluginOperationStarted",
                    fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
                }
                await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)

            except Exception as e:
                tb_str = traceback.format_exc()
                self.logger.error(f"Error running plugin script {plugin_script_path}: {e}\n{tb_str}")
                return
        else:
            self.logger.error(f"No callable run() method found in {plugin_script_path} OperationMain class")
            return


    async def stop_plugin_operation(self, component: object, operation_id: str, sensor_node_id: Union[int, str] = 0) -> None:
        """
        Stops a plugin operation on the Sensor Node.

        Parameters
        ----------
        operation_id : str
            The ID of the operation to stop.
        
        Returns
        -------
        None
        """
        self.logger.info(f"Stopping plugin operation with ID: {operation_id}")
        if operation_id not in self.operations:
            self.logger.error(f"Operation ID {operation_id} not found.")
            return
        
        operation = self.operations[operation_id]
        if "stop" in operation and callable(operation["stop"]):
            try:
                await operation["stop"]()
            except Exception as e:
                tb_str = traceback.format_exc()
                self.logger.error(f"Error stopping plugin operation {operation_id}: {e}\n{tb_str}")
        else:
            self.logger.error(f"No callable stop method for operation {operation_id}.")
        self.logger.info(f"Operation {operation_id} stop requested.")
        while operation["status"]():
            await asyncio.sleep(1)
            self.logger.info(f"Operation {operation_id} is still running.")

        self.logger.info(f"Operation {operation_id} has stopped.")
        if "teardown" in operation and callable(operation["teardown"]):
            try:
                await operation["teardown"]()
            except Exception as e:
                self.logger.error(f"Error tearing down plugin operation {operation_id}: {e}")
        self.logger.info(f"Operation {operation_id} has completed teardown.")

        # Send a message to the Dashboard indicating the operation has stopped
        PARAMETERS = {
            "sensor_node_id": sensor_node_id,
            "operation_id": operation_id,
            "plugin": operation.get("plugin"),
            "operation": operation.get("operation"),
        }
        msg = {
            fissure.comms.MessageFields.IDENTIFIER: self.identifier,
            fissure.comms.MessageFields.MESSAGE_NAME: "pluginOperationStopped",
            fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
        }
        await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


    async def stop_all_plugin_operations(self, component: object, sensor_node_id: Union[int, str] = 0) -> None:
        """
        Stops all running plugin operations on the Sensor Node.

        Parameters
        ----------
        sensor_node_id : Union[int, str], optional
            Sensor node ID, by default 0.
        """
        self.logger.info("Stopping all plugin operations.")
        for operation_id in list(self.operations.keys()):
            await self.stop_plugin_operation(component, operation_id, sensor_node_id)


    async def plugin_action(self, component: object, plugin_name: str, action_name: str, parameters: Dict[str, Any] = {}, sensor_node_id: Union[int, str] = 0) -> None:
        """
        Calls a specific action function within a plugin.

        Parameters
        ----------
        plugin_name : str
            The name of the plugin.
        action_name : str
            The name of the action function to invoke.
        parameters : Dict[str, Any], optional
            The parameters to pass to the action function.
        """
        try:
            self.logger.info(f"Invoking plugin action: {plugin_name} - {action_name} with parameters: {parameters}")

            # Get the plugin path using the plugin name
            plugin_path = os.path.join(PLUGIN_DIR, plugin_name)
            if not os.path.exists(plugin_path):
                self.logger.error(f"Plugin path does not exist: {plugin_path}")
                return        
            self.logger.debug(f"Plugin path resolved: {plugin_path}")

            # Get the plugin script path using the plugin name and action
            plugin_actions_module = os.path.join(plugin_path, 'actions.py')
            if not os.path.exists(plugin_actions_module):
                self.logger.error(f"Plugin actions module does not exist: {plugin_actions_module}")
                return
            self.logger.debug(f"Plugin actions module resolved: {plugin_actions_module}")

            # Import and run the action function from the plugin script
            spec = importlib.util.spec_from_file_location("plugin_module", plugin_actions_module)
            if spec is None:
                self.logger.error(f"Could not load spec for plugin actions module: {plugin_actions_module}")
                return
            plugin_module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(plugin_module)

            # Get the action function
            action_func = getattr(plugin_module, action_name, None)
            if action_func is None or not callable(action_func):
                self.logger.error(f"No callable {action_name} found in {plugin_actions_module}")
                return

            # Invoke the action function
            try:
                if inspect.iscoroutinefunction(action_func):
                    await action_func(self, parameters, sensor_node_id)
                else:
                    action_func(self, parameters, sensor_node_id)
            except Exception as e:
                tb_str = traceback.format_exc()
                self.logger.error(f"Error invoking plugin action {action_name} from {plugin_actions_module}: {e}\n{tb_str}")
                return
        except Exception as e:
            tb_str = traceback.format_exc()
            self.logger.error(f"Error in plugin_action for {plugin_name} - {action_name}: {e}\n{tb_str}")
            return


    async def shutdown_comms(self):
        """
        """
        if self.tsi_detector_socket:
            try:
                self.stopTSI_Detector(-1)
                await asyncio.sleep(2)
            except:
                pass

        if self.pd_bits_socket:
            try:
                self.stopPD(-1)
                await asyncio.sleep(2)
            except:
                pass

        if self.hiprfisr_socket:
            if self.network_type == "IP":
                try:
                    self.hiprfisr_socket.terminated = True
                    self.hiprfisr_socket.shutdown()
                    # self.hiprfisr_socket.close_sockets()
                except:
                    pass
            elif self.network_type == "Meshtastic":
                await self.hiprfisr_socket.disconnect()


    async def heartbeat_loop(self):
        """
        Sends periodic sensor-node heartbeats and checks if HIPRFISR is alive.
        """
        while not self.shutdown:
            await asyncio.sleep(0.25)

            # 1. SEND node heartbeat (only if connected)
            if self.network_type == "IP":  # and self.hiprfisr_connected:
                try:
                    await self.send_heartbeat()
                except Exception:
                    pass
                    # self.hiprfisr_connected = False
            
            elif self.network_type == "Meshtastic":
                try:
                    await self.send_heartbeat()
                except Exception:
                    pass

            # 2. RECEIVE heartbeat from HIPRFISR
            try:
                await self.recv_heartbeat()
            except Exception:
                pass
                # self.hiprfisr_connected = False

            # # 3. CHECK timeout
            # try:
            #     await self.check_heartbeats()
            # except Exception:
            #     self.hiprfisr_connected = False


    async def recv_heartbeat(self):
        """
        Receive Heartbeat Messages
        """
        heartbeat = await self.hiprfisr_socket.recv_heartbeat()

        if heartbeat is not None:
            heartbeat_time = float(heartbeat.get(fissure.comms.MessageFields.TIME))
            self.heartbeats[fissure.comms.Identifiers.HIPRFISR] = heartbeat_time
            self.logger.debug(f"received HiprFisr heartbeat ({fissure.utils.get_timestamp(heartbeat_time)})")


    async def begin(self):
        """
        """
        self.logger.info("=== STARTING SENSOR NODE ===")

        # Connect to HIPRFISR (HB + MSG channels)
        if self.network_type == "IP":
            ok = await self.hiprfisr_socket.connect(self.hiprfisr_address)

            if ok:
                self.logger.info(
                    f"Connected to HIPRFISR @ {self.hiprfisr_address}"
                )
                await asyncio.sleep(0.1)  # For ZMQ handshake to complete
            else:
                self.logger.error("FAILED connecting to HIPRFISR")
                return
        elif self.network_type == "Meshtastic":
            try:
                serial_port = self.pending_meshtastic_params["serial_port"]
                self.hiprfisr_socket = fissure.comms.FissureMeshtasticNode(
                    serial_port,
                    self.pending_meshtastic_params["name"],
                    self.pending_meshtastic_params["context"],
                )
                self.logger.info(
                    f"Connected to Meshtastic serial port: {serial_port}"
                )
            except Exception as e:
                self.logger.error(
                    f"Failed to initialize Meshtastic on {serial_port}: {e}"
                )
                return
        else:
            self.logger.error("Unknown network type. Enter IP or Meshtastic in node YAML config file.")
            return
        
        # Start Heartbeat Loop
        heartbeat_task = asyncio.create_task(self.heartbeat_loop())
        self.child_tasks.append(heartbeat_task)

        # -----------------------------------------------------
        # Main loop
        # -----------------------------------------------------
        try:
            while not self.shutdown:
                await asyncio.sleep(DELAY)

                if self.network_type == "IP":
                    await self.read_hiprfisr_messages()

                    if self.tsi_detector_socket:
                        await self.read_detector_messages()

                    if self.pd_bits_socket:
                        await self.read_pd_bits_messages()

        except asyncio.CancelledError:
            raise

        finally:
            # Stop Heartbeat Task
            heartbeat_task.cancel()
            try:
                await heartbeat_task
            except asyncio.CancelledError:
                pass

            # Cleanup
            for sender in self.alert_senders.values():
                try:
                    sender.stop()
                except:
                    pass

            self.alert_senders.clear()
    
            # Close Running Tasks
            for task in self.child_tasks:
                task.cancel()
            await asyncio.gather(*self.child_tasks, return_exceptions=True)

            # Shut Down Comms
            await self.shutdown_comms()


    async def read_hiprfisr_messages(self):
        """
        Read messages from the ZMQ message channel.
        """

        # If already terminated, do not enter the loop at all.
        if getattr(self.hiprfisr_socket, "terminated", False):
            return

        while True:
            # Allow graceful exit when shutdown has been requested.
            if self.shutdown or getattr(self.hiprfisr_socket, "terminated", False):
                return

            try:
                parsed = await self.hiprfisr_socket.recv_msg()
            except Exception:
                # Socket error: mark terminated and exit the loop.
                self.hiprfisr_socket.terminated = True
                # self.hiprfisr_connected = False
                return

            if parsed is None:
                # tiny sleep prevents a busy-loop at 100% CPU
                await asyncio.sleep(0.01)
                continue

            # If we reach here, we actually received a real message.
            # self.hiprfisr_connected = True

            msg_type = parsed.get(fissure.comms.MessageFields.TYPE)

            if msg_type == fissure.comms.MessageTypes.COMMANDS:
                try:
                    await self.hiprfisr_socket.run_callback(self, parsed)
                except Exception:
                    pass

            elif msg_type == fissure.comms.MessageTypes.STATUS:
                # you may add future handling, but nothing now
                pass

            else:
                # unknown message type — ignore
                pass


    async def send_heartbeat(self):
        """
        Sends a heartbeat to HIPRFISR (ROUTER) using the router identity.
        """
        if self.network_type != "IP" and self.network_type != "Meshtastic":
            return

        now = time.time()
        last = self.heartbeats["self"]

        # throttle
        if (now - last) < self.heartbeat_interval:
            return

        # Build the message
        nickname = self.settings_dict.get("Sensor Node", {}).get("nickname", "-")
        if self.network_type == "IP":
            hb = {
                fissure.comms.MessageFields.IDENTIFIER: self.identifier,
                fissure.comms.MessageFields.MESSAGE_NAME: fissure.comms.MessageFields.HEARTBEAT,
                fissure.comms.MessageFields.TIME: now,
                fissure.comms.MessageFields.IP: self.ip_address,
                fissure.comms.MessageFields.INTERVAL: self.heartbeat_interval,  # TODO: Get other components to send their interval? Update MessageTypes

                fissure.comms.MessageFields.PARAMETERS: {
                    "network_type": self.network_type,
                    "nickname": nickname,
                    # "uuid": self.uuid,           # stable node uuid (the KEY in HIPRFISR)
                    # "socket_id": self.socket_id  # Gets detected by the ZMQ ROUTER/Receiver
                    # "settings": {} #self.settings_dict["Sensor Node"], On recall settings
                }
            }
            await self.hiprfisr_socket.send_heartbeat(hb)

        elif self.network_type == "Meshtastic":
            PARAMETERS = {
                "msg": [
                    self.assigned_id,
                    self.heartbeat_interval,
                    nickname,
                    now,
                ]
            }
            heartbeat_message = {
                fissure.comms.MessageFields.SOURCE: self.uuid,  # Nodes always send the UUID and not the assigned ID/identifier
                fissure.comms.MessageFields.DESTINATION: fissure.comms.Identifiers.HIPRFISR_LT,  # TODO: obtain HIPRFISR ID some other way
                fissure.comms.MessageFields.MESSAGE_NAME: "recvMeshtasticHeartbeatsLT",
                fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
            }
            await self.hiprfisr_socket.send_heartbeat(heartbeat_message)

        self.heartbeats["self"] = now
        self.logger.debug(f"Sent heartbeat at {now}")


    # async def check_heartbeats(self):
    #     """
    #     Watchdog for HIPRFISR connectivity.
    #     """
    #     now = time.time()
    #     last = self.heartbeats[fissure.comms.Identifiers.HIPRFISR]

    #     hb_timeout = self.heartbeat_interval * 3

    #     if (now - last) > hb_timeout:
    #         # self.logger.warning(
    #         #     f"No heartbeat from HIPRFISR for {now - last:.1f}s – marking disconnected"
    #         # )
    #         # self.hiprfisr_connected = False
    #         print("SET TO FALSE!")


    def updateLoggingLevels(self, new_console_level="", new_file_level=""):
        """ Update the logging levels on the Sensor Node.
        """
        # Update New Levels for PD
        for n in range(0,len(self.logger.parent.handlers)):
            if self.logger.parent.handlers[n].name == "console":
                if new_console_level == "DEBUG":
                    self.logger.parent.handlers[n].level = 10
                elif new_console_level == "INFO":
                    self.logger.parent.handlers[n].level = 20
                elif new_console_level == "WARNING":
                    self.logger.parent.handlers[n].level = 30
                elif new_console_level == "ERROR":
                    self.logger.parent.handlers[n].level = 40
            elif self.logger.parent.handlers[n].name == "file":
                if new_file_level == "DEBUG":
                    self.logger.parent.handlers[n].level = 10
                elif new_file_level == "INFO":
                    self.logger.parent.handlers[n].level = 20
                elif new_file_level == "WARNING":
                    self.logger.parent.handlers[n].level = 30
                elif new_file_level == "ERROR":
                    self.logger.parent.handlers[n].level = 40


    #######################  Generic Functions  ########################

    # def updateFISSURE_Configuration(self):
        # """ Reload fissure_config.yaml after changes.
        # """
        # # Update Sensor Node Dictionary
        # #self.settings_dictionary = self.loadConfiguration()


    def replaceUsername(self, filepath, new_username):
        """ Swaps out the username for a filepath in the home directory with a new username.
        """
        # Ignore ~/ Filepaths and Non-Home Directories
        if filepath.replace('"','').replace("'",'').strip().startswith('/home') == False:
            return filepath
            
        else:
            # Get the User's Home Directory
            home_directory = os.path.expanduser("~")

            # Extract the Original Username
            original_username = filepath.split(os.path.sep)[2]

            # Replace the Original Username
            new_filepath = filepath.replace(original_username, new_username, 1)

            return new_filepath
    

    async def flowGraphError(self, sensor_node_id=0, error=""):
        """ Sends a message back to the HIPRFISR that there was an error with a flow graph.
        """
        # Send Message
        PARAMETERS = {"sensor_node_id": sensor_node_id, "error": error}
        msg = {
                    fissure.comms.MessageFields.IDENTIFIER: self.identifier,
                    fissure.comms.MessageFields.MESSAGE_NAME: "flowGraphError",
                    fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
        }
        await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


    async def flowGraphFinished(self, sensor_node_id, flow_graph_type, read_filepath="", return_filepath=""):
        """ Signals to all components that the flow graph has finished.
        """
        # Send Message
        if flow_graph_type == "PD":
            PARAMETERS = {"sensor_node_id": sensor_node_id, "category": "PD"}
            msg = {
                        fissure.comms.MessageFields.IDENTIFIER: self.identifier,
                        fissure.comms.MessageFields.MESSAGE_NAME: "flowGraphFinished",
                        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
            }
            await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)
        elif flow_graph_type == "Attack":
            PARAMETERS = {"sensor_node_id": sensor_node_id, "category": "Attack"}
            msg = {
                        fissure.comms.MessageFields.IDENTIFIER: self.identifier,
                        fissure.comms.MessageFields.MESSAGE_NAME: "flowGraphFinished",
                        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
            }
            await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)
        elif flow_graph_type == "IQ":
            # Remote Sensor Node
            if self.local_remote == "remote":

                # If a Valid File
                if read_filepath != "":
                    # Read the File
                    with open(read_filepath, "rb") as f:
                        get_data = f.read()
                    get_data = binascii.hexlify(get_data)
                    get_data = get_data.decode("utf-8").upper()
                else:
                    get_data = ""
                
                # Transfer IQ Data Back to HIPRFISR/Dashboard
                PARAMETERS = {"sensor_node_id": sensor_node_id, "operation": "IQ", "filepath": return_filepath, "data": get_data}
                msg = {
                            fissure.comms.MessageFields.IDENTIFIER: self.identifier,
                            fissure.comms.MessageFields.MESSAGE_NAME: "saveFile",
                            fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
                }
                await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)  # Replace with data socket connection
            
            # Local Sensor Node
            else:
                PARAMETERS = {"sensor_node_id": sensor_node_id}
                msg = {
                            fissure.comms.MessageFields.IDENTIFIER: self.identifier,
                            fissure.comms.MessageFields.MESSAGE_NAME: "flowGraphFinishedIQ",
                            fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
                }
                await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)
        elif flow_graph_type == "IQ Playback":
            PARAMETERS = {"sensor_node_id": sensor_node_id}
            msg = {
                        fissure.comms.MessageFields.IDENTIFIER: self.identifier,
                        fissure.comms.MessageFields.MESSAGE_NAME: "flowGraphFinishedIQ_Playback",
                        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
            }
            await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)
        elif flow_graph_type == "Inspection":
            PARAMETERS = {"sensor_node_id": sensor_node_id}
            msg = {
                        fissure.comms.MessageFields.IDENTIFIER: self.identifier,
                        fissure.comms.MessageFields.MESSAGE_NAME: "flowGraphFinishedIQ_Inspection",
                        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
            }
            await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)
        elif flow_graph_type == "Sniffer - Stream":
            PARAMETERS = {"sensor_node_id": sensor_node_id, "category": "Stream"}
            msg = {
                        fissure.comms.MessageFields.IDENTIFIER: self.identifier,
                        fissure.comms.MessageFields.MESSAGE_NAME: "flowGraphFinishedSniffer",
                        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
            }
            await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)
        elif flow_graph_type == "Sniffer - Tagged Stream":
            PARAMETERS = {"sensor_node_id": sensor_node_id, "category": "Tagged Stream"}
            msg = {
                        fissure.comms.MessageFields.IDENTIFIER: self.identifier,
                        fissure.comms.MessageFields.MESSAGE_NAME: "flowGraphFinishedSniffer",
                        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
            }
            await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)
        elif flow_graph_type == "Sniffer - Message/PDU":
            PARAMETERS = {"sensor_node_id": sensor_node_id, "category": "Message/PDU"}
            msg = {
                        fissure.comms.MessageFields.IDENTIFIER: self.identifier,
                        fissure.comms.MessageFields.MESSAGE_NAME: "flowGraphFinishedSniffer",
                        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
            }
            await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


    async def flowGraphStarted(self, sensor_node_id, flow_graph_type):
        """ Signals to all components that the flow graph has started.
        """
        # Send Message
        if flow_graph_type == "PD":
            PARAMETERS = {"sensor_node_id": sensor_node_id, "category": "PD"}
            msg = {
                        fissure.comms.MessageFields.IDENTIFIER: self.identifier,
                        fissure.comms.MessageFields.MESSAGE_NAME: "flowGraphStarted",
                        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
            }
            await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)
        elif flow_graph_type == "Attack":
            PARAMETERS = {"sensor_node_id": sensor_node_id, "category": "Attack"}
            msg = {
                        fissure.comms.MessageFields.IDENTIFIER: self.identifier,
                        fissure.comms.MessageFields.MESSAGE_NAME: "flowGraphStarted",
                        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
            }
            await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)
        elif flow_graph_type == "IQ":
            PARAMETERS = {"sensor_node_id": sensor_node_id}
            msg = {
                        fissure.comms.MessageFields.IDENTIFIER: self.identifier,
                        fissure.comms.MessageFields.MESSAGE_NAME: "flowGraphStartedIQ",
                        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
            }
            await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)
        elif flow_graph_type == "IQ Playback":
            PARAMETERS = {"sensor_node_id": sensor_node_id}
            msg = {
                        fissure.comms.MessageFields.IDENTIFIER: self.identifier,
                        fissure.comms.MessageFields.MESSAGE_NAME: "flowGraphStartedIQ_Playback",
                        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
            }
            await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)
        elif flow_graph_type == "Inspection":
            PARAMETERS = {"sensor_node_id": sensor_node_id}
            msg = {
                        fissure.comms.MessageFields.IDENTIFIER: self.identifier,
                        fissure.comms.MessageFields.MESSAGE_NAME: "flowGraphStartedIQ_Inspection",
                        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
            }
            await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)
        elif flow_graph_type == "Sniffer - Stream":
            PARAMETERS = {"sensor_node_id": sensor_node_id, "category": "Stream"}
            msg = {
                        fissure.comms.MessageFields.IDENTIFIER: self.identifier,
                        fissure.comms.MessageFields.MESSAGE_NAME: "flowGraphStartedSniffer",
                        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
            }
            await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)
        elif flow_graph_type == "Sniffer - Tagged Stream":
            PARAMETERS = {"sensor_node_id": sensor_node_id, "category": "Tagged Stream"}
            msg = {
                        fissure.comms.MessageFields.IDENTIFIER: self.identifier,
                        fissure.comms.MessageFields.MESSAGE_NAME: "flowGraphStartedSniffer",
                        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
            }
            await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)
        elif flow_graph_type == "Sniffer - Message/PDU":
            PARAMETERS = {"sensor_node_id": sensor_node_id, "category": "Message/PDU"}
            msg = {
                        fissure.comms.MessageFields.IDENTIFIER: self.identifier,
                        fissure.comms.MessageFields.MESSAGE_NAME: "flowGraphStartedSniffer",
                        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
            }
            await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


    def runPythonScriptThread(self, stop_event, sensor_node_id, file_type, flow_graph_filename, variable_names, variable_values, run_with_sudo, autorun_index, trigger_action):
        """ Runs the attack flow graph in the new thread.
        """
        # Return Different Status Messages for Autorun
        if autorun_index == -1:
            # Stop Any Running Attack Flow Graphs
            try:
                self.attackFlowGraphStop(sensor_node_id, None)
            except:
                pass

            try:
                # Replace Username in Filepaths
                if self.local_remote == "remote":
                    # In Variables
                    for n in range(0,len(variable_names)):
                        if 'filepath' in variable_names[n]:
                            variable_values[n] = self.replaceUsername(variable_values[n], os.getenv('USER'))

                    # In Filepath
                    flow_graph_filename = self.replaceUsername(flow_graph_filename, os.getenv('USER'))
                
                # Check for Quotes and Backticks
                for n in range(0,len(variable_values)):
                    variable_values[n] = variable_values[n].replace('`','\\`')
                    variable_values[n] = variable_values[n].replace('"','\\"')

                # Start it
                arguments = ""
                for n in variable_values:
                    arguments = arguments + '"' + n + '" '

                # Python3
                if file_type == "Python3 Script":
                    if run_with_sudo == True:
                        osCommandString = "sudo python3 " + '"' + flow_graph_filename + '" ' + arguments
                    else:
                        osCommandString = "python3 " + '"' + flow_graph_filename + '" ' + arguments

                # Python2
                else:
                    if run_with_sudo == True:
                        osCommandString = "sudo python2 " + '"' + flow_graph_filename + '" ' + arguments
                    else:
                        osCommandString = "python2 " + '"' + flow_graph_filename + '" ' + arguments

                # Signal Start
                asyncio.run(self.flowGraphStarted(sensor_node_id, "Attack"))  # Signals to other components
                self.attack_script_name = flow_graph_filename

                # In New Terminal
                if trigger_action == False:
                    self.alert_senders[autorun_index] = alertSender(osCommandString, self.identifier, sensor_node_id, self.hiprfisr_socket, self.gps_position, self.logger, self.network_type)
                    self.alert_senders[autorun_index].thread.join()

                    # In FISSURE Dashboard
                    #proc = subprocess.Popen(osCommandString + " &", shell=True)#, stderr=subprocess.PIPE)
                    #output, error = proc.communicate()
                    
                    # Restore the Start Button for Scripts
                    if self.network_type == "IP":
                        asyncio.run(self.flowGraphFinished(sensor_node_id, "Attack"))
                        asyncio.run(self.multiStageAttackFinished(sensor_node_id))

                # As a Blocking Trigger
                else:               
                    result = subprocess.run(osCommandString, shell=True, capture_output=True, text=True)
                    if result.returncode == 0:
                        self.trigger_done.set()                

            # Error Loading Flow Graph
            except Exception as e:
                asyncio.run(self.flowGraphStarted(sensor_node_id, "Attack"))
                asyncio.run(self.flowGraphFinished(sensor_node_id, "Attack"))
                asyncio.run(self.flowGraphError(sensor_node_id, str(e)))
                asyncio.run(self.multiStageAttackFinished(sensor_node_id))              
                #~ #raise e
                
        # Autorun
        else:
            # Replace Username in Filepaths
            if self.local_remote == "remote":
                for n in range(0,len(variable_names)):
                    # In Variables
                    if 'filepath' in variable_names[n]:
                        variable_values[n] = self.replaceUsername(variable_values[n], os.getenv('USER'))

                    # In Filepath
                    flow_graph_filename = self.replaceUsername(flow_graph_filename, os.getenv('USER'))

            # Check for Quotes and Backticks
            for n in range(0,len(variable_values)):
                variable_values[n] = variable_values[n].replace('`','\\`')
                variable_values[n] = variable_values[n].replace('"','\\"')

            # Start it
            arguments = ""
            for n in variable_values:
                arguments = arguments + '"' + n + '" '

            # Python3
            if file_type == "Python3 Script":
                if run_with_sudo == True:
                    osCommandString = "sudo python3 " + '"' + flow_graph_filename + '" ' + arguments
                else:
                    osCommandString = "python3 " + '"' + flow_graph_filename + '" ' + arguments

            # Python2
            else:
                if run_with_sudo == True:
                    osCommandString = "sudo python2 " + '"' + flow_graph_filename + '" ' + arguments
                else:
                    osCommandString = "python2 " + '"' + flow_graph_filename + '" ' + arguments

            # In New Terminal
            if trigger_action == False:
                #proc = subprocess.Popen('gnome-terminal -- ' + osCommandString + " &", shell=True)
                self.alert_senders[autorun_index] = alertSender(osCommandString, self.identifier, sensor_node_id, self.hiprfisr_socket, self.gps_position, self.logger, self.network_type)
                self.alert_senders[autorun_index].thread.join()

                # In FISSURE Dashboard
                #proc = subprocess.Popen(osCommandString + " &", shell=True)#, stderr=subprocess.PIPE)
                #output, error = proc.communicate()
                
                # Restore the Start Button for Scripts
                if self.network_type == "IP":
                    asyncio.run(self.flowGraphFinished(sensor_node_id, "Attack"))
                    asyncio.run(self.multiStageAttackFinished(sensor_node_id))

            # As a Blocking Trigger
            else:               
                result = subprocess.run(osCommandString, shell=True, capture_output=True, text=True)
                if result.returncode == 0:
                    self.trigger_done.set()

            self.attack_script_name = flow_graph_filename
            
            # Ignore for Autorun on Start Triggers
            if autorun_index > -1:
                self.autorun_playlist_manager[autorun_index] = flow_graph_filename
                self.autorun_multistage_watcher[autorun_index] = True


    def overwriteFlowGraphVariables(self, flow_graph_filename, variable_names, variable_values):
        # print("Variable Names:", variable_names)
        # print("Variable Values:", variable_values)

        # Check if we need to handle string variables
        fix_strings = False
        fix_strings_index = None

        for n in range(len(variable_names)):
            if variable_names[n] == "string_variables":
                fix_strings = True
                fix_strings_index = n
                break

        # Load New Flow Graph
        flow_graph_filename = flow_graph_filename.rsplit("/", 1)[-1]
        flow_graph_filename = flow_graph_filename.replace(".py", "")
        loadedmod = __import__(flow_graph_filename)

        # Get source code
        stistr = inspect.getsource(loadedmod)
        # print("Original Flow Graph Code:\n", stistr)

        variable_line_position = 0
        new_stistr = ""

        # Process each line in the source
        for line in iter(stistr.splitlines()):
            # print("Processing Line:", line)

            # Change Variable Values
            if variable_line_position == 2:
                if line.strip() == "":  # End of the variable declaration section
                    variable_line_position = 3
                else:
                    # Extract the second value between the two '=' signs
                    split_line = line.split("=", 2)
                    if len(split_line) < 3:
                        # print(f"Skipping line (not a variable assignment): {line}")
                        new_stistr += line + "\n"
                        continue

                    # Preserve indentation before the variable assignment
                    indentation = line[:len(line) - len(line.lstrip())]  # Extract leading spaces
                    variable_name = split_line[1].strip()

                    # Ignore the 'notes' variable
                    if variable_name.replace(" ", "") == "notes":
                        new_stistr += line + "\n"
                        continue  # Skip this line without modifying

                    # Ensure we only process variables that exist in variable_names
                    if variable_name in variable_names:
                        index = variable_names.index(variable_name)
                        new_value = variable_values[index]

                        # Handle empty values explicitly
                        if new_value.strip() == "":
                            new_value = '""'  # Ensure empty values are properly assigned

                        # Handle numbers vs. strings
                        elif fissure.utils.isFloat(new_value):
                            if fix_strings and variable_name in variable_values[fix_strings_index]:
                                new_value = f'"{new_value}"'  # Convert numbers to strings if necessary
                        elif not new_value.startswith('"') and not new_value.startswith("'"):
                            new_value = f'"{new_value}"'  # Ensure strings are properly quoted

                        # Debug print to track replacements
                        # print(f"Updating {variable_name}: {split_line[-1].strip()} -> {new_value}")

                        # Construct new line with updated value, preserving indentation
                        new_line = f"{indentation}{split_line[0].strip()} = {variable_name} = {new_value}\n"
                        new_stistr += new_line
                        continue  # Skip adding the original line

            # Write Unreplaced Contents
            new_stistr += line + "\n"

            # Identify start of variable section
            if "# Variables" in line:
                variable_line_position = 1

            # Move past the header separator
            if variable_line_position == 1:
                variable_line_position = 2

            # Identify class name
            if "class " in line and "(gr." in line:
                class_name = line.split(" ")[1].split("(")[0]

        # Compile and execute modified code
        # print("\nCompiled Modified Flow Graph:\n", new_stistr)
        sticode = compile(new_stistr, '<string>', 'exec')
        loadedmod = types.ModuleType('modified_flow_graph')
        exec(sticode, loadedmod.__dict__)

        # print("Flow Graph Successfully Updated")
        return loadedmod, class_name


    def setVariable(self, flow_graph="", variable="", value=""):
        """ Sets a variable of a specified running flow graph.
        """
        # Make it Match GNU Radio Format
        formatted_name = "set_" + variable
        isNumber = fissure.utils.isFloat(value)
        if isNumber:
            if flow_graph == "Protocol Discovery":
                getattr(self.pdflowtoexec,formatted_name)(float(value))
            elif flow_graph == "Attack":
                getattr(self.attackflowtoexec,formatted_name)(float(value))
            elif flow_graph == "Sniffer":
                getattr(self.snifferflowtoexec,formatted_name)(float(value))
            elif flow_graph == "Wideband":
                getattr(self.wideband_flowtoexec,formatted_name)(float(value))
        else:
            if flow_graph == "Protocol Discovery":
                getattr(self.pdflowtoexec,formatted_name)(value)
            elif flow_graph == "Attack":
                getattr(self.attackflowtoexec,formatted_name)(value)
            elif flow_graph == "Sniffer":
                getattr(self.snifferflowtoexec,formatted_name)(value)
            elif flow_graph == "Wideband":
                getattr(self.wideband_flowtoexec,formatted_name)(value)


    ######################  Attack Flow Graphs  ########################

    def attackFlowGraphStart(self, sensor_node_id=0, flow_graph_filepath="", variable_names=[], variable_values=[], file_type="", run_with_sudo=False, autorun_index=0):
        """ Runs the flow graph with the specified file path.
        """
        # Make a new Thread
        stop_event = threading.Event()
        if file_type == "Flow Graph":
            c_thread = threading.Thread(target=self.runFlowGraphThread, args=(stop_event, sensor_node_id, flow_graph_filepath, variable_names, variable_values, autorun_index))
        elif file_type == "Flow Graph - GUI":
            c_thread = threading.Thread(target=self.runFlowGraphGUI_Thread, args=(stop_event, sensor_node_id, flow_graph_filepath, variable_names, variable_values, autorun_index))
        # Python2, Python3
        else:
            c_thread = threading.Thread(target=self.runPythonScriptThread, args=(stop_event, sensor_node_id, file_type, flow_graph_filepath, variable_names, variable_values, run_with_sudo, autorun_index, False))  # backticks execute commands

        c_thread.daemon = True
        c_thread.start()
    

    def attackFlowGraphStop(self, sensor_node_id=0, parameter="", autorun_index=0):
        """ Stop the currently running attack flow graph.
        """
        # Stop Triggers
        if self.triggers_running == True:
            self.triggers_running = False
            self.trigger_done.set()
        
        # Stop Alert Sender Gracefully if Present
        if parameter == "Python Script":
            # Stop Alert Sender
            sender = self.alert_senders.pop(autorun_index, None)
            if sender:
                try:
                    sender.stop()
                    sender.thread.join(timeout=3)
                except Exception as e:
                    self.logger.warning(f"Failed to stop alert sender: {e}")
            
            # Normal
            if autorun_index == -1:
                os.system("sudo pkill -f " + '"' + self.attack_script_name +'"')
                self.attack_flow_graph_loaded = False
            # Autorun
            else:
                process_name = self.autorun_playlist_manager[autorun_index] if 0 <= autorun_index < len(self.autorun_playlist_manager) else None
                if process_name is None:
                    self.logger.debug(f"⚠️ Warning: No process found for autorun index {autorun_index}. Skipping kill command.")
                else:
                    os.system("sudo pkill -f " + '"' + process_name + '"')

                # os.system("sudo pkill -f " + '"' + self.autorun_playlist_manager[autorun_index] +'"')
                self.autorun_playlist_manager[autorun_index] = None
                
        elif parameter == "Flow Graph - GUI":
            # Normal
            if autorun_index == -1:
                os.system("sudo pkill -f " + '"' + self.attack_script_name +'"')
                self.attack_flow_graph_loaded = False
            # Autorun
            else:
                process_name = self.autorun_playlist_manager[autorun_index] if 0 <= autorun_index < len(self.autorun_playlist_manager) else None
                if process_name is None:
                    self.logger.debug(f"⚠️ Warning: No process found for autorun index {autorun_index}. Skipping kill command.")
                else:
                    os.system("sudo pkill -f " + '"' + process_name + '"')

                # os.system("sudo pkill -f " + '"' + self.autorun_playlist_manager[autorun_index] +'"')
                self.autorun_playlist_manager[autorun_index] = None
            
        else:
            # Normal
            if autorun_index == -1:
                if self.attack_flow_graph_loaded == True:
                    self.attackflowtoexec.stop()
                    self.attackflowtoexec.wait()

                    # Stop Fuzzer Thread or Future Blocks with Infinite Threads
                    if hasattr(self.attackflowtoexec,'fuzzer_fuzzer_0_0'):
                        self.attackflowtoexec.fuzzer_fuzzer_0_0.stop_event.set()

                    del self.attackflowtoexec  # Free up the ports
                    self.attack_flow_graph_loaded = False
            
            # Autorun
            else:
                self.autorun_playlist_manager[autorun_index].stop()
                self.autorun_playlist_manager[autorun_index].wait()
                self.autorun_playlist_manager[autorun_index] = None
                self.autorun_multistage_watcher[autorun_index] = False


    def runFlowGraphThread(self, stop_event, sensor_node_id, flow_graph_filename, variable_names, variable_values, autorun_index):
        """ Runs the attack script in the new thread.
        """
        # Return Different Status Messages for Autorun
        if autorun_index == -1:
            try:
                # Stop Any Running Attack Flow Graphs
                try:
                    self.attackFlowGraphStop(sensor_node_id, None)
                except:
                    pass
                    
                # Replace Username in Filepaths
                if self.local_remote == "remote":
                    for n in range(0,len(variable_names)):
                        if 'filepath' in variable_names[n]:
                            variable_values[n] = self.replaceUsername(variable_values[n], os.getenv('USER'))
                
                # Overwrite Variables
                loadedmod, class_name = self.overwriteFlowGraphVariables(flow_graph_filename, variable_names, variable_values)

                # Call the "__init__" Function
                self.attackflowtoexec = getattr(loadedmod,class_name)()
                
                # Start it
                self.attackflowtoexec.start()  # How do you tell if this fails?
                asyncio.run(self.flowGraphStarted(sensor_node_id, "Attack"))  # Signals to other components
                    
                # Physical Layer Fuzzing Can Now Commence
                self.attack_flow_graph_loaded = True
                
                # Let it Run
                self.attackflowtoexec.wait()
                
                # Signal on the PUB that the Attack Flow Graph is Finished
                asyncio.run(self.flowGraphFinished(sensor_node_id, "Attack"))
                        
            # Error Loading Flow Graph
            except Exception as e:
                asyncio.run(self.flowGraphStarted(sensor_node_id, "Attack"))
                asyncio.run(self.flowGraphFinished(sensor_node_id, "Attack"))
                asyncio.run(self.flowGraphError(sensor_node_id, str(e)))
                asyncio.run(self.multiStageAttackFinished(sensor_node_id))
                #~ #raise e
                
        # Autorun
        else:
            # Replace Username in Filepaths
            if self.local_remote == "remote":
                for n in range(0,len(variable_names)):
                    if 'filepath' in variable_names[n]:
                        variable_values[n] = self.replaceUsername(variable_values[n], os.getenv('USER'))

            # Overwrite Variables
            loadedmod, class_name = self.overwriteFlowGraphVariables(flow_graph_filename, variable_names, variable_values)

            # Call the "__init__" Function
            self.autorun_playlist_manager[autorun_index] = getattr(loadedmod,class_name)()
            
            # Start it
            self.autorun_playlist_manager[autorun_index].start()
            self.autorun_multistage_watcher[autorun_index] = True
            
            # Let it Run
            self.autorun_playlist_manager[autorun_index].wait()


    def runFlowGraphGUI_Thread(self, stop_event, sensor_node_id, flow_graph_filename, variable_names, variable_values, autorun_index):
        """ Runs the attack flow graph in the new thread.
        """
        # Normal
        if autorun_index == -1:
        
            # # Stop Any Running Attack Flow Graphs
            # try:
                # self.attackFlowGraphStop(sensor_node_id, None)
            # except:
                # pass

            try:
                # Replace Username in Filepaths
                if self.local_remote == "remote":
                    for n in range(0,len(variable_names)):
                        if 'filepath' in variable_names[n]:
                            variable_values[n] = self.replaceUsername(variable_values[n], os.getenv('USER'))

                # Start it
                filepath = flow_graph_filename
                flow_graph_filename = flow_graph_filename.rsplit("/",1)[1]
                arguments = ""
                for n in range(0,len(variable_names)):
                    arguments = arguments + '--' + variable_names[n] + '="' + variable_values[n] + '" '

                osCommandString = "python3 " + '"' + filepath + '" ' + arguments
                proc = subprocess.Popen(osCommandString + " &", shell=True)
                asyncio.run(self.flowGraphStarted(sensor_node_id, "Attack"))  # Signals to other components
                self.attack_script_name = flow_graph_filename
                time.sleep(4.8)  # Need a way to detect flow graph/hardware is running when called via Python
                self.attack_flow_graph_loaded = True

            # Error Loading Flow Graph
            except Exception as e:
                asyncio.run(self.flowGraphStarted(sensor_node_id, "Attack"))
                asyncio.run(self.flowGraphFinished(sensor_node_id, "Attack"))
                asyncio.run(self.flowGraphError(sensor_node_id, str(e)))
                asyncio.run(self.multiStageAttackFinished(sensor_node_id))
                #~ #raise e
        
        # Autorun
        else:
            try:
                # Replace Username in Filepaths
                if self.local_remote == "remote":
                    for n in range(0,len(variable_names)):
                        if 'filepath' in variable_names[n]:
                            variable_values[n] = self.replaceUsername(variable_values[n], os.getenv('USER'))

                # Start it
                filepath = flow_graph_filename
                flow_graph_filename = flow_graph_filename.rsplit("/",1)[1]
                arguments = ""
                for n in range(0,len(variable_names)):
                    arguments = arguments + '--' + variable_names[n] + '="' + variable_values[n] + '" '

                osCommandString = "python3 " + '"' + filepath + '" ' + arguments
                proc = subprocess.Popen(osCommandString + " &", shell=True)
                self.autorun_playlist_manager[autorun_index] = flow_graph_filename
                time.sleep(4.8)  # Need a way to detect flow graph/hardware is running when called via Python
                self.autorun_multistage_watcher[autorun_index] = True

            # Error Loading Flow Graph
            except Exception as e:
                self.logger.error("Error running flow graph with GUI")
            

    ##############  IQ Recording, IQ Playback Flow Graphs  #############
    
    def iqFlowGraphThread(self, sensor_node_id, flow_graph_filename, variable_names, variable_values, read_filepath, return_filepath):
        """ Runs the IQ script in the new thread.
        """
        # Stop Any Running IQ Flow Graphs
        try:
            self.iqFlowGraphStop(None)
        except:
            pass

        try:
            # Overwrite Variables
            loadedmod, class_name = self.overwriteFlowGraphVariables(flow_graph_filename, variable_names, variable_values)

            # Call the "__init__" Function
            self.iqflowtoexec = getattr(loadedmod,class_name)()

            # Start it
            self.iqflowtoexec.start()
            if "iq_recorder" in flow_graph_filename:
                asyncio.run(self.flowGraphStarted(sensor_node_id, "IQ"))
            elif "iq_playback" in flow_graph_filename:
                asyncio.run(self.flowGraphStarted(sensor_node_id, "IQ Playback"))

            # Let it Run
            self.iqflowtoexec.wait()

            # Signal on the PUB that the IQ Flow Graph is Finished
            if "iq_recorder" in flow_graph_filename:
                asyncio.run(self.flowGraphFinished(sensor_node_id, "IQ", read_filepath, return_filepath))
                self.iqFlowGraphStop(None)
            elif "iq_playback" in flow_graph_filename:
                asyncio.run(self.flowGraphFinished(sensor_node_id, "IQ Playback"))

        # Error Loading Flow Graph
        except Exception as e:
            if "iq_recorder" in flow_graph_filename:
                asyncio.run(self.flowGraphStarted(sensor_node_id, "IQ"))
                asyncio.run(self.flowGraphFinished(sensor_node_id, "IQ"))
                self.iqFlowGraphStop(None)
            elif "iq_playback" in flow_graph_filename:
                asyncio.run(self.flowGraphStarted(sensor_node_id, "IQ Playback"))
                asyncio.run(self.flowGraphFinished(sensor_node_id, "IQ Playback"))
                self.iqFlowGraphStop(None)


    def iqFlowGraphStop(self, parameter=""):
        """ Stop the currently running IQ flow graph.
        """
        self.iqflowtoexec.stop()
        self.iqflowtoexec.wait()
        del self.iqflowtoexec  # Free up the ports


    ####################  Inspection Flow Graphs  ######################

    def inspectionFlowGraphGUI_Thread(self, sensor_node_id, flow_graph_filename, variable_names, variable_values):
        """ Runs the inspection flow graph in the new thread.
        """
        try:
            # Start it
            filepath = self.replaceUsername(flow_graph_filename, os.getenv('USER'))
            flow_graph_filename = flow_graph_filename.rsplit("/",1)[1]
            arguments = ""
            for n in range(0,len(variable_names)):
                arguments = arguments + '--' + variable_names[n] + '="' + variable_values[n] + '" '

            osCommandString = "python3 " + '"' + filepath + '" ' + arguments
            proc = subprocess.Popen(osCommandString + " &", shell=True)

            asyncio.run(self.flowGraphStarted(sensor_node_id, "Inspection"))  # Signals to other components
            self.inspection_script_name = flow_graph_filename

        # Error Loading Flow Graph
        except Exception as e:
            asyncio.run(self.flowGraphStarted(sensor_node_id, "Inspection"))
            asyncio.run(self.flowGraphFinished(sensor_node_id, "Inspection"))
            asyncio.run(self.flowGraphError(sensor_node_id, str(e)))


    #######################  Protocol Discovery  #######################

    def stopPD(self, sensor_node_id=0):
        """
        Stops PD processing of bits by closing the ZMQ SUB socket.
        """
        # Stop Operations
        self.logger.info("PD: Stopping Protocol Discovery...")
        self.running_PD = False
        
        # if self.running_TSI_simulator:
        #     self.running_TSI_simulator = False
        # elif len(self.detector_script_name) > 0:
        #     self.detectorFlowGraphStop(sensor_node_id, "Flow Graph - GUI")
        # else:
        #     try:
        #         # Stop Flow Graphs
        #         self.wideband_flowtoexec.stop()
        #         self.wideband_flowtoexec.wait()
        #         del self.wideband_flowtoexec  # Free up the ports
        #     except:
        #         pass

        # Close Temporary SUB Socket
        if self.pd_bits_socket != None:
            self.pd_bits_socket.close()
            self.pd_bits_context.term()
            self.pd_bits_socket = None
            self.pd_bits_context = None


    async def read_pd_bits_messages(self):
        """
        Reads messages on the PD bits ZMQ SUB and forwards them to the HIRPFISR/Dashboard
        """
        poller = zmq.Poller()
        poller.register(self.pd_bits_socket, zmq.POLLIN)

        socks = dict(poller.poll(timeout=0))  # Set timeout to 0 for non-blocking poll

        if self.pd_bits_socket in socks and socks[self.pd_bits_socket] == zmq.POLLIN:
            while True:
                try:
                    # Receive a message
                    bits_message = self.pd_bits_socket.recv_string(flags=zmq.NOBLOCK)
                    
                    # Send the Message
                    PARAMETERS = {"bits_message": bits_message}
                    msg = {
                                fissure.comms.MessageFields.IDENTIFIER: self.identifier,
                                fissure.comms.MessageFields.MESSAGE_NAME: "pdBitsReturn",
                                fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
                    }
                    await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)

                except zmq.Again:
                    # No more messages are available
                    break


    def protocolDiscoveryFG_ThreadStart(self, sensor_node_id, flow_graph_filename, variable_names, variable_values):
        """ 
        Runs the flow graph in the new thread.
        """
        # # Stop Any Running PD Flow Graphs
        # try:
        #     self.stopFlowGraph(None)
        # except:
        #     pass

        try:
            # Replace Username in Filepaths
            if self.local_remote == "remote":
                for n in range(0,len(variable_names)):
                    if 'filepath' in variable_names[n]:
                        variable_values[n] = self.replaceUsername(variable_values[n], os.getenv('USER'))

            # Overwrite Variables
            loadedmod, class_name = self.overwriteFlowGraphVariables(flow_graph_filename, variable_names, variable_values)

            # Call the "__init__" Function
            self.pdflowtoexec = getattr(loadedmod,class_name)()

            # Start it
            self.pdflowtoexec.start()
            asyncio.run(self.flowGraphStarted(sensor_node_id, "PD"))  # Signals to other components
            self.pdflowtoexec.wait()

            # Signal on the PUB that the PD Flow Graph is Finished
            asyncio.run(self.flowGraphFinished(sensor_node_id, "PD"))

        # Error Loading Flow Graph
        except Exception as e:
            asyncio.run(self.flowGraphStarted(sensor_node_id, "PD"))
            asyncio.run(self.flowGraphFinished(sensor_node_id, "PD"))
            asyncio.run(self.flowGraphError(sensor_node_id, str(e)))


    ######################  Sniffer Flow Graphs  #######################

    def snifferFlowGraphThread(self, sensor_node_id, flow_graph_filename, variable_names, variable_values):
        """ Runs the flow graph in the new thread.
        """
        try:
            # Overwrite Variables
            loadedmod, class_name = self.overwriteFlowGraphVariables(flow_graph_filename, variable_names, variable_values)

            # Call the "__init__" Function
            self.snifferflowtoexec = getattr(loadedmod,class_name)()

            # Start it
            self.snifferflowtoexec.start()
            if "Sniffer_stream" in flow_graph_filename:
                asyncio.run(self.flowGraphStarted(sensor_node_id, "Sniffer - Stream"))
            elif "Sniffer_tagged_stream" in flow_graph_filename:
                asyncio.run(self.flowGraphStarted(sensor_node_id, "Sniffer - Tagged Stream"))
            elif "Sniffer_async" in flow_graph_filename:
                asyncio.run(self.flowGraphStarted(sensor_node_id, "Sniffer - Message/PDU"))
            self.snifferflowtoexec.wait()

        # Error Loading Flow Graph
        except Exception as e:
            if "Sniffer_stream.py" in flow_graph_filename:
                asyncio.run(self.flowGraphStarted(sensor_node_id, "Sniffer - Stream"))
                asyncio.run(self.flowGraphFinished(sensor_node_id, "Sniffer - Stream"))
            elif "Sniffer_tagged_stream.py" in flow_graph_filename:
                asyncio.run(self.flowGraphStarted(sensor_node_id, "Sniffer - Tagged Stream"))
                asyncio.run(self.flowGraphFinished(sensor_node_id, "Sniffer - Tagged Stream"))
            elif "Sniffer_async.py" in flow_graph_filename:
                asyncio.run(self.flowGraphStarted(sensor_node_id, "Sniffer - Message/PDU"))
                asyncio.run(self.flowGraphFinished(sensor_node_id, "Sniffer - Message/PDU"))

            asyncio.run(self.flowGraphError(sensor_node_id, str(e)))


    ############################  Triggers  ############################

    def triggerRunScript(self, result_dict, index, script_filepath, variable_names, variable_values, python_type):
        """ Runs an individual trigger and wait for a return code.
        """
        try:
            # Replace Username in Filepaths
            if self.local_remote == "remote":
                for n in range(0,len(variable_names)):
                    if 'filepath' in variable_names[n]:
                        variable_values[n] = self.replaceUsername(variable_values[n], os.getenv('USER'))
            
            # Check for Quotes and Backticks
            for n in range(0,len(variable_values)):
                variable_values[n] = variable_values[n].replace('`','\\`')
                variable_values[n] = variable_values[n].replace('"','\\"')

            # Start it
            arguments = ""
            for n in variable_values:
                arguments = arguments + '"' + n + '" '        
            osCommandString = python_type + ' "' + script_filepath + '" ' + arguments
            process = subprocess.Popen(osCommandString, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, preexec_fn=os.setsid)
            
            # Listen for Return Code 0
            while not self.trigger_done.is_set():
                if process.poll() is not None:
                    result_dict[index] = process.returncode
                    if process.returncode == 0:
                        self.trigger_done.set()
                    break
                time.sleep(0.1)
            
            # Termination Event is Set, Kill the Process
            if self.trigger_done.is_set() and process.poll() is None:
                os.killpg(os.getpgid(process.pid), signal.SIGTERM)
                #process.terminate()
                #process.kill()
                #process.wait()
                result_dict[index] = -1
        except Exception as e:
            self.logger.error(f"Error running trigger script {script_filepath}: {e}")


    def triggerStart(self, trigger_values, fissure_event, event_values, autorun_index):
        """ Starts trigger threads before continuing with other actions.
        """
        # Run the Triggers
        self.logger.info("Starting Triggers...")
        threads = []
        result_dict = {}
        self.triggers_running = True
        self.trigger_done = threading.Event()
        for n in range(0,len(trigger_values)):
            trigger_file = os.path.join(fissure.utils.get_fg_library_dir(self.os_info), "Triggers", trigger_values[n][0])
            trigger_type = trigger_values[n][1]
            trigger_variables = eval(trigger_values[n][2])
            trigger_variable_values = eval(trigger_values[n][3])
            
            # From FISSURE Library
            if trigger_type == "Flow Graph":
                #c_thread = threading.Thread(target=self.runFlowGraphThread, args=(self.trigger_done, event_values[0], event_values[1], event_values[2], event_values[3], event_values[4]))
                pass  # Do everything through Python for now, make sure "run to completion is set"
            elif trigger_type == "Flow Graph - GUI":
                pass
            elif trigger_type == "Python2 Script":
                thread = threading.Thread(target=self.triggerRunScript, args=(result_dict, n, trigger_file, trigger_variables, trigger_variable_values, 'python2'))
                threads.append(thread)
                thread.start()
            elif trigger_type == "Python3 Script":
                thread = threading.Thread(target=self.triggerRunScript, args=(result_dict, n, trigger_file, trigger_variables, trigger_variable_values, 'python3'))
                threads.append(thread)
                thread.start()
            else:
                self.logger.error("Error!")

        # Signal Start, Restore Start/Stop Buttons
        if fissure_event == "Single-Stage Attack":
            asyncio.run(self.flowGraphStarted(event_values[0], "Attack"))
        # elif fissure_event == "Multi-Stage Attack":
            # asyncio.run(self.flowGraphStarted(sensor_node_id, "Attack"))
        # elif fissure_event == "Archive Replay":
            # asyncio.run(self.flowGraphStarted(sensor_node_id, "Archive"))
        # elif fissure_event == "Autorun Playlist":
            # asyncio.run(self.flowGraphStarted(sensor_node_id, "Attack"))

        # Monitor Trigger Threads for Termination
        print_timer = 0
        while not self.trigger_done.is_set():
            # Print to Terminal/Log
            if print_timer >= 5:
                self.logger.info("Waiting on triggers...")
                print_timer = 0
            else:
                print_timer = print_timer + 0.1
                
            # Wait for a Thread to End
            if not any(thread.is_alive() for thread in threads):
                break                
            time.sleep(0.1)
        
        # If Termination Event is Set, Attempt to Join all Threads
        if self.trigger_done.is_set():
            for thread in threads:
                if thread.is_alive():
                    thread.join()
        
        # Check the Return Codes
        for i, returncode in result_dict.items():
            if returncode == 0:
                self.logger.info(f"Trigger {i} completed successfully with return code 0.")
            else:
                self.logger.info(f"Trigger {i} ended with return code {returncode}.")

        #Cancelled
        if self.triggers_running == False:
            self.logger.info("Triggers Ended")

            # Restore the Start Button for Scripts
            if fissure_event == "Single-Stage Attack":
                asyncio.run(self.flowGraphFinished(event_values[0], "Attack"))
            elif fissure_event == "Multi-Stage Attack":
                asyncio.run(self.multiStageAttackFinished(event_values[0]))
            elif fissure_event == "Archive Replay":
                asyncio.run(self.archivePlaylistFinished(event_values[0]))
            elif fissure_event == "Autorun Playlist":
                pass

        # Trigger Done
        elif self.trigger_done.is_set():
            self.logger.info("Triggers Complete.")
    
            # Run the Event
            if fissure_event == "Single-Stage Attack":
                self.logger.info("Starting Single-Stage Attack...")
                self.attackFlowGraphStart(event_values[0], event_values[1], event_values[2], event_values[3], event_values[4], event_values[5], event_values[6])
           
            elif fissure_event == "Multi-Stage Attack":
                self.logger.info("Starting Multi-Stage Attack...")
                self.multiStageAttackStart(event_values[0], event_values[1], event_values[2], event_values[3], event_values[4], event_values[5], event_values[6], event_values[7])
                #self.multiStageAttackStart(sensor_node_id, filenames, variable_names, variable_values, durations, repeat, file_types, autorun_index)

            elif fissure_event == "Archive Replay":
                self.logger.info("Starting Archive Replay...")
                
                # Make a New Thread
                self.archive_playlist_stop_event = threading.Event()
                archive_playlist_thread = threading.Thread(target=self.archivePlaylistThreadStart, args=(event_values[0], event_values[1], event_values[2], event_values[3], event_values[4], event_values[5], event_values[6], event_values[7], event_values[8], event_values[9], event_values[10], event_values[11]))
                archive_playlist_thread.start()

            elif fissure_event == "Autorun Playlist":
                self.logger.info("Starting Autorun Playlist...")
                sensor_node_id = event_values[0]
                playlist_dict = event_values[1]
                
                # Run at Startup
                if sensor_node_id == '':
                    # Read the Autorun Playlist File
                    filename = os.path.join(fissure.utils.SENSOR_NODE_DIR, "Autorun_Playlists", "default.yaml")
                    with open(filename) as yaml_library_file:
                        playlist_dict = yaml.load(yaml_library_file, yaml.FullLoader)
                
                # Passed in from Dashboard
                else:
                    # Send the Message
                    asyncio.run(self.autorunPlaylistStarted(sensor_node_id))
                
                # Make a New Thread
                self.autorun_playlist_stop_event = threading.Event()
                self.autorun_playlist_thread = threading.Thread(target=self.autorunPlaylistThreadStart, args=[sensor_node_id, playlist_dict])
                self.autorun_playlist_thread.start()
                

    async def autorunPlaylistStarted(self, sensor_node_id):
        """ Sends the Autorun Playlist Started message to the HIPRFISR/Dashboard.
        """
        # Send the Message
        if self.network_type == "IP":
            PARAMETERS = {"sensor_node_id": sensor_node_id}
            msg = {
                        fissure.comms.MessageFields.IDENTIFIER: self.identifier,
                        fissure.comms.MessageFields.MESSAGE_NAME: "autorunPlaylistStarted",
                        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
            }
            await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)
    

    #######################  Physical Fuzzing  #########################


    def physicalFuzzingThreadStart(self, sensor_node_id, fuzzing_variables, fuzzing_type, fuzzing_min, fuzzing_max, fuzzing_update_period, fuzzing_seed_step):
        """ Updates flow graph variables for a running flow graph at a specified rate.
        """
        # Wait for Flow Graph to Load
        while True:
            if self.attack_flow_graph_loaded == True:
                break
            time.sleep(0.1)

        # Get the Update Period
        try:
            update_period = float(fuzzing_update_period)
        except:
            update_period = 1

        # Initialize Values
        for n in range(0,len(fuzzing_variables)):
            variable = str(fuzzing_variables[n])

            if fuzzing_type[n] == "Sequential":
                # Check if it is a Float
                if fissure.utils.isFloat((fuzzing_min[n])):
                    generic_value = float(fuzzing_min[n])
                # What Happens for a String?
                else:
                    generic_value = str(fuzzing_min[n])
            elif fuzzing_type[n] == "Random":
                # Check if it is a Float
                if fissure.utils.isFloat((fuzzing_min[n])):
                    generic_rg = random.Random(float(fuzzing_seed_step[n]))
                    generic_value = generic_rg.randrange(float(fuzzing_min[n]),float(fuzzing_max[n]),1)
                # What Happens for a String?
                else:
                    generic_value = str(fuzzing_min[n])

        # Reset Stop Event
        self.physical_fuzzing_stop_event = False

        # Set Variable Loop
        while(not self.physical_fuzzing_stop_event):

            # Update Each Checked Variable
            for n in range(0,len(fuzzing_variables)):

                variable = str(fuzzing_variables[n])

                # Call the Set Function of the Flow Graph
                self.setVariable("Attack",variable, generic_value)
                self.logger.info("Set " + variable + " to: {}" .format(generic_value))

                # Generate New Value
                if fuzzing_type[n] == "Sequential":
                    # Float
                    if fissure.utils.isFloat(fuzzing_min[n]):
                        # Increment
                        generic_value = generic_value + float(fuzzing_seed_step[n])

                        # Max is Reached
                        if generic_value > float(fuzzing_max[n]):
                            generic_value = float(fuzzing_min[n])

                    # What Happens for a String?
                    else:
                        generic_value = str(fuzzing_min[n])

                elif fuzzing_type[n] == "Random":
                    if fissure.utils.isFloat(fuzzing_min[n]):
                        # New Random Number
                        generic_value = generic_rg.randrange(float(fuzzing_min[n]),float(fuzzing_max[n]),1)
                    # What Happens for a String?
                    else:
                        generic_value = str(fuzzing_min[n])

            # Sleep at "Update Interval"
            time.sleep(update_period)

        # Reset Stop Event
        self.physical_fuzzing_stop_event = False


    #######################  Multi-Stage Attack  #######################
    
    def multiStageAttackStart(self, sensor_node_id=0, filenames=[], variable_names=[], variable_values=[], durations=[], repeat=False, file_types=[], autorun_index=0):
        """ Starts a new thread for running two flow graphs. A new thread is created to allow the Sensor Node to still perform normal functionality while waiting for an attack to finish.
        """
        # Make a New Thread
        if autorun_index == -1:
            self.multi_stage_stop_event = threading.Event()
        else:
            self.autorun_multistage_manager[autorun_index] = threading.Event()
        multi_stage_thread = threading.Thread(target=self.multiStageAttackThreadStart, args=(sensor_node_id, filenames, variable_names, variable_values, durations, repeat, file_types, autorun_index))

        multi_stage_thread.start()
    

    def multiStageAttackThreadStart(self, sensor_node_id, filenames, variable_names, variable_values, durations, repeat, file_types, autorun_index):
        """ Starts consecutive flow graphs with each running for a set duration with a fixed pause in between.
        """
        # Normal
        if autorun_index == -1:
            while(not self.multi_stage_stop_event.is_set()):
                for n in range(0,len(filenames)):

                    # Make a new Thread
                    stop_event = threading.Event()
                    if file_types[n] == "Flow Graph":
                        flow_graph_filename = filenames[n].replace(".py","")
                        c_thread = threading.Thread(target=self.runFlowGraphThread, args=(stop_event,sensor_node_id,flow_graph_filename,variable_names[n],variable_values[n], autorun_index))
                    elif file_types[n] == "Flow Graph - GUI":
                        flow_graph_filename = filenames[n]                        
                        c_thread = threading.Thread(target=self.runFlowGraphGUI_Thread, args=(stop_event,sensor_node_id,flow_graph_filename,variable_names[n],variable_values[n], autorun_index))
                    # Python2, Python3
                    else:
                        run_with_sudo = True
                        for m in range(0,len(variable_names[n])):
                            if variable_names[n][m] == "run_with_sudo":
                                if str(variable_values[n][m]).lower() == "true":
                                    run_with_sudo = True
                                else:
                                    run_with_sudo = False
                                break
                        c_thread = threading.Thread(target=self.runPythonScriptThread, args=(stop_event,sensor_node_id,file_types[n],filenames[n],variable_names[n],variable_values[n],run_with_sudo,autorun_index,False))

                    c_thread.daemon = True
                    c_thread.start()

                    # Wait for the Flow Graph to Start
                    if (file_types[n] == "Flow Graph") or (file_types[n] == "Flow Graph - GUI"):
                        while self.attack_flow_graph_loaded == False:
                            time.sleep(0.05)

                    # Start the Timer
                    start_time = time.time()                    
                    while time.time() - start_time < float(durations[n]):
                        # Check if Stop was Pressed while Running Flow Graph
                        if self.multi_stage_stop_event.is_set():
                            break
                        time.sleep(.05)

                    # Stop the Flow Graph
                    if file_types[n] == "Flow Graph":
                        self.attackFlowGraphStop(sensor_node_id, "Flow Graph", autorun_index)
                        time.sleep(0.5)  # LimeSDR needs time to stop or there will be a busy error
                    elif file_types[n] == "Flow Graph - GUI":
                        self.attackFlowGraphStop(sensor_node_id, "Flow Graph - GUI", autorun_index)
                        time.sleep(0.5)  # LimeSDR needs time to stop or there will be a busy error
                    else:
                        self.attackFlowGraphStop(sensor_node_id, "Python Script", autorun_index)

                    # Break if Stop was Pressed while Running Flow Graph
                    if self.multi_stage_stop_event.is_set():
                        break

                # End the thread
                if repeat == False:
                    self.multiStageAttackStop(sensor_node_id, autorun_index)
        
        # Autorun
        else:            
            while(not self.autorun_multistage_manager[autorun_index].is_set()):
                for n in range(0,len(filenames)):

                    # Make a new Thread
                    stop_event = threading.Event()
                    if file_types[n] == "Flow Graph":
                        flow_graph_filename = filenames[n].replace(".py","")
                        c_thread = threading.Thread(target=self.runFlowGraphThread, args=(stop_event,sensor_node_id,flow_graph_filename,variable_names[n],variable_values[n], autorun_index))
                    elif file_types[n] == "Flow Graph - GUI":
                        flow_graph_filename = filenames[n]
                        c_thread = threading.Thread(target=self.runFlowGraphGUI_Thread, args=(stop_event,sensor_node_id,flow_graph_filename,variable_names[n],variable_values[n], autorun_index))
                    # Python2, Python3
                    else:
                        run_with_sudo = True
                        for m in range(0,len(variable_names[n])):
                            if variable_names[n][m] == "run_with_sudo":
                                if str(variable_values[n][m]).lower() == "true":
                                    run_with_sudo = True
                                else:
                                    run_with_sudo = False
                                break
                        c_thread = threading.Thread(target=self.runPythonScriptThread, args=(stop_event,sensor_node_id,file_types[n],filenames[n],variable_names[n],variable_values[n],run_with_sudo,autorun_index,False))

                    c_thread.daemon = True
                    c_thread.start()

                    # Wait for the Flow Graph to Start
                    if (file_types[n] == "Flow Graph") or (file_types[n] == "Flow Graph - GUI"):
                        while self.autorun_multistage_watcher[autorun_index] == False:
                            time.sleep(0.05)

                    # Start the Timer
                    start_time = time.time()                    
                    while time.time() - start_time < float(durations[n]):
                        if self.autorun_multistage_manager[autorun_index].is_set():
                            break
                        time.sleep(.05)

                    # Stop the Flow Graph
                    if file_types[n] == "Flow Graph":
                        self.attackFlowGraphStop(sensor_node_id, "Flow Graph", autorun_index)
                        time.sleep(0.5)  # LimeSDR needs time to stop or there will be a busy error
                    elif file_types[n] == "Flow Graph - GUI":
                        self.attackFlowGraphStop(sensor_node_id, "Flow Graph - GUI", autorun_index)
                        time.sleep(0.5)  # LimeSDR needs time to stop or there will be a busy error
                    else:
                        self.attackFlowGraphStop(sensor_node_id, "Python Script", autorun_index)

                    # Break if Stop was Pressed while Running Flow Graph
                    if self.autorun_multistage_manager[autorun_index].is_set():
                        break

                # End the thread
                if repeat == False:
                    self.multiStageAttackStop(sensor_node_id, autorun_index)


    async def multiStageAttackFinished(self, sensor_node_id):
        """ Signals to the other components that the multi-stage attack has finished.
        """
        # Send the Message
        PARAMETERS = {"sensor_node_id": sensor_node_id}
        msg = {
                    fissure.comms.MessageFields.IDENTIFIER: self.identifier,
                    fissure.comms.MessageFields.MESSAGE_NAME: "multiStageAttackFinished",
                    fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
        }
        await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)
        

    def multiStageAttackStop(self, sensor_node_id=0, autorun_index=0):
        """ Stops a multi-stage attack already in progress
        """
        # Stop Triggers
        if self.triggers_running == True:
            self.triggers_running = False
            self.trigger_done.set()

        # Normal
        if autorun_index == -1:
            try:
                # Signal to the Other Components
                asyncio.run(self.multiStageAttackFinished(sensor_node_id))

                # Stop the Thread
                self.multi_stage_stop_event.set()
                
            except:
                pass
            
        # Autorun
        else:
            # Reset Listener Loop Variable
            self.autorun_multistage_watcher[autorun_index] = False

            # Stop the Thread
            self.autorun_multistage_manager[autorun_index].set()


    #######################  Archive Playlist  #########################

    def archivePlaylistThreadStart(self, sensor_node_id, flow_graph, filenames, frequencies, sample_rates, formats, channels, gains, durations, repeat, ip_address, serial):
        """ Starts consecutive flow graphs with each running for a set duration with a fixed pause in between.
        """
        # LimeSDR Channel Nomenclature
        for m in range(0,len(channels)):
            if channels[m] == "A":
                channels[m] = "0"
            elif channels[m] == "B":
                channels[m] = "1"

        while(not self.archive_playlist_stop_event.is_set()):
            for n in range(0,len(filenames)):
                # Update Archive Replay Playlist Position
                asyncio.run(self.archivePlaylistPosition(sensor_node_id, n))

                # Change Variable Values
                variable_names = ["tx_gain","tx_frequency","tx_channel","sample_rate","filepath","ip_address","serial"]
                variable_values = [gains[n],frequencies[n],channels[n],sample_rates[n],filenames[n],ip_address, serial]
                
                # Adjust Filepath
                if self.local_remote == "remote":
                    variable_values[4] = os.path.join(fissure.utils.SENSOR_NODE_DIR, "Archive_Replay", filenames[n].split('/')[-1])

                # Make a new Thread
                stop_event = threading.Event()
                c_thread = threading.Thread(target=self.archiveFlowGraphThread, args=(stop_event,sensor_node_id,flow_graph,variable_names,variable_values))
                c_thread.daemon = True
                c_thread.start()
                
                # Wait for the Flow Graph to Start
                while self.archive_flow_graph_loaded == False:
                    time.sleep(0.05)

                # Start the Timer
                start_time = time.time()
                while time.time() - start_time < float(durations[n]):
                    # Check if Stop was Pressed while Running Flow Graph
                    if self.archive_playlist_stop_event.is_set():
                        break
                    time.sleep(0.05)

                # Stop the Flow Graph
                self.archiveFlowGraphStop(sensor_node_id)
                time.sleep(0.5)  # LimeSDR needs time to stop or there will be a busy error

                # Break if Stop was Pressed while Running Flow Graph
                if self.archive_playlist_stop_event.is_set():
                    break

            # End the thread
            if repeat == False:
                self.archivePlaylistStop(sensor_node_id)


    def archiveFlowGraphThread(self, stop_event, sensor_node_id, flow_graph_filename, variable_names, variable_values):
        """ Runs the attack script in the new thread.
        """
        # Stop Any Running Attack Flow Graphs
        try:
            self.attackFlowGraphStop(sensor_node_id, None)
        except:
            pass

        try:
            # Overwrite Variables
            loadedmod, class_name = self.overwriteFlowGraphVariables(flow_graph_filename, variable_names, variable_values)

            # Call the "__init__" Function
            self.archiveflowtoexec = getattr(loadedmod,class_name)()

            # Start it
            self.archiveflowtoexec.start()
            # if "archive_replay" in flow_graph_filename:
                # pass
            self.archive_flow_graph_loaded = True

            # Let it Run
            self.archiveflowtoexec.wait()

            # Signal on the PUB that the Attack Flow Graph is Finished
            # if "archive_replay" in flow_graph_filename:
                # pass

        # Error Loading Flow Graph
        except Exception as e:
            if "archive_replay" in flow_graph_filename:
                asyncio.run(self.archivePlaylistFinished(sensor_node_id))
            else:
                #asyncio.run(self.flowGraphStarted("Attack"))
                #asyncio.run(self.flowGraphFinished("Attack"))
                asyncio.run(self.flowGraphError(sensor_node_id, str(e)))
                #self.sensor_node_pub_server.sendmsg('Status', Identifier = 'Sensor Node', MessageName = 'Multi-Stage Attack Finished', Parameters = "")
            #~ #raise e


    async def archivePlaylistPosition(self, sensor_node_id, position):
        """ Sends the archive replay playlist position to the HIPRFISR/Dashboard.
        """
        # Send File Position to Dashboard
        PARAMETERS = {"sensor_node_id": sensor_node_id, "position": position}
        msg = {
                    fissure.comms.MessageFields.IDENTIFIER: self.identifier,
                    fissure.comms.MessageFields.MESSAGE_NAME: "archivePlaylistPosition",
                    fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
        }
        await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


    def archiveFlowGraphStop(self, sensor_node_id):
        """ Stop the currently running archive flow graph.
        """
        self.archiveflowtoexec.stop()
        self.archiveflowtoexec.wait()
        del self.archiveflowtoexec  # Free up the ports
        self.archive_flow_graph_loaded = False


    def archivePlaylistStop(self, sensor_node_id=0):
        """ Stops a multi-stage attack already in progress
        """
        try:
            # Stop Triggers
            if self.triggers_running:
                self.triggers_running = False
                self.trigger_done.set()
            
            # Signal to the Other Components
            asyncio.run(self.archivePlaylistFinished(sensor_node_id))
            
            # Reset Listener Loop Variable
            self.archive_flow_graph_loaded = False

            # Stop the Thread
            self.archive_playlist_stop_event.set()
            
        except Exception as e:
            self.logger.error(f"Error in archivePlaylistStop: {e}")


    async def archivePlaylistFinished(self, sensor_node_id):
        """ Signals to the other components that the multi-stage attack has finished.
        """
        # Send the Message
        PARAMETERS = {"sensor_node_id": sensor_node_id}
        msg = {
                    fissure.comms.MessageFields.IDENTIFIER: self.identifier,
                    fissure.comms.MessageFields.MESSAGE_NAME: "archivePlaylistFinished",
                    fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
        }
        await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)
    
    
    ##########################  TSI Detector  #############################

    def stopTSI_Detector(self, sensor_node_id=0):
        """
        Pauses TSI processing of signals after receiving the command from the HIPRFISR
        """
        # Stop Operations
        self.logger.info("TSI: Stopping TSI Detector...")
        self.running_TSI = False
        self.running_TSI_wideband = False

        if self.running_TSI_simulator:
            self.running_TSI_simulator = False
        elif len(self.detector_script_name) > 0:
            self.detectorFlowGraphStop(sensor_node_id, "Flow Graph - GUI")
        else:
            try:
                # Stop Flow Graphs
                self.wideband_flowtoexec.stop()
                self.wideband_flowtoexec.wait()
                del self.wideband_flowtoexec  # Free up the ports
            except:
                pass

        # Close Temporary SUB Socket
        if self.tsi_detector_socket != None:
            self.tsi_detector_socket.close()
            self.tsi_detector_context.term()
            self.tsi_detector_socket = None
            self.tsi_detector_context = None


    def startWidebandThread(self, sensor_node_id, detector_port):
        """ Begins TSI wideband sweeping
        """
        self.running_TSI_wideband = True

        variable_names = []
        variable_values = []
        class_name = []

        # Make a New Wideband Update Thread
        stop_event2 = threading.Event()
        c_thread2 = threading.Thread(target=self.widebandUpdateThread, args=(stop_event2,sensor_node_id,class_name,variable_names,variable_values, detector_port))
        c_thread2.start()


    def stopWidebandThread(self):
        """ Stops TSI wideband sweeping
        """
        # Make a New Wideband Update Thread
        self.running_TSI_wideband = False


    def runWidebandThread(self, sensor_node_id, flow_graph_filename, variable_names, variable_values):
        """ Runs the flow graph in the new thread.
        """
        # Stop Any Running Wideband Flow Graphs
        try:
            self.wideband_flowtoexec.stop()
            self.wideband_flowtoexec.wait()
            del self.wideband_flowtoexec  # Free up the ports
        except:
            pass

        # Overwrite Variables
        loadedmod, class_name = self.overwriteFlowGraphVariables(flow_graph_filename, variable_names, variable_values)

        # Call the "__init__" Function
        self.wideband_flowtoexec = getattr(loadedmod,class_name)()

        # Start it
        self.wideband_flowtoexec.start()
        self.wideband_flowtoexec.wait()

        # # Error Loading Flow Graph
        # except Exception as e:
            # # print("Error: " + str(e))
            # # self.running_TSI = False
            # # self.running_wideband = False
            # PARAMETERS = {"sensor_node_id": sensor_node_id, error=str(e)}
            # msg = {
                        # fissure.comms.MessageFields.IDENTIFIER: self.identifier,
                        # fissure.comms.MessageFields.MESSAGE_NAME: "Detector Flow Graph Error",
                        # fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
            # }
            # await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


    def runDetectorSimulatorThread(self, variable_names, variable_values, detector_port):
        """ Runs the simulator in the new thread.
        """
        self.logger.info("SIMULATOR THREAD STARTED")
        self.running_TSI_simulator = True

        # Create Temporary ZMQ PUB
        context = zmq.Context()
        pub_socket = context.socket(zmq.PUB)
        pub_socket.bind("tcp://127.0.0.1:" + str(detector_port))
        
        try:
            # Replace Username in Filepaths
            if self.local_remote == "remote":
                for n in range(0,len(variable_names)):
                    if 'filepath' in variable_names[n]:
                        variable_values[n] = self.replaceUsername(variable_values[n], os.getenv('USER'))

            while self.running_TSI_simulator == True:

                # Open CSV Simulator File
                with open(variable_values[0], "r") as f:
                    reader = csv.reader(f, delimiter=",")

                    for i, line in enumerate(reader):
                        # Skip First Row
                        if int(i) > 0:
                            new_message = "TSI:/Signal Found/" + str(int(line[0])) + "/" + str(int(line[1])) + "/" + str(time.time())  # "TSI:/Signal Found/2260000000/-55/1526333364.11"
                            pub_socket.send_string(new_message)
                            time.sleep(float(line[2]))

                        if not self.running_TSI_simulator:
                            break

        finally:
            pub_socket.close()
            context.term()
            self.logger.info("SIMULATOR THREAD TERMINATED")


    def widebandUpdateThread(self, stop_event, sensor_node_id, class_name, variable_names, variable_values, detector_port):
        """ Updates the wideband flow graph parameters in the new thread.
        """
        self.logger.info("WIDEBAND UPDATE THREAD STARTED!!!")
        # Create the Temporary ZMQ SUB
        if self.tsi_detector_socket == None:
            self.tsi_detector_context = zmq.Context()
            self.tsi_detector_socket = self.tsi_detector_context.socket(zmq.SUB)
            self.tsi_detector_socket.connect("tcp://127.0.0.1:" + str(detector_port))
            self.tsi_detector_socket.setsockopt_string(zmq.SUBSCRIBE, "")

        # Wideband Sweep Logic
        new_freq = self.wideband_start_freq[self.wideband_band]
        while self.running_TSI_wideband == True:           
            #try:
            # Check for Configuration Update
            if self.configuration_updated == True:
                new_freq = self.wideband_start_freq[0]
                self.configuration_updated = False

            # Update Flow Graph
            self.setVariable("Wideband","rx_freq",new_freq)

            # Send Frequency and Band Status to Dashboard
            asyncio.run(self.bandID_Return(sensor_node_id, self.wideband_band+1, new_freq))

            # Step Frequency
            new_freq = new_freq + self.wideband_step_size[self.wideband_band]

            # Passed Stop Frequency
            if new_freq > self.wideband_stop_freq[self.wideband_band]:
                # Increase Band
                self.wideband_band = self.wideband_band + 1

                # Reset Band
                if self.wideband_band >= len(self.wideband_start_freq):
                    self.wideband_band = 0

                # Begin at Start Frequency
                new_freq = self.wideband_start_freq[self.wideband_band]

            # Check Blacklist
            not_in_blacklist = False
            while not_in_blacklist == False:
                not_in_blacklist = True
                for n in range(0,len(self.blacklist)):
                    if self.blacklist[n][0] <= new_freq <= self.blacklist[n][1]:
                        not_in_blacklist = False

                        # Step Frequency
                        new_freq = new_freq + self.wideband_step_size[self.wideband_band]

                        # Passed Stop Frequency
                        if new_freq > self.wideband_stop_freq[self.wideband_band]:
                            # Increase Band
                            self.wideband_band = self.wideband_band + 1

                            # Reset Band
                            if self.wideband_band >= len(self.wideband_start_freq):
                                self.wideband_band = 0

                            # Begin at Start Frequency
                            new_freq = self.wideband_start_freq[self.wideband_band]
            #except:
            #    pass

            # Dwell on Frequency
            time.sleep(self.wideband_dwell[self.wideband_band])


    async def bandID_Return(self, sensor_node_id, band_id, frequency):
        """
        Sends a Band ID message with current status during a TSI detector sweep to the HIPRFISR/Dashboard.
        """
        PARAMETERS = {"sensor_node_id": sensor_node_id, "band_id": band_id, "frequency": frequency}
        msg = {
                    fissure.comms.MessageFields.IDENTIFIER: self.identifier,
                    fissure.comms.MessageFields.MESSAGE_NAME: "bandID_Return",
                    fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
        }
        await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


    def detectorFlowGraphStop(self, sensor_node_id, parameter):
        """ Stop the currently running detector flow graph.
        """
        # Only Supports Flow Graphs with GUIs
        if (parameter == "Flow Graph - GUI") and (len(self.detector_script_name) > 0):
            os.system("sudo pkill -f " + '"' + self.detector_script_name +'"')
            self.detector_script_name = ""


    def detectorFlowGraphGUI_Thread(self, sensor_node_id, flow_graph_filename, variable_names, variable_values, detector_port):
        """ Runs the detector flow graph in the new thread.
        """
        try:
            # Start it
            filepath = os.path.join(fissure.utils.get_fg_library_dir(self.os_info), "TSI Flow Graphs", "Detectors", flow_graph_filename)
            arguments = ""
            for n in range(0,len(variable_names)):
                arguments = arguments + '--' + variable_names[n] + '="' + variable_values[n] + '" '

            osCommandString = "python3 " + '"' + filepath + '" ' + arguments
            proc = subprocess.Popen(osCommandString + " &", shell=True)

            #asyncio.run(self.flowGraphStarted("Inspection"))  # Signals to other components
            self.detector_script_name = flow_graph_filename

            # Create the Temporary ZMQ SUB
            if self.tsi_detector_socket == None:
                self.tsi_detector_context = zmq.Context()
                self.tsi_detector_socket = self.tsi_detector_context.socket(zmq.SUB)
                self.tsi_detector_socket.connect("tcp://127.0.0.1:" + str(detector_port))
                self.tsi_detector_socket.setsockopt_string(zmq.SUBSCRIBE, "")

        # Error Loading Flow Graph
        except Exception as e:
            self.logger.error(str(e))
            #print("ERROR")
            #asyncio.run(self.flowGraphStarted("Inspection"))
            #asyncio.run(self.flowGraphFinished("Inspection"))
            asyncio.run(self.flowGraphError(sensor_node_id, str(e)))
            #~ #raise e    
    

    async def read_detector_messages(self):
        """
        Reads messages on the Detector ZMQ SUB and forwards them to the HIRPFISR/Dashboard
        """
        poller = zmq.Poller()
        poller.register(self.tsi_detector_socket, zmq.POLLIN)

        socks = dict(poller.poll(timeout=0))  # Set timeout to 0 for non-blocking poll

        if self.tsi_detector_socket in socks and socks[self.tsi_detector_socket] == zmq.POLLIN:
            while True:
                try:
                    # Receive a message
                    message = self.tsi_detector_socket.recv_string(flags=zmq.NOBLOCK)
                    # message = json.loads(message_json)
                    # print("Received:", message)
                    
                    # Parse the Message
                    split_message = message.split('/')
                    frequency_value = int(float(split_message[2]))  # Python must go str>float>int with decimals
                    power_value = int(float(split_message[3]))
                    time_value = float(split_message[4])

                    # Send the Message
                    PARAMETERS = {"frequency_value": frequency_value, "power_value": power_value, "time_value": time_value}
                    msg = {
                                fissure.comms.MessageFields.IDENTIFIER: self.identifier,
                                fissure.comms.MessageFields.MESSAGE_NAME: "detectorReturn",
                                fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
                    }
                    await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)

                except zmq.Again:
                    # No more messages are available
                    break

    
    #######################  Autorun Playlists  ##########################

    def autorunPlaylistStart(self, sensor_node_id=0, playlist_dict={}, trigger_values=[]):
        """ Starts a new thread for cycling through the autorun playlist.
        """
        # Use the Function that is Called Frequently in SensorNode.py
        if len(trigger_values) == 0:
            self.logger.info("START!")

            # Check if the thread is already running
            if self.autorun_playlist_thread and self.autorun_playlist_thread.is_alive():
                self.logger.info("Autorun Playlist is already running. Ignoring duplicate request.")
                return  # Prevent starting another instance
            
            # Passed in from the Dashboard
            if sensor_node_id != '':
                # Send the Message
                asyncio.run(self.autorunPlaylistStarted(sensor_node_id))
            
            # Make a New Thread
            self.autorun_playlist_stop_event = threading.Event()
            self.autorun_playlist_thread = threading.Thread(target=self.autorunPlaylistThreadStart, args=[sensor_node_id, playlist_dict])
            self.autorun_playlist_thread.start()
        else:            
            # Make a new Trigger Thread
            if self.settings_dict['Sensor Node']['autorun'] == True:
                autorun_index = -2  # Autorun on start with trigger
            else:
                autorun_index = -1  # Autorun through Dashboard with trigger
            unused_stop_event = threading.Event()
            fissure_event_values = [sensor_node_id, playlist_dict]
            c_thread = threading.Thread(target=self.triggerStart, args=(trigger_values, "Autorun Playlist", fissure_event_values, autorun_index))
            c_thread.daemon = True
            c_thread.start()


    def autorunPlaylistExecute(self, sensor_node_id=0, playlist_filename=""):
        """ 
        Starts a new thread for cycling through the autorun playlist.
        """
        # Check if the autorun playlist thread is already running
        if self.autorun_playlist_thread and self.autorun_playlist_thread.is_alive():
            self.logger.info("Autorun Playlist is already running. Ignoring duplicate execute request.")
            return
    
        # Read the Autorun Playlist File
        filename = os.path.join(fissure.utils.SENSOR_NODE_DIR, "Autorun_Playlists", playlist_filename)
        if os.path.isfile(filename):
            with open(filename) as yaml_library_file:
                playlist_dict = yaml.load(yaml_library_file, yaml.FullLoader)
                trigger_dict = playlist_dict['trigger_values']
            self.autorunPlaylistStart(sensor_node_id, playlist_dict, trigger_dict)


    def autorunPlaylistThreadStart(self, sensor_node_id, playlist_dict):
        """ Cycles through autorun playlist items.
        """
        # Delayed Start
        autorun_delay = self.settings_dict['Sensor Node']['autorun_delay_seconds']
        try:
            time.sleep(int(autorun_delay))
        except:
            self.logger.error("Invalid autorun delay")
            return
        
        self.logger.info("Autorun Playlist Thread")
        #print(playlist_dict)
        #playlist_dict = eval(playlist_dict)
        
        # Parse Playlist Items
        get_delay_start = eval(playlist_dict.pop('delay_start'))
        get_delay_start_time = playlist_dict.pop('delay_start_time')
        get_repetition_interval = int(playlist_dict.pop('repetition_interval_seconds'))
        try:
            get_empty_triggers = playlist_dict.pop('trigger_values')
        except:
            pass
            
        # Autorun Playlist Repeat Loop
        while True:
            sorted_playlist_dict = sorted(playlist_dict.items())
            
            # Initialize Timeouts and Repeats
            autorun_playlist_start_times = []
            autorun_playlist_repeat = []
            autorun_playlist_started = []
            autorun_playlist_first_time = []
            self.autorun_playlist_manager = []
            self.autorun_multistage_manager = []
            self.autorun_multistage_watcher = []
            for playlist_index,v in sorted_playlist_dict:
                playlist_index = int(playlist_index)
                autorun_playlist_start_times.append(0)
                autorun_playlist_repeat.append(eval(sorted_playlist_dict[int(playlist_index)][1]['repeat']))
                autorun_playlist_started.append(False)
                autorun_playlist_first_time.append(True)
                self.autorun_playlist_manager.append(None)
                self.autorun_multistage_manager.append(None)
                self.autorun_multistage_watcher.append(False)
            
            # One Playlist Run
            while True:
                
                # Delay Start
                if get_delay_start == False:
                    
                    for playlist_index,v in sorted_playlist_dict:
                        playlist_index = int(playlist_index)
                        attack_dict = sorted_playlist_dict[playlist_index][1]
                        
                        # Individual Delay
                        if attack_dict['delay'] == "True":
                            if time.time() >= parser.parse(attack_dict['start_time']).timestamp():  # FIX THIS
                                attack_dict['delay'] = "False"
                                sorted_playlist_dict[playlist_index][1]['delay'] = "False"
                                
                        # Individual Delay is Off/Over
                        if attack_dict['delay'] == "False":
                    
                            # Single-Stage
                            if attack_dict['type'] == "Single-Stage":
                                self.logger.info("Single-Stage")
                                get_details = eval(attack_dict['details'])
                                get_variable_names = eval(attack_dict['variable_names'])
                                get_variable_values = eval(attack_dict['variable_values'])
                                
                                # Start Attack
                                if (time.time() <= autorun_playlist_start_times[playlist_index] + float(attack_dict['timeout_seconds']) or (autorun_playlist_first_time[playlist_index] == True)) and (self.autorun_playlist_stop_event.is_set() == False):
                                    #print(time.time() <= autorun_playlist_start_times[playlist_index] + float(attack_dict['timeout_seconds']))
                                    #print(autorun_playlist_first_time[playlist_index])
                                    #print(self.autorun_playlist_stop_event.is_set())
                                    
                                    if autorun_playlist_started[playlist_index] == False:
                                        if (autorun_playlist_first_time[playlist_index] == True) or (autorun_playlist_repeat[playlist_index] == True):
                                            self.logger.info("start it")
                                            self.attackFlowGraphStart(sensor_node_id, get_details[4], get_variable_names, get_variable_values, get_details[5], get_details[6], playlist_index)
                                            autorun_playlist_start_times[playlist_index] = time.time() + float(attack_dict['timeout_seconds'])
                                            autorun_playlist_started[playlist_index] = True
                                            autorun_playlist_first_time[playlist_index] = False
                                    
                                # Timeout, Stop Attack
                                else:
                                    if autorun_playlist_started[playlist_index] == True:
                                        self.logger.info("stop it")
                                        get_file_type = get_details[5]
                                        if (get_file_type == "Python2 Script") or (get_file_type == "Python3 Script"):
                                            get_file_type = "Python Script"
                                        self.attackFlowGraphStop(sensor_node_id, get_file_type, playlist_index)
                                        autorun_playlist_started[playlist_index] = False                        
                            
                            # Multi-Stage
                            elif attack_dict['type'] == "Multi-Stage":
                                self.logger.info("Multi-Stage")
                                get_details = eval(attack_dict['details'])
                                get_variable_names = eval(attack_dict['variable_names'])
                                get_variable_values = eval(attack_dict['variable_values'])
                                
                                # Start Attack
                                if (time.time() <= autorun_playlist_start_times[playlist_index] + float(attack_dict['timeout_seconds']) or (autorun_playlist_first_time[playlist_index] == True)) and (self.autorun_playlist_stop_event.is_set() == False):
                                    if autorun_playlist_started[playlist_index] == False:
                                        if (autorun_playlist_first_time[playlist_index] == True) or (autorun_playlist_repeat[playlist_index] == True):
                                            self.logger.info("Start it")
                                            get_file_types = []
                                            get_durations = []
                                            get_filenames = []
                                            for n in range(0,len(get_details)):
                                                get_file_types.append(get_details[n][4])
                                                get_durations.append(get_details[n][5])
                                                get_filenames.append(get_details[n][6])
                                            self.multiStageAttackStart(sensor_node_id, get_filenames, get_variable_names, get_variable_values, get_durations, autorun_playlist_repeat[playlist_index], get_file_types, playlist_index)
                                            autorun_playlist_start_times[playlist_index] = time.time() + float(attack_dict['timeout_seconds'])
                                            autorun_playlist_started[playlist_index] = True
                                            autorun_playlist_first_time[playlist_index] = False
                                    
                                # Timeout, Stop Attack
                                else:
                                    if autorun_playlist_started[playlist_index] == True:
                                        self.logger.info("Stop it")
                                        self.multiStageAttackStop(sensor_node_id, playlist_index)
                                        autorun_playlist_started[playlist_index] = False
                    
                    # Exit When Everything is Stopped
                    if self.autorun_playlist_stop_event.is_set() or not any(autorun_playlist_started):
                        break

                # Delaying Start
                else:
                    # Check Time for Delay Start
                    if time.time() >= parser.parse(get_delay_start_time).timestamp():
                        get_delay_start = False
                        
                    # Exit if Stop is Clicked
                    if self.autorun_playlist_stop_event.is_set():
                        break
                
                self.logger.info("Looping")
                time.sleep(0.2)
            
            # Repeat for Another Loop
            if get_repetition_interval > 0:
                # Exit if Stop is Clicked
                if self.autorun_playlist_stop_event.is_set():
                    break

                # Sleep for Repetition Interval
                self.logger.info("Sleeping until next playlist run.")
                time.sleep(get_repetition_interval)
                self.logger.info("Done sleeping.")   
            else:
                break
    
        # Send the Message
        if sensor_node_id != '':
            if sensor_node_id > 0:
                asyncio.run(self.autorunPlaylistFinished(sensor_node_id))

                
    async def autorunPlaylistFinished(self, sensor_node_id):
        """ Sends the autorun playlist finished message to the HIPRFISR/Dashboard.
        """
        # Send the Message
        if self.network_type == "IP":
            PARAMETERS = {"sensor_node_id": sensor_node_id}
            msg = {
                        fissure.comms.MessageFields.IDENTIFIER: self.identifier,
                        fissure.comms.MessageFields.MESSAGE_NAME: "autorunPlaylistFinished",
                        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
            }
            await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


    async def gpsUpdate(self, gps_data):
        """
        Callback function to save GPS updates from Meshtastic node.
        """
        # Update Values, Keep old values if partially None
        if gps_data:
            for key in ['latitude', 'longitude', 'altitude']:
                value = gps_data.get(key)
                if value is not None:
                    self.gps_position[key] = value
            
            # Store DDM Values
            self.gps_position['latitude_ddm'], self.gps_position['longitude_ddm'] = fissure.utils.common.decimal_to_ddm(self.gps_position['latitude'], self.gps_position['longitude'])
            self.logger.warning(f"Updating GPS position: {self.gps_position}")

        # Failed GPS probe, stale value
        else:
            # TODO: Add a flag for stale
            self.logger.warning(f"Failed to update GPS position. Keeping last position: {self.gps_position}")

        # Beacon GPS Position to HIPFISR then TAK
        if self.gps_tak_beacon == True:
            if self.network_type == "IP":
                PARAMETERS = {
                    "uid": self.identifier,
                    "lat": self.gps_position['latitude'],
                    "lon": self.gps_position['longitude'],
                    "alt": self.gps_position['altitude'],
                    "time": datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%fZ'),
                    "remarks": "GPS UPDATE"
                }
                msg = {
                    fissure.comms.MessageFields.IDENTIFIER: self.identifier,
                    fissure.comms.MessageFields.MESSAGE_NAME: "takPlotGpsUpdate",
                    fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
                }
                await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)

            elif self.network_type == "Meshtastic":
                PARAMETERS = {
                    "msg": [
                        self.uuid,
                        self.gps_position['latitude'],
                        self.gps_position['longitude'],
                        self.gps_position['altitude'],
                        datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%fZ'),
                        'GPS UPDATE'
                    ]
                }
                msg = {
                    fissure.comms.MessageFields.SOURCE: self.assigned_id,
                    fissure.comms.MessageFields.DESTINATION: fissure.comms.Identifiers.HIPRFISR_LT,  # TODO: obtain HIPRFISR ID some other way
                    fissure.comms.MessageFields.MESSAGE_NAME: "takPlotGpsUpdateLT",
                    fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
                }
                await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


    ########################################################################


class GPSManager:
    """
    Manages periodic GPS updates from multiple sources.
    """

    def __init__(
            self, 
            logger: logging.Logger, 
            gps_update_interval_seconds: int, 
            gps_callback: Callable[[Dict[str, float]], None], 
            gpsd_serial_port = str,
            settings=None,
            meshtastic_lock=None
        ):
        """
        Args:
            gps_update_interval_seconds (int): How often to check GPS (in seconds).
            gps_callback (Callable): Function to call when GPS updates.
        """
        self.logger = logger
        self.gps_update_interval_seconds = gps_update_interval_seconds
        self.gps_callback = gps_callback  # Function to store GPS data
        self.gpsd_serial_port = gpsd_serial_port
        self.settings = settings or {}
        self.meshtastic_lock = meshtastic_lock
        self.running = False  # Controls the GPS update loop


    async def fetch_gps_from_meshtastic(self, meshtastic_node) -> Optional[Dict[str, float]]:
        """
        Fetch GPS data from an existing Meshtastic node.
        """
        try:
            gps_data = await meshtastic_node.get_gps_position()
            return gps_data
        except Exception as e:
            self.logger.error(f"Error getting GPS from Meshtastic: {e}")
            return None
    
    
    async def fetch_gps_from_meshtastic_new_connection(self, serial_port) -> Optional[Dict[str, float]]:
        """
        Fetch GPS data from a new temporary Meshtastic serial connection.
        """
        try:
            gps_data = await fissure.utils.hardware.probeMeshtasticGPS(serial_port, 10)
            return gps_data
        except Exception as e:
            self.logger.error(f"Error getting GPS from Meshtastic: {e}")
            return None


    async def fetch_gps_from_gpsd(self):
        """
        Fetch GPS data from a gpsd source.
        """
        try:
            # Read gpsd
            get_coordinates = fissure.utils.hardware.probe_gpsd(self.logger, "DD", self.gpsd_serial_port, True)
            return get_coordinates
        except Exception as e:
            self.logger.error(f"Error getting GPS from gpsd: {e}")
            return None
        

    async def fetch_gps_from_saved(self):
        """
        Fetch GPS data from a saved value in the config file.
        """
        try:
            saved = self.settings.get('gps_position', {})
            lat = saved.get('latitude', 0.0)
            lon = saved.get('longitude', 0.0)
            alt = saved.get('altitude', 0.0)
            return {'latitude': lat, 'longitude': lon, 'altitude': alt}
    
        except Exception as e:
            self.logger.error(f"Error getting GPS from saved value in config file: {e}")
            return None


    async def fetch_gps_from_internet(self):
        """
        Fetch approximate GPS data from the internet using IP-based geolocation.
        Returns None if unavailable (no fallback here).
        """
        return await fissure.utils.hardware.probeInternetGPS(self.logger)
            

    async def periodic_gps_update(self, gps_source, meshtastic_node):
        """Periodically updates GPS position from available sources."""
        self.running = True
        while self.running:
            gps_data = None

            # Meshtastic, existing connection
            if gps_source == "Meshtastic":  # TODO: add lower() logic across all gps_source to account for caps in config files
                if meshtastic_node:
                    gps_data = await self.fetch_gps_from_meshtastic(meshtastic_node)

            # Meshtastic, new connection/on IP networking with a Meshtastic device plugged in
            elif gps_source == "Meshtastic New Connection":
                if meshtastic_node:
                    async with self.meshtastic_lock:  # Prevents multiple calls from Find button
                        gps_data = await self.fetch_gps_from_meshtastic_new_connection(meshtastic_node)

            # gpsd, USB GPS receiver
            elif gps_source == "gpsd":
                gps_data = await self.fetch_gps_from_gpsd()

            # Saved
            elif gps_source == "saved":
                gps_data = await self.fetch_gps_from_saved()

            # Internet
            elif gps_source == "internet":
                gps_data = await self.fetch_gps_from_internet()

            # Send new GPS data to the callback function
            # Handle None values in the callback function and treat as stale
            await self.gps_callback(gps_data)

            await asyncio.sleep(self.gps_update_interval_seconds)


    def stop(self):
        """Stops GPS updates."""
        self.running = False


if __name__ == "__main__":
    args = parse_args()
    rc = 0
    # try:
    run(args.local)
    # except Exception:
        # rc = 1

    sys.exit(rc)
