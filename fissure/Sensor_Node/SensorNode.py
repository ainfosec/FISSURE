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
import socket

from inspect import isfunction
from types import ModuleType
from typing import Dict, List, Union, Callable, Optional, Any

import asyncio
import fissure.callbacks
import fissure.comms
import fissure.utils
from fissure.utils import PLUGIN_DIR
from fissure.utils import plugin
from fissure.utils.artifacts import ArtifactManager

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
    
    sensor_node.gps_manager = gps_manager

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
        self.hiprfisr_seen = False
        self.local_remote = "local" if local_flag else "remote"

        self.os_info = fissure.utils.get_os_info()
        filename = os.path.join(fissure.utils.YAML_DIR, "Sensor_Node_Config", "default.yaml")
        with open(filename) as yaml_library_file:
            self.settings_dict = yaml.load(yaml_library_file, yaml.FullLoader)

        # Dashboard selected-node state, and GUI gating consistent with --local.
        self.settings_dict["Sensor Node"]["local_remote"] = self.local_remote

        if self.local_remote == "local":
            self.settings_dict["Sensor Node"]["network_type"] = "IP"
            self.settings_dict["Sensor Node"]["node_ip_address"] = "ipc"
            self.settings_dict["Sensor Node"]["nickname"] = "Local Sensor Node"

        self.update_ip_address_settings()
        
        self.child_tasks = []
        self.sockets = []
        self.current_status = "Idle"

        # Version
        self.version_string = "0.0.0"

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

        self.heartbeat_interval = int(self.settings_dict["Sensor Node"].get("heartbeat_interval", 5))
        self.heartbeat_interval_connected = int(self.settings_dict["Sensor Node"].get("heartbeat_interval_connected", 20))
        self.sensor_node_heartbeat_time = 0
        self.attack_flow_graph_loaded = False
        self.physical_fuzzing_stop_event = False
        self.attack_script_name = ""
        self.triggers_running = False
        self.alert_senders = {}

        self.running_PD = False
        self.pd_bits_socket = None

        self.autorun_playlist_thread = None
        if self.settings_dict['Sensor Node']['autorun'] is True:
            filename = os.path.join(fissure.utils.SENSOR_NODE_DIR, "Autorun_Playlists", "default.yaml")
            with open(filename) as yaml_library_file:
                playlist_dict = yaml.load(yaml_library_file, yaml.FullLoader)
                trigger_dict = playlist_dict['trigger_values']
            self.autorunPlaylistStart(playlist_dict, trigger_dict)

        # ZMQ DEALER/ROUTER fields
        self.listener = None
        self.artifact_transfer_client = None
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

        gps_settings = self.settings_dict["Sensor Node"].get("gps", {})

        self.gps_autostart = bool(gps_settings.get("gps_autostart", True))
        self.gps_source = str(gps_settings.get("gps_source", "saved"))
        self.gps_update_interval_seconds = int(gps_settings.get("gps_update_interval_seconds", 20))

        self.meshtastic_lock = asyncio.Lock()

        # Cached node position state. The heartbeat reads this; it does not probe GPS.
        self.gps_position = gps_settings.get("gps_position", {}) or {}
        self.gps_position.setdefault("latitude", 0.0)
        self.gps_position.setdefault("longitude", 0.0)
        self.gps_position.setdefault("altitude", 0.0)

        self.gps_position["latitude_ddm"], self.gps_position["longitude_ddm"] = \
            fissure.utils.common.decimal_to_ddm(
                self.gps_position["latitude"],
                self.gps_position["longitude"]
            )

        # A saved/default position is usable as a fallback immediately.
        self.gps_valid = True
        self.gps_time = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        self.gps_stale = False

        self.operations = {} # operation tracking dictionary

        # initialize artifact manager
        self.artifact_manager = ArtifactManager(logger=self.logger)

        # Keep ArtifactManager as the only artifact-schema implementation.
        # This wrapper only forces the authoritative Sensor Node source ID and
        # schedules the existing HIPRFISR metadata notification.
        self._original_create_artifact = (
            self.artifact_manager.create_artifact
        )

        def create_artifact_wrapper(
            source_id: str,
            operation_id: str,
            files,
            name: str,
            artifact_type: str,
            metadata: Union[Dict[str, Any], None] = None,
            relations=None,
            file_metadata=None,
            artifact_id: str = "",
        ) -> str:
            created_artifact_id = self._original_create_artifact(
                source_id=self.uuid,
                operation_id=operation_id,
                files=files,
                name=name,
                artifact_type=artifact_type,
                metadata=metadata,
                relations=relations,
                file_metadata=file_metadata,
                artifact_id=artifact_id,
            )

            asyncio.create_task(
                self._notify_hiprfisr_of_artifact(
                    created_artifact_id
                )
            )

            return created_artifact_id

        self.artifact_manager.create_artifact = (
            create_artifact_wrapper
        )


    async def initialize_comms(self):
        if self.network_type == "IP":

            # Build HIPRFISR address
            if self.local_remote == "remote":
                network_protocol = "tcp"
            else:
                network_protocol = "ipc"

            self.hiprfisr_address = fissure.comms.Address(
                protocol=network_protocol,
                address=self.hiprfisr_ip_address,
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


    async def send_alert(self, node_uid: str, opid: str, message: str, logger: None = None) -> None:
        """
        Send an alert message.

        This method is meant to be provided as a callback for plugin operations to send alert messages.

        Parameters
        ----------
        node_uid : str
            Sensor node UID
        opid : str
            The operation ID. Unused placeholder for future use.
        message : str
            The alert message.
        logger : None
            Unused placeholder for debugging.
        """
        PARAMETERS = {
            "node_uid": node_uid,
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
                    "node_uid": node_uid,
                    "alert_text": PARAMETERS["alert_text"][:100]
                }
            }
        await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


    async def send_detection(self, detection: dict) -> None:
        """
        Publish one structured detector observation.

        Detections remain transient. The Sensor Node is the first common
        routing point so future local detector-group/trigger consumers can
        react before the same Detection is forwarded to HIPRFISR.
        """
        if not isinstance(detection, dict):
            self.logger.error("send_detection() requires a detection dictionary.")
            return

        detection = dict(detection)

        detection["kind"] = "detection"
        detection["event_type"] = "detection"
        detection["node_uid"] = self.uuid
        detection.setdefault("source_id", self.uuid)
        detection.setdefault("detection_id", str(uuid.uuid4()))

        operation_id = str(
            detection.get("opid")
            or detection.get("operation_id")
            or ""
        ).strip()

        if operation_id:
            detection["opid"] = operation_id
            detection.setdefault("operation_id", operation_id)

        detection_timestamp = detection.get("timestamp")
        if detection_timestamp in (None, ""):
            detection_timestamp = time.time()
            detection["timestamp"] = detection_timestamp

        observation_time = detection.get("observation_time")

        if not observation_time:
            try:
                observation_time = datetime.fromtimestamp(
                    float(detection_timestamp),
                    tz=timezone.utc,
                ).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
            except Exception:
                if isinstance(detection_timestamp, str):
                    observation_time = detection_timestamp.replace(" ", "T")
                else:
                    observation_time = datetime.now(timezone.utc).strftime(
                        "%Y-%m-%dT%H:%M:%S.%fZ"
                    )

        lat = detection.get("latitude")
        if lat is None:
            lat = detection.get("lat")

        lon = detection.get("longitude")
        if lon is None:
            lon = detection.get("lon")

        alt = detection.get("altitude")
        if alt is None:
            alt = detection.get("alt")
        if alt is None:
            alt = detection.get("hae_m")
        if alt is None:
            alt = detection.get("hae")

        gps_position = getattr(self, "gps_position", {}) or {}

        if lat is None:
            lat = gps_position.get("latitude")
        if lon is None:
            lon = gps_position.get("longitude")
        if alt is None:
            alt = gps_position.get("altitude")

        if lat is not None:
            detection.setdefault("latitude", lat)
        if lon is not None:
            detection.setdefault("longitude", lon)
        if alt is not None:
            detection.setdefault("altitude", alt)

        detection.setdefault("observation_time", observation_time)

        if self.network_type != "IP":
            self.logger.warning(
                "Structured detection returns are currently supported only "
                "for IP Sensor Nodes."
            )
            return

        PARAMETERS = {
            "detection": detection,
            "lat": lat,
            "lon": lon,
            "alt": alt,
            "observation_time": observation_time,
        }

        msg = {
            fissure.comms.MessageFields.IDENTIFIER: self.identifier,
            fissure.comms.MessageFields.MESSAGE_NAME: "detectionReturn",
            fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
        }

        await self.hiprfisr_socket.send_msg(
            fissure.comms.MessageTypes.COMMANDS,
            msg,
        )


    async def send_tak_cot(self, msg: dict) -> None:
        """
        Unified TAK message sender (node → HIPRFISR).

        Plugins send a dictionary containing any of:

            msg = {
                "msg_type": "pin" | "track" | "event",   # optional, default="pin"
                "uid": str,                               # required
                "lat": float | True,                      # True = auto-fill from node GPS
                "lon": float | True,
                "alt": float | True,
                "time": str | True,                       # True = auto-fill now()
                "remarks": str,
                "tak_icon": str,                          # TAK icon e.g. "a-h-G-E-S"
                "opid": str,
                "data": dict                              # only for event messages

                # Optional alert / evidence fields (pins):
                "alert_kind": str,
                "alert_summary": str,
                "artifact_id": str,
                "operation_id": str,      # evidence/artifact op id (not self.opid)
                "node_uid": str,

                # Optional small scalar extras (kept intentionally small):
                "count": int,
                "duration_s": float,
                "fps": float,
                "frames_written": int,
                "burst_index": int,
                "burst_total": int,
                "timestamp": str,
                "name": str,
            }

        Missing fields are ignored.
        True values for lat/lon/alt/time trigger auto-resolution.
        """
        # --------------------------------------------------
        # Validate minimal required field
        # --------------------------------------------------
        if "uid" not in msg:
            self.logger.error("send_tak_cot() missing required field: uid")
            return

        # --------------------------------------------------
        # Resolve msg_type
        # --------------------------------------------------
        msg_type = msg.get("msg_type")
        if not msg_type:
            # auto-detect: GPS UPDATE => track
            if msg.get("remarks") == "GPS UPDATE":
                msg_type = "track"
            else:
                msg_type = "pin"

        # --------------------------------------------------
        # Normalize GPS + timestamp (only if fields exist)
        # --------------------------------------------------
        lat = msg.get("lat")
        if lat is True:
            lat = self.gps_position.get("latitude", 0.0)

        lon = msg.get("lon")
        if lon is True:
            lon = self.gps_position.get("longitude", 0.0)

        alt = msg.get("alt")
        if alt is True:
            alt = self.gps_position.get("altitude", 0.0)

        timestamp = msg.get("time")
        if timestamp is True:
            timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        elif isinstance(timestamp, str):
            timestamp = timestamp.replace(" ", "T")  # safety normalization

        # --------------------------------------------------
        # Optional fields (base schema)
        # --------------------------------------------------
        remarks = msg.get("remarks")
        tak_icon = msg.get("tak_icon")
        opid = msg.get("opid")
        data = msg.get("data")  # for event messages only
        uid = msg["uid"]

        # --------------------------------------------------
        # Build payload (include ONLY present fields)
        # --------------------------------------------------
        payload = {"msg_type": msg_type, "uid": uid}

        if lat is not None:
            payload["lat"] = lat
        if lon is not None:
            payload["lon"] = lon
        if alt is not None:
            payload["alt"] = alt
        if timestamp is not None:
            payload["time"] = timestamp
        if remarks is not None:
            payload["remarks"] = remarks
        if tak_icon is not None:
            payload["tak_icon"] = tak_icon
        if opid is not None:
            payload["opid"] = opid
        if data is not None:
            payload["data"] = data

        # --------------------------------------------------
        # Pass-through extra fields (used by TAK utility layer)
        # Keep this intentionally small + scalar.
        # --------------------------------------------------
        passthrough_keys = {
            # pin alert structure
            "alert_kind",
            "alert_summary",
            "artifact_id",
            "operation_id",
            "node_uid",

            # optional lightweight extras
            "name",
            "count",
            "duration_s",
            "fps",
            "frames_written",
            "burst_index",
            "burst_total",
            "timestamp",
        }

        for k in passthrough_keys:
            if k in msg and msg[k] is not None:
                payload[k] = msg[k]

        # --------------------------------------------------
        # IP MODE → send takReturn
        # --------------------------------------------------
        if self.network_type == "IP":
            msg_out = {
                fissure.comms.MessageFields.IDENTIFIER: self.identifier,
                fissure.comms.MessageFields.MESSAGE_NAME: "takReturn",
                fissure.comms.MessageFields.PARAMETERS: {
                    "payload": payload
                },
            }

        # --------------------------------------------------
        # MESHTASTIC MODE → legacy LT list format
        # (does NOT support arbitrary extra fields)
        # --------------------------------------------------
        elif self.network_type == "Meshtastic":

            if lat is None or lon is None or alt is None:
                self.logger.error("Meshtastic TAK requires lat/lon/alt.")
                return

            if timestamp is None:
                timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

            PARAMETERS = [
                msg_type,
                timestamp,
                uid,
                lat,
                lon,
                (data[:20] if isinstance(data, str) else None),
            ]

            msg_out = {
                fissure.comms.MessageFields.IDENTIFIER: self.identifier,
                fissure.comms.MessageFields.MESSAGE_NAME: "takReturnLT",
                fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
            }

        else:
            self.logger.error(f"Unknown network type for TAK: {self.network_type}")
            return

        await self.hiprfisr_socket.send_msg(
            fissure.comms.MessageTypes.COMMANDS, msg_out
        )
    

    async def send_soi_update(
        self,
        node_uid,
        soi_id,
        frequency_mhz,
        status,
        operation_id="",
        artifact_id="",
        summary=None,
        lat=None,    # float | True | None
        lon=None,    # float | True | None
        alt=None,    # float | True | None  (treat as HAE)
        observation_time=None,   # str | True | None
    ):
        
        # --------------------------------------------
        # Normalize GPS + timestamp (match send_tak_cot)
        # --------------------------------------------
        if lat is True:
            lat = self.gps_position.get("latitude")
        if lon is True:
            lon = self.gps_position.get("longitude")
        if alt is True:
            alt = self.gps_position.get("altitude")
        if observation_time is True:
            observation_time = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        elif isinstance(observation_time, str):
            observation_time = observation_time.replace(" ", "T")

        # --------------------------------------------
        # Build PARAMETERS (include only if present)
        # --------------------------------------------
        PARAMETERS = {
            "node_uid": node_uid,
            "soi_id": soi_id,
            "frequency_mhz": frequency_mhz,
            "status": status,
            "operation_id": operation_id or "",
            "artifact_id": artifact_id or "",
            "summary": summary or {},
        }

        # add location only if provided/resolved
        if lat is not None: PARAMETERS["lat"] = float(lat)
        if lon is not None: PARAMETERS["lon"] = float(lon)
        if alt is not None: PARAMETERS["alt"] = float(alt)
        if observation_time is not None: PARAMETERS["observation_time"] = observation_time

        if self.network_type == "IP":
            msg = {
                fissure.comms.MessageFields.IDENTIFIER: self.identifier,
                fissure.comms.MessageFields.MESSAGE_NAME: "soiUpdate",
                fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
            }

        elif self.network_type == "Meshtastic":
            compact = {
                "node_uid": node_uid,
                "soi_id": str(soi_id)[:16],
                "f": float(frequency_mhz),
                "s": str(status)[:16],
            }
            msg = {
                fissure.comms.MessageFields.SOURCE: self.assigned_id,
                fissure.comms.MessageFields.MESSAGE_NAME: "soiUpdateLT",
                fissure.comms.MessageFields.PARAMETERS: compact,
            }

        else:
            self.logger.error("Unknown network type for SOI update")
            return

        await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)



    async def send_target_update(
        self,
        node_uid,
        target_id,
        source_soi_id="",
        frequency_mhz=None,
        state="",
        classification=None,   # dict
        location=None,         # dict
        history_entry=None,    # dict
        artifact_id="",
        summary=None,
        lat=None,              # float | True | None
        lon=None,              # float | True | None
        alt=None,              # float | True | None (HAE)
        observation_time=None, # str | True | None
    ):
        """
        Target update (node -> HIPRFISR), analogous to send_soi_update.

        Notes
        -----
        - This function sends canonical (nested) blobs to the hub.
        - The hub is responsible for emitting TAK in the ONE flat format.
        """

        # --------------------------------------------
        # Normalize GPS + timestamp (match send_soi_update)
        # --------------------------------------------
        if lat is True:
            lat = self.gps_position.get("latitude")
        if lon is True:
            lon = self.gps_position.get("longitude")
        if alt is True:
            alt = self.gps_position.get("altitude")
        if observation_time is True:
            observation_time = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        elif isinstance(observation_time, str):
            observation_time = observation_time.replace(" ", "T")

        # --------------------------------------------
        # Build PARAMETERS (include only if present)
        # --------------------------------------------
        PARAMETERS = {
            "node_uid": node_uid,
            "target_id": target_id,
            "source_soi_id": source_soi_id or "",
            "frequency_mhz": frequency_mhz,
            "state": state or "",
            "artifact_id": artifact_id or "",
            "classification": classification or {},
            "location": location or {},
            "history_entry": history_entry or {},
            "summary": summary or {},
        }

        # add location only if provided/resolved
        if lat is not None: PARAMETERS["lat"] = float(lat)
        if lon is not None: PARAMETERS["lon"] = float(lon)
        if alt is not None: PARAMETERS["alt"] = float(alt)
        if observation_time is not None: PARAMETERS["observation_time"] = observation_time

        if self.network_type == "IP":
            msg = {
                fissure.comms.MessageFields.IDENTIFIER: self.identifier,
                fissure.comms.MessageFields.MESSAGE_NAME: "targetUpdate",
                fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
            }

        elif self.network_type == "Meshtastic":
            compact = {
                "node_uid": str(node_uid)[:16],
                "target_id": str(target_id)[:16],
                "soi": str(source_soi_id)[:16],
                "f": float(frequency_mhz) if frequency_mhz is not None else 0.0,
                "st": str(state)[:16],
            }
            msg = {
                fissure.comms.MessageFields.SOURCE: self.assigned_id,
                fissure.comms.MessageFields.MESSAGE_NAME: "targetUpdateLT",
                fissure.comms.MessageFields.PARAMETERS: compact,
            }

        else:
            self.logger.error("Unknown network type for Target update")
            return

        await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)

        self.logger.info(f"SensorNode send_target_update called with target_id={target_id} state={state}")
    

    async def send_target_patch(
        self,
        target_id: str,
        patch: dict,
        history_entry: dict = None,
        artifact_id: str = "",
    ):
        """
        Target patch (node -> HIPRFISR).

        IP path sends a canonical target-shaped patch that the hub merges into the
        authoritative stored target record.

        Meshtastic is intentionally left minimal for now.
        """
        if not target_id:
            self.logger.error("send_target_patch missing target_id")
            return

        if not isinstance(patch, dict):
            self.logger.error("send_target_patch patch must be a dict")
            return

        if history_entry is None:
            history_entry = {}
        elif not isinstance(history_entry, dict):
            self.logger.error("send_target_patch history_entry must be a dict")
            return

        if self.network_type == "IP":
            msg = {
                fissure.comms.MessageFields.IDENTIFIER: self.identifier,
                fissure.comms.MessageFields.MESSAGE_NAME: "targetPatch",
                fissure.comms.MessageFields.PARAMETERS: {
                    "target_id": target_id,
                    "patch": patch,
                    "history_entry": history_entry,
                    "artifact_id": artifact_id or "",
                },
            }

        elif self.network_type == "Meshtastic":
            compact = {
                "target_id": str(target_id)[:16],
                "st": str((patch or {}).get("state", ""))[:16],
            }
            msg = {
                fissure.comms.MessageFields.SOURCE: self.assigned_id,
                fissure.comms.MessageFields.MESSAGE_NAME: "targetUpdateLT",
                fissure.comms.MessageFields.PARAMETERS: compact,
            }

        else:
            self.logger.error("Unknown network type for target patch")
            return

        await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)
        self.logger.info(f"SensorNode send_target_patch called with target_id={target_id}")


    async def _notify_hiprfisr_of_artifact(self, artifact_id: str) -> None:
        """Notify HIPRFISR of a new artifact (async helper method).
        
        Parameters
        ----------
        artifact_id : str
            The artifact ID to notify about
        """
        # notify hiprfisr of new artifact
        artifact = self.artifact_manager.get_artifact(artifact_id)
        if artifact is None:
            self.logger.error(f"Failed to retrieve newly created artifact {artifact_id} for notification.")
            return
        PARAMETERS = {
            "artifact": artifact.to_dict()
        }
        msg = {
            fissure.comms.MessageFields.IDENTIFIER: self.identifier,
            fissure.comms.MessageFields.MESSAGE_NAME: "updateArtifact",
            fissure.comms.MessageFields.PARAMETERS: PARAMETERS
        }
        await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


    async def run_plugin_operation(
        self,
        component: object,  # Required for callback system
        plugin: str,
        operation: str,
        parameters: Dict[str, Any],
        node_uid: str,
        wait: bool = False,
        start_timeout: float = 2.0,
    ) -> Optional[str]:
        """
        Runs a plugin operation on the Sensor Node.

        Behavior (low-traffic + no duplicates):
        - No pluginOperationStarted/Stopped messages
        - Node status auto-reverts to Idle when the LAST active operation completes
        - Finalizer is the ONLY owner of teardown + registry removal
        - stop_plugin_operation should only request stop + await task (no teardown/pop)

        Parameters
        ----------
        plugin : str
            The name of the plugin.
        operation : str
            The plugin filename to run relative to the plugin directory.
        parameters : dict
            The operation parameters (user-provided).
        node_uid : str
            The UID of the sensor node.
        wait : bool
            If True, wait for the operation to complete + teardown before returning.
            If False, return after startup handshake (or immediate completion).
        start_timeout : float
            Seconds to wait for a long-running operation to report a non-None running() state.

        Returns
        -------
        Optional[str]
            operation_id (opid) if successfully scheduled; otherwise None.
        """
        # -------------------------------------------------------------------------
        # One-time state for low-traffic status + lifecycle
        # -------------------------------------------------------------------------
        if not hasattr(self, "_active_operation_ids"):
            self._active_operation_ids = set()
        if not hasattr(self, "_last_published_status"):
            self._last_published_status = None
        if not hasattr(self, "_idle_status_text"):
            self._idle_status_text = "Idle"
        if not hasattr(self, "current_status"):
            self.current_status = self._idle_status_text  # canonical, used by beacons

        async def _set_status_edge(status_text: str, *, force: bool = False) -> None:
            """
            Canonical status setter + optional low-traffic publisher.

            - self.current_status is the source of truth (beacons read this)
            - publish_status_to_hiprfisr is best-effort
            - sends ONLY on change unless force=True
            """
            s = (status_text or "").strip() or "unknown"

            # If state didn't change and we're not forcing, do nothing
            if (not force) and self.current_status == s:
                return

            # Update canonical state first (so beacons reflect immediately)
            self.current_status = s

            # Publish only if we haven't already published this value (unless force=True)
            if force or (self._last_published_status != s):
                self._last_published_status = s
                try:
                    await self.publish_status_to_hiprfisr(s)
                except Exception:
                    # Comms is best-effort; do not fail operation
                    self.logger.debug("Status publish failed.", exc_info=True)

        self.logger.info(f"Running plugin operation: {plugin} - {operation} with parameters: {parameters}")

        # -------------------------------------------------------------------------
        # Resolve plugin paths
        # -------------------------------------------------------------------------
        plugin_path = os.path.join(PLUGIN_DIR, plugin)
        if not os.path.exists(plugin_path):
            self.logger.error(f"Plugin path does not exist: {plugin_path}")
            return None
        self.logger.info(f"Plugin path resolved: {plugin_path}")

        plugin_script_path = os.path.join(plugin_path, "operations", operation)
        if not os.path.exists(plugin_script_path):
            self.logger.error(f"Plugin script does not exist: {plugin_script_path}")
            return None
        self.logger.info(f"Plugin script resolved: {plugin_script_path}")

        # -------------------------------------------------------------------------
        # Import operation module
        # -------------------------------------------------------------------------
        try:
            spec = importlib.util.spec_from_file_location("plugin_module", plugin_script_path)
            if spec is None or spec.loader is None:
                self.logger.error(f"Could not load spec for plugin script: {plugin_script_path}")
                return None
            plugin_module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(plugin_module)
        except Exception as e:
            tb_str = traceback.format_exc()
            self.logger.error(f"Error importing plugin script {plugin_script_path}: {e}\n{tb_str}")
            return None

        # -------------------------------------------------------------------------
        # Get OperationMain
        # -------------------------------------------------------------------------
        operation_main = getattr(plugin_module, "OperationMain", None)
        if operation_main is None:
            self.logger.error(f"No OperationMain class found in {plugin_script_path}")
            return None
        if not inspect.isclass(operation_main):
            self.logger.error(f"OperationMain is not a class in {plugin_script_path}")
            return None

        # -------------------------------------------------------------------------
        # Resources
        # -------------------------------------------------------------------------
        if not hasattr(operation_main, "get_resources") or not callable(getattr(operation_main, "get_resources")):
            self.logger.error(f"No callable get_resources() found in {plugin_script_path} OperationMain class")
            return None
        try:
            resources = operation_main.get_resources()
        except Exception as e:
            tb_str = traceback.format_exc()
            self.logger.error(f"Error calling get_resources() in {plugin_script_path}: {e}\n{tb_str}")
            return None
        if not isinstance(resources, dict):
            self.logger.error(f"get_resources() did not return a dictionary: {resources}")
            return None
        self.logger.info(f"Plugin operation resources: {resources}")

        # Record user parameters (for UI/reporting/logging only; not sent over air)
        user_parameters = parameters.copy()

        # -------------------------------------------------------------------------
        # Add callbacks + context for Operation base class
        # -------------------------------------------------------------------------
        parameters["node_uid"] = node_uid
        parameters["alert_callback"] = self.send_alert
        parameters["tak_cot_callback"] = self.send_tak_cot
        parameters["detection_callback"] = self.send_detection
        parameters["status_callback"] = self.publish_status_to_hiprfisr
        parameters["target_callback"] = self.send_target_patch  #self.send_target_update
        parameters["soi_callback"] = self.send_soi_update
        parameters["artifact_manager"] = self.artifact_manager
        parameters["logger"] = self.logger

        # -------------------------------------------------------------------------
        # Initialize operation instance (filter init params)
        # -------------------------------------------------------------------------
        try:
            init_signature = inspect.signature(operation_main.__init__)
            init_params = set(init_signature.parameters.keys())
            filtered_parameters = {k: v for k, v in parameters.items() if k in init_params}
            operation_inst = operation_main(**filtered_parameters)
            requested_operation_id = str(parameters.get("operation_id") or "").strip()
            if requested_operation_id:
                operation_inst.opid = requested_operation_id
                
        except Exception as e:
            tb_str = traceback.format_exc()
            self.logger.error(f"Error initializing operation class from {plugin_script_path}: {e}\n{tb_str}")
            return None
        self.logger.info(f"Plugin operation initialized: {operation}")

        # -------------------------------------------------------------------------
        # Validate required attributes/methods
        # -------------------------------------------------------------------------
        if not hasattr(operation_inst, "opid"):
            self.logger.error(f"No operation ID (opid) found in {plugin_script_path}")
            return None
        if not hasattr(operation_inst, "running") or not callable(operation_inst.running):
            self.logger.error(f"No running flag found in {plugin_script_path}")
            return None
        if not hasattr(operation_inst, "stop") or not callable(operation_inst.stop):
            self.logger.error(f"No callable stop() method found in {plugin_script_path}")
            return None
        if not hasattr(operation_inst, "teardown") or not callable(operation_inst.teardown):
            self.logger.error(f"No callable teardown() method found in {plugin_script_path}")
            return None
        if not hasattr(operation_inst, "run") or not callable(operation_inst.run):
            self.logger.error(f"No callable run() method found in {plugin_script_path} OperationMain class")
            return None
        if not hasattr(operation_inst, "setup") or not callable(operation_inst.setup):
            self.logger.error(f"No callable setup() method found in {plugin_script_path} OperationMain class")
            return None

        # -------------------------------------------------------------------------
        # Setup environment
        # -------------------------------------------------------------------------
        try:
            env_ready = await operation_inst.setup()
        except Exception as e:
            tb_str = traceback.format_exc()
            self.logger.error(f"Error during setup() for {plugin_script_path}: {e}\n{tb_str}")
            return None
        if not env_ready:
            self.logger.error(f"Plugin operation {operation} setup failed.")
            return None
        self.logger.info(f"Plugin operation environment for {operation} is ready.")

        # -------------------------------------------------------------------------
        # Register operation
        # -------------------------------------------------------------------------
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
            "task": None,
        }

        # Track "busy vs idle" based on active operation IDs
        self._active_operation_ids.add(operation_id)

        # Transition idle->running exactly once (edge-triggered)
        if len(self._active_operation_ids) == 1:
            # Keep short. If you prefer "Running" only, do that.
            await _set_status_edge(f"Running: {operation}")

        # -------------------------------------------------------------------------
        # Start the operation task
        # -------------------------------------------------------------------------
        self.logger.info(f"Starting plugin operation {operation_id}")
        task = asyncio.create_task(operation_inst.run(), name=f"op:{operation_id}")
        self.operations[operation_id]["task"] = task

        # -------------------------------------------------------------------------
        # Finalizer: teardown + cleanup + status revert (single owner)
        # -------------------------------------------------------------------------
        async def _finalize_operation() -> None:
            err_str = ""
            try:
                await task
            except Exception:
                err_str = traceback.format_exc()
                self.logger.error(f"Plugin operation {operation_id} raised:\n{err_str}")
            finally:
                # Teardown (exactly once, owned here)
                try:
                    await operation_inst.teardown()
                except Exception:
                    self.logger.error(
                        f"Error tearing down plugin operation {operation_id}:\n{traceback.format_exc()}"
                    )

                # Remove from registry (exactly once, owned here)
                self.operations.pop(operation_id, None)

                # Update active set
                self._active_operation_ids.discard(operation_id)

                # If this was the last active op, revert status once (edge-triggered)
                if len(self._active_operation_ids) == 0:
                    # Choose behavior:
                    # - If you want errors to persist until next heartbeat, you can set "Error" when err_str != ""
                    # - If you want always "Idle" on completion, do that regardless
                    if err_str:
                        await _set_status_edge("Error")
                    else:
                        await _set_status_edge(self._idle_status_text)

        finalize_task = asyncio.create_task(_finalize_operation(), name=f"op_finalize:{operation_id}")

        # -------------------------------------------------------------------------
        # Startup handshake: wait for running() to become non-None OR task to finish quickly
        # -------------------------------------------------------------------------
        deadline = time.time() + float(start_timeout)
        while operation_inst.running() is None and not task.done() and time.time() < deadline:
            await asyncio.sleep(0.05)

        if task.done():
            exc = task.exception()
            if exc is None:
                self.logger.info(f"Plugin operation {operation_id} completed quickly.")
            else:
                self.logger.error(f"Plugin operation {operation_id} failed immediately: {exc!r}")
            if wait:
                await finalize_task
            return operation_id

        # Long-running (or still starting but past timeout)
        self.logger.info(f"Plugin operation {operation_id} running (running()={operation_inst.running()}).")

        if wait:
            await finalize_task

        return operation_id


    async def stop_plugin_operation(
        self, 
        component: object, # Required for callback system
        operation_id: str
    ) -> None:
        """
        Stops a plugin operation on the Sensor Node.

        IMPORTANT:
        - This function must NOT teardown or pop the operation registry.
        The run_plugin_operation finalizer owns teardown + cleanup + status revert.
        - This prevents duplicate teardown and duplicate status transitions.
        """
        self.logger.info(f"Stopping plugin operation with ID: {operation_id}")

        op = self.operations.get(operation_id)
        if not op:
            self.logger.error(f"Operation ID {operation_id} not found.")
            return

        # Request stop
        if op.get("stop") and callable(op["stop"]):
            try:
                await op["stop"]()
            except Exception:
                self.logger.error(f"Error stopping plugin operation {operation_id}:\n{traceback.format_exc()}")
                # still continue to wait for task to settle
        else:
            self.logger.error(f"No callable stop method for operation {operation_id}.")
            return

        self.logger.info(f"Operation {operation_id} stop requested.")

        # Prefer awaiting the task; finalizer will handle teardown + cleanup.
        task = op.get("task")
        if task is not None:
            try:
                await task
            except Exception:
                # Finalizer logs full traceback; keep noise low here.
                self.logger.debug(f"stop_plugin_operation: task raised for {operation_id}")
            return

        # Fallback: poll running() if task missing (should be rare)
        try:
            while op.get("status") and callable(op["status"]) and op["status"]():
                await asyncio.sleep(0.25)
        except Exception:
            self.logger.debug(f"stop_plugin_operation: status polling error for {operation_id}")


    async def stop_all_plugin_operations(
        self, 
        component: object,  # Required for callback system
        requester_uid: str,
        requester_type: str
    ) -> None:
        """
        Stops all running plugin operations on the Sensor Node.

        Parameters
        ----------
        requester_type : str
            dashboard, tak, or broadcast 
        plugin_name : str
            The name of the plugin.
        """
        self.logger.info("Stopping all plugin operations.")
        for operation_id in list(self.operations.keys()):
            await self.stop_plugin_operation(component, operation_id)


    async def plugin_action(
        self,
        comonent: object,  # Required for callback system
        requester_uid: str, 
        requester_type: str,  
        plugin_name: str, 
        action_name: str, 
        parameters: Dict[str, Any] = {}
    ) -> None:
        """
        Calls a specific action function within a plugin.

        Parameters
        ----------
        requester_uid : str
            TAK unique identifier
        requester_type : str
            dashboard, tak, or broadcast 
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

            if not plugin.action_is_allowed(
                plugin_name,
                action_name,
                requester_type=(
                    requester_type
                ),
                node_location=(
                    self.local_remote
                ),
                logger=self.logger,
            ):
                self.logger.warning(
                    "Rejected plugin action execution: "
                    f"{plugin_name}.{action_name}, "
                    f"requester_type={requester_type}, "
                    f"node_location={self.local_remote}"
                )
                return

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
                    await action_func(self, parameters, self.uuid)
                else:
                    action_func(self, parameters, self.uuid)
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
        if self.pd_bits_socket:
            try:
                self.stopPD()
                await asyncio.sleep(2)
            except:
                pass

        artifact_client = self.artifact_transfer_client
        if artifact_client is not None:
            try:
                artifact_client.close()
            except Exception:
                pass
        self.artifact_transfer_client = None

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
            ok = await self.hiprfisr_socket.connect(
                self.hiprfisr_address
            )

            if ok:
                self.logger.info(
                    f"Connected to HIPRFISR @ {self.hiprfisr_address}"
                )
                await asyncio.sleep(
                    0.1
                )  # For ZMQ handshake to complete

                artifact_host = (
                    "127.0.0.1"
                    if self.hiprfisr_address.protocol == "ipc"
                    else self.hiprfisr_address.address
                )

                self.artifact_transfer_client = (
                    fissure.comms.ArtifactTransferClient(
                        endpoint=fissure.comms.build_artifact_endpoint(
                            artifact_host
                        ),
                        identity=f"sensor-artifacts-{self.uuid}",
                        role=fissure.comms.ROLE_SENSOR_NODE,
                        node_uid=self.uuid,
                        logger=self.logger,
                    )
                )

                await self.artifact_transfer_client.connect()

                from fissure.Sensor_Node.SensorNodeFileTransferController import (
                    SensorNodeFileTransferController,
                )

                file_transfer_controller = (
                    SensorNodeFileTransferController(
                        self
                    )
                )

                file_transfer_task = asyncio.create_task(
                    file_transfer_controller.receive_loop()
                )

                file_transfer_task.set_name(
                    f"Sensor Node File Transfer Receiver {self.uuid}"
                )

                self.child_tasks.append(
                    file_transfer_task
                )

            else:
                self.logger.error(
                    "FAILED connecting to HIPRFISR"
                )
                return

        elif self.network_type == "Meshtastic":
            try:
                serial_port = (
                    self.pending_meshtastic_params[
                        "serial_port"
                    ]
                )

                self.hiprfisr_socket = (
                    fissure.comms.FissureMeshtasticNode(
                        serial_port,
                        self.pending_meshtastic_params[
                            "name"
                        ],
                        self.pending_meshtastic_params[
                            "context"
                        ],
                    )
                )

                self.logger.info(
                    "Connected to Meshtastic serial port: "
                    f"{serial_port}"
                )

            except Exception as e:
                self.logger.error(
                    "Failed to initialize Meshtastic on "
                    f"{serial_port}: {e}"
                )
                return

        else:
            self.logger.error(
                "Unknown network type. Enter IP or Meshtastic "
                "in node YAML config file."
            )
            return

        # Start Heartbeat Loop
        heartbeat_task = asyncio.create_task(
            self.heartbeat_loop()
        )
        self.child_tasks.append(
            heartbeat_task
        )

        # Local Sensor Node should appear quickly in Dashboard/Tactical UI.
        # Do this after connect and after the heartbeat loop exists.
        if self.local_remote == "local":
            await self.announce_local_startup()

        # -----------------------------------------------------
        # Main loop
        # -----------------------------------------------------
        try:
            while not self.shutdown:
                await asyncio.sleep(
                    DELAY
                )

                if self.network_type == "IP":
                    await self.read_hiprfisr_messages()

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
                except Exception:
                    pass

            self.alert_senders.clear()

            # Close Running Tasks
            for task in self.child_tasks:
                task.cancel()

            await asyncio.gather(
                *self.child_tasks,
                return_exceptions=True,
            )

            # Shut Down Comms
            await self.shutdown_comms()


    async def read_hiprfisr_messages(self):
        """
        Read messages from the HIPRFISR ZMQ message channel.

        IMPORTANT BEHAVIOR
        -----------------
        - Never blocks the receive loop on long-running actions
        - plugin_action callbacks are spawned as background tasks
        - short control commands (stop, queries, etc.) are awaited normally
        - keeps message reception responsive so STOP works immediately
        """

        # If already terminated, do not enter the loop at all.
        if getattr(self.hiprfisr_socket, "terminated", False):
            return

        # Ensure task tracking list exists
        if not hasattr(self, "child_tasks"):
            self.child_tasks = []

        while True:
            # Graceful exit
            if self.shutdown or getattr(self.hiprfisr_socket, "terminated", False):
                return

            try:
                parsed = await self.hiprfisr_socket.recv_msg()
            except Exception:
                # Socket error: mark terminated and exit the loop
                self.hiprfisr_socket.terminated = True
                return

            if parsed is None:
                # prevent busy loop
                await asyncio.sleep(0.01)
                continue

            msg_type = parsed.get(fissure.comms.MessageFields.TYPE)

            if msg_type != fissure.comms.MessageTypes.COMMANDS:
                continue

            # We have received at least one valid command from HIPRFISR.
            # From this point on, use heartbeat_interval_connected for steady-state heartbeats.
            self.hiprfisr_seen = True

            msg_name = parsed.get(fissure.comms.MessageFields.MESSAGE_NAME)

            # ------------------------------------------------------------
            # LONG-RUNNING COMMANDS → spawn (DO NOT await)
            # ------------------------------------------------------------
            if msg_name in {
                "plugin_action",   # actions like promote_to_soi
            }:
                self.logger.debug(f"Spawning async callback for {msg_name}")

                task = asyncio.create_task(
                    self.hiprfisr_socket.run_callback(self, parsed),
                    name=f"hiprfisr_cb:{msg_name}"
                )

                self.child_tasks.append(task)

                # auto-cleanup finished tasks
                task.add_done_callback(
                    lambda t: self.child_tasks.remove(t)
                    if t in self.child_tasks else None
                )

                continue

            # ------------------------------------------------------------
            # SHORT / CONTROL COMMANDS → await normally
            # (stop_all_plugin_operations MUST be fast)
            # ------------------------------------------------------------
            try:
                await self.hiprfisr_socket.run_callback(self, parsed)
            except Exception:
                self.logger.exception(f"Callback failed for {msg_name}")


    async def send_heartbeat(self, force: bool = False):
        """
        Sends a heartbeat to HIPRFISR.

        Heartbeat is the authoritative liveness signal. For IP nodes, it also
        carries cached node status and cached GPS state when available. It does
        not perform GPS probing.
        """
        if self.network_type != "IP" and self.network_type != "Meshtastic":
            return

        now = time.time()
        last = self.heartbeats["self"]

        heartbeat_interval = (
            self.heartbeat_interval_connected
            if getattr(self, "hiprfisr_seen", False)
            else self.heartbeat_interval
        )

        # Throttle unless explicitly forced
        if not force and (now - last) < heartbeat_interval:
            return

        # Get Sensor Node nickname
        if self.local_remote == "local":
            nickname = "Local Sensor Node"
        else:
            nickname = (
                self.settings_dict
                .get("Sensor Node", {})
                .get("nickname", "-")
            )

        # Build the message
        if self.network_type == "IP":
            gps_position = getattr(self, "gps_position", {}) or {}

            hb = {
                fissure.comms.MessageFields.IDENTIFIER: self.identifier,
                fissure.comms.MessageFields.MESSAGE_NAME: fissure.comms.MessageFields.HEARTBEAT,
                fissure.comms.MessageFields.TIME: now,
                fissure.comms.MessageFields.IP: self.node_ip_address,
                fissure.comms.MessageFields.INTERVAL: heartbeat_interval,
                fissure.comms.MessageFields.PARAMETERS: {
                    "network_type": self.network_type,
                    "nickname": nickname,
                    "hiprfisr_ip_address": self.hiprfisr_ip_address,
                    "node_ip_address": self.node_ip_address,

                    # Unified node state. HIPRFISR will consume these in the next step.
                    "status": getattr(self, "current_status", "unknown"),
                    "version": getattr(self, "version_string", ""),
                    "gps_source": getattr(self, "gps_source", ""),
                    "gps_valid": bool(getattr(self, "gps_valid", False)),
                    "gps_time": getattr(self, "gps_time", None),
                    "gps_stale": bool(getattr(self, "gps_stale", False)),
                    "lat": gps_position.get("latitude"),
                    "lon": gps_position.get("longitude"),
                    "alt": gps_position.get("altitude"),
                }
            }

            await self.hiprfisr_socket.send_heartbeat(hb)

        elif self.network_type == "Meshtastic":
            PARAMETERS = {
                "msg": [
                    self.assigned_id,
                    heartbeat_interval,
                    nickname,
                    now,
                ]
            }

            heartbeat_message = {
                fissure.comms.MessageFields.SOURCE: self.uuid,
                fissure.comms.MessageFields.DESTINATION: fissure.comms.Identifiers.HIPRFISR_LT,
                fissure.comms.MessageFields.MESSAGE_NAME: "recvMeshtasticHeartbeatsLT",
                fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
            }

            await self.hiprfisr_socket.send_heartbeat(heartbeat_message)

        # Update Heartbeat Time
        self.heartbeats["self"] = now
        self.logger.debug(f"Sent heartbeat at {now} force={force}")


    async def announce_local_startup(self):
        """
        Local-only startup announce.

        Sends a small burst of heartbeats so the local node appears in HIPRFISR
        and Dashboard without waiting for the normal heartbeat interval.
        """
        if self.local_remote != "local":
            return

        if self.network_type != "IP":
            return

        for _ in range(3):
            try:
                await self.send_heartbeat(force=True)
            except Exception:
                self.logger.debug("Local startup heartbeat failed.", exc_info=True)

            await asyncio.sleep(0.15)


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
    

    async def flowGraphError(self, error=""):
        """ Sends a message back to the HIPRFISR that there was an error with a flow graph.
        """
        # Send Message
        PARAMETERS = {
            "error": error
        }
        msg = {
                    fissure.comms.MessageFields.IDENTIFIER: self.identifier,
                    fissure.comms.MessageFields.MESSAGE_NAME: "flowGraphError",
                    fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
        }
        await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


    async def flowGraphFinished(self, flow_graph_type, read_filepath="", return_filepath=""):
        """ Signals to all components that the flow graph has finished.
        """
        # Send Message
        if flow_graph_type == "PD":
            PARAMETERS = {
                "category": "PD"
            }
            msg = {
                        fissure.comms.MessageFields.IDENTIFIER: self.identifier,
                        fissure.comms.MessageFields.MESSAGE_NAME: "flowGraphFinished",
                        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
            }
            await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)
        elif flow_graph_type == "Attack":
            PARAMETERS = {
                "category": "Attack"
            }
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
                PARAMETERS = {
                    "operation": "IQ", 
                    "filepath": return_filepath, 
                    "data": get_data
                }
                msg = {
                            fissure.comms.MessageFields.IDENTIFIER: self.identifier,
                            fissure.comms.MessageFields.MESSAGE_NAME: "saveFile",
                            fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
                }
                await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)  # Replace with data socket connection
            
            # Local Sensor Node
            else:
                msg = {
                            fissure.comms.MessageFields.IDENTIFIER: self.identifier,
                            fissure.comms.MessageFields.MESSAGE_NAME: "flowGraphFinishedIQ",
                }
                await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)
        elif flow_graph_type == "IQ Playback":
            msg = {
                        fissure.comms.MessageFields.IDENTIFIER: self.identifier,
                        fissure.comms.MessageFields.MESSAGE_NAME: "flowGraphFinishedIQ_Playback",
            }
            await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)
        elif flow_graph_type == "Sniffer - Stream":
            PARAMETERS = {"category": "Stream"}
            msg = {
                        fissure.comms.MessageFields.IDENTIFIER: self.identifier,
                        fissure.comms.MessageFields.MESSAGE_NAME: "flowGraphFinishedSniffer",
                        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
            }
            await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)
        elif flow_graph_type == "Sniffer - Tagged Stream":
            PARAMETERS = {"category": "Tagged Stream"}
            msg = {
                        fissure.comms.MessageFields.IDENTIFIER: self.identifier,
                        fissure.comms.MessageFields.MESSAGE_NAME: "flowGraphFinishedSniffer",
                        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
            }
            await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)
        elif flow_graph_type == "Sniffer - Message/PDU":
            PARAMETERS = {"category": "Message/PDU"}
            msg = {
                        fissure.comms.MessageFields.IDENTIFIER: self.identifier,
                        fissure.comms.MessageFields.MESSAGE_NAME: "flowGraphFinishedSniffer",
                        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
            }
            await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


    async def flowGraphStarted(self, flow_graph_type):
        """ Signals to all components that the flow graph has started.
        """
        # Send Message
        if flow_graph_type == "PD":
            PARAMETERS = {"category": "PD"}
            msg = {
                        fissure.comms.MessageFields.IDENTIFIER: self.identifier,
                        fissure.comms.MessageFields.MESSAGE_NAME: "flowGraphStarted",
                        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
            }
            await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)
        elif flow_graph_type == "Attack":
            PARAMETERS = {"category": "Attack"}
            msg = {
                        fissure.comms.MessageFields.IDENTIFIER: self.identifier,
                        fissure.comms.MessageFields.MESSAGE_NAME: "flowGraphStarted",
                        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
            }
            await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)
        elif flow_graph_type == "IQ":
            msg = {
                        fissure.comms.MessageFields.IDENTIFIER: self.identifier,
                        fissure.comms.MessageFields.MESSAGE_NAME: "flowGraphStartedIQ",
            }
            await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)
        elif flow_graph_type == "IQ Playback":
            msg = {
                        fissure.comms.MessageFields.IDENTIFIER: self.identifier,
                        fissure.comms.MessageFields.MESSAGE_NAME: "flowGraphStartedIQ_Playback",
            }
            await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)
        elif flow_graph_type == "Sniffer - Stream":
            PARAMETERS = {"category": "Stream"}
            msg = {
                        fissure.comms.MessageFields.IDENTIFIER: self.identifier,
                        fissure.comms.MessageFields.MESSAGE_NAME: "flowGraphStartedSniffer",
                        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
            }
            await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)
        elif flow_graph_type == "Sniffer - Tagged Stream":
            PARAMETERS = {"category": "Tagged Stream"}
            msg = {
                        fissure.comms.MessageFields.IDENTIFIER: self.identifier,
                        fissure.comms.MessageFields.MESSAGE_NAME: "flowGraphStartedSniffer",
                        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
            }
            await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)
        elif flow_graph_type == "Sniffer - Message/PDU":
            PARAMETERS = {"category": "Message/PDU"}
            msg = {
                        fissure.comms.MessageFields.IDENTIFIER: self.identifier,
                        fissure.comms.MessageFields.MESSAGE_NAME: "flowGraphStartedSniffer",
                        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
            }
            await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


    def runPythonScriptThread(self, stop_event, file_type, flow_graph_filename, variable_names, variable_values, run_with_sudo, autorun_index, trigger_action):
        """ Runs the attack flow graph in the new thread.
        """
        # Return Different Status Messages for Autorun
        if autorun_index == -1:
            # Stop Any Running Attack Flow Graphs
            try:
                self.attackFlowGraphStop(None)
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
                asyncio.run(self.flowGraphStarted("Attack"))  # Signals to other components
                self.attack_script_name = flow_graph_filename

                # In New Terminal
                if trigger_action == False:
                    self.alert_senders[autorun_index] = alertSender(osCommandString, self.identifier, self.identifier, self.hiprfisr_socket, self.gps_position, self.logger, self.network_type)
                    self.alert_senders[autorun_index].thread.join()

                    # In FISSURE Dashboard
                    #proc = subprocess.Popen(osCommandString + " &", shell=True)#, stderr=subprocess.PIPE)
                    #output, error = proc.communicate()
                    
                    # Restore the Start Button for Scripts
                    if self.network_type == "IP":
                        asyncio.run(self.flowGraphFinished("Attack"))
                        asyncio.run(self.multiStageAttackFinished())

                # As a Blocking Trigger
                else:               
                    result = subprocess.run(osCommandString, shell=True, capture_output=True, text=True)
                    if result.returncode == 0:
                        self.trigger_done.set()                

            # Error Loading Flow Graph
            except Exception as e:
                asyncio.run(self.flowGraphStarted("Attack"))
                asyncio.run(self.flowGraphFinished("Attack"))
                asyncio.run(self.flowGraphError(str(e)))
                asyncio.run(self.multiStageAttackFinished())              
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
                self.alert_senders[autorun_index] = alertSender(osCommandString, self.identifier, node_uid, self.hiprfisr_socket, self.gps_position, self.logger, self.network_type)
                self.alert_senders[autorun_index].thread.join()

                # In FISSURE Dashboard
                #proc = subprocess.Popen(osCommandString + " &", shell=True)#, stderr=subprocess.PIPE)
                #output, error = proc.communicate()
                
                # Restore the Start Button for Scripts
                if self.network_type == "IP":
                    asyncio.run(self.flowGraphFinished("Attack"))
                    asyncio.run(self.multiStageAttackFinished())

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
        else:
            if flow_graph == "Protocol Discovery":
                getattr(self.pdflowtoexec,formatted_name)(value)
            elif flow_graph == "Attack":
                getattr(self.attackflowtoexec,formatted_name)(value)
            elif flow_graph == "Sniffer":
                getattr(self.snifferflowtoexec,formatted_name)(value)


    ######################  Attack Flow Graphs  ########################

    def attackFlowGraphStart(self, flow_graph_filepath="", variable_names=[], variable_values=[], file_type="", run_with_sudo=False, autorun_index=0):
        """ Runs the flow graph with the specified file path.
        """
        # Make a new Thread
        stop_event = threading.Event()

        if file_type == "Flow Graph":
            c_thread = threading.Thread(target=self.runFlowGraphThread, args=(stop_event, flow_graph_filepath, variable_names, variable_values, autorun_index))
        elif file_type == "Flow Graph - GUI":
            c_thread = threading.Thread(target=self.runFlowGraphGUI_Thread, args=(stop_event, flow_graph_filepath, variable_names, variable_values, autorun_index))
        # Python2, Python3
        else:
            c_thread = threading.Thread(target=self.runPythonScriptThread, args=(stop_event, file_type, flow_graph_filepath, variable_names, variable_values, run_with_sudo, autorun_index, False))  # backticks execute commands

        c_thread.daemon = True
        c_thread.start()
    

    def attackFlowGraphStop(self, parameter="", autorun_index=0):
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


    def runFlowGraphThread(self, stop_event, flow_graph_filename, variable_names, variable_values, autorun_index):
        """ Runs the attack script in the new thread.
        """
        # Return Different Status Messages for Autorun
        if autorun_index == -1:
            try:
                # Stop Any Running Attack Flow Graphs
                try:
                    self.attackFlowGraphStop(None)
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
                asyncio.run(self.flowGraphStarted("Attack"))  # Signals to other components
                    
                # Physical Layer Fuzzing Can Now Commence
                self.attack_flow_graph_loaded = True
                
                # Let it Run
                self.attackflowtoexec.wait()
                
                # Signal on the PUB that the Attack Flow Graph is Finished
                asyncio.run(self.flowGraphFinished("Attack"))
                        
            # Error Loading Flow Graph
            except Exception as e:
                asyncio.run(self.flowGraphStarted("Attack"))
                asyncio.run(self.flowGraphFinished("Attack"))
                asyncio.run(self.flowGraphError(str(e)))
                asyncio.run(self.multiStageAttackFinished())
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


    def runFlowGraphGUI_Thread(self, stop_event, flow_graph_filename, variable_names, variable_values, autorun_index):
        """ Runs the attack flow graph in the new thread.
        """
        # Normal
        if autorun_index == -1:
        
            # # Stop Any Running Attack Flow Graphs
            # try:
                # self.attackFlowGraphStop(None)
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
                asyncio.run(self.flowGraphStarted("Attack"))  # Signals to other components
                self.attack_script_name = flow_graph_filename
                time.sleep(4.8)  # Need a way to detect flow graph/hardware is running when called via Python
                self.attack_flow_graph_loaded = True

            # Error Loading Flow Graph
            except Exception as e:
                asyncio.run(self.flowGraphStarted("Attack"))
                asyncio.run(self.flowGraphFinished("Attack"))
                asyncio.run(self.flowGraphError(str(e)))
                asyncio.run(self.multiStageAttackFinished())
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
            

    ##############  IQ Playback Flow Graphs  #############
    
    def iqFlowGraphThread(
        self,
        flow_graph_filename,
        variable_names,
        variable_values,
    ):
        """
        Run an IQ playback flow graph in the worker thread.
        """
        try:
            self.iqFlowGraphStop(None)
        except Exception:
            pass

        try:
            loadedmod, class_name = (
                self.overwriteFlowGraphVariables(
                    flow_graph_filename,
                    variable_names,
                    variable_values,
                )
            )

            self.iqflowtoexec = getattr(
                loadedmod,
                class_name,
            )()

            self.iqflowtoexec.start()

            asyncio.run(
                self.flowGraphStarted(
                    "IQ Playback"
                )
            )

            self.iqflowtoexec.wait()

            asyncio.run(
                self.flowGraphFinished(
                    "IQ Playback"
                )
            )

        except Exception:
            asyncio.run(
                self.flowGraphStarted(
                    "IQ Playback"
                )
            )

            asyncio.run(
                self.flowGraphFinished(
                    "IQ Playback"
                )
            )

            try:
                self.iqFlowGraphStop(None)
            except Exception:
                pass


    def iqFlowGraphStop(self, parameter=""):
        """ Stop the currently running IQ flow graph.
        """
        self.iqflowtoexec.stop()
        self.iqflowtoexec.wait()
        del self.iqflowtoexec  # Free up the ports


    #######################  Protocol Discovery  #######################

    def stopPD(self):
        """
        Stops PD processing of bits by closing the ZMQ SUB socket.
        """
        # Stop Operations
        self.logger.info("PD: Stopping Protocol Discovery...")
        self.running_PD = False
        
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


    def protocolDiscoveryFG_ThreadStart(self, flow_graph_filename, variable_names, variable_values):
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
            asyncio.run(self.flowGraphStarted("PD"))  # Signals to other components
            self.pdflowtoexec.wait()

            # Signal on the PUB that the PD Flow Graph is Finished
            asyncio.run(self.flowGraphFinished("PD"))

        # Error Loading Flow Graph
        except Exception as e:
            asyncio.run(self.flowGraphStarted("PD"))
            asyncio.run(self.flowGraphFinished("PD"))
            asyncio.run(self.flowGraphError(str(e)))


    ######################  Sniffer Flow Graphs  #######################

    def snifferFlowGraphThread(self, flow_graph_filename, variable_names, variable_values):
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
                asyncio.run(self.flowGraphStarted("Sniffer - Stream"))
            elif "Sniffer_tagged_stream" in flow_graph_filename:
                asyncio.run(self.flowGraphStarted("Sniffer - Tagged Stream"))
            elif "Sniffer_async" in flow_graph_filename:
                asyncio.run(self.flowGraphStarted("Sniffer - Message/PDU"))
            self.snifferflowtoexec.wait()

        # Error Loading Flow Graph
        except Exception as e:
            if "Sniffer_stream.py" in flow_graph_filename:
                asyncio.run(self.flowGraphStarted("Sniffer - Stream"))
                asyncio.run(self.flowGraphFinished("Sniffer - Stream"))
            elif "Sniffer_tagged_stream.py" in flow_graph_filename:
                asyncio.run(self.flowGraphStarted("Sniffer - Tagged Stream"))
                asyncio.run(self.flowGraphFinished("Sniffer - Tagged Stream"))
            elif "Sniffer_async.py" in flow_graph_filename:
                asyncio.run(self.flowGraphStarted("Sniffer - Message/PDU"))
                asyncio.run(self.flowGraphFinished("Sniffer - Message/PDU"))

            asyncio.run(self.flowGraphError(str(e)))


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
            asyncio.run(self.flowGraphStarted("Attack"))
        # elif fissure_event == "Multi-Stage Attack":
            # asyncio.run(self.flowGraphStarted("Attack"))
        # elif fissure_event == "Archive Replay":
            # asyncio.run(self.flowGraphStarted("Archive"))
        # elif fissure_event == "Autorun Playlist":
            # asyncio.run(self.flowGraphStarted("Attack"))

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
                asyncio.run(self.flowGraphFinished("Attack"))
            elif fissure_event == "Multi-Stage Attack":
                asyncio.run(self.multiStageAttackFinished())
            elif fissure_event == "Autorun Playlist":
                pass

        # Trigger Done
        elif self.trigger_done.is_set():
            self.logger.info("Triggers Complete.")
    
            # Run the Event
            if fissure_event == "Single-Stage Attack":
                self.logger.info("Starting Single-Stage Attack...")
                self.attackFlowGraphStart(event_values[0], event_values[1], event_values[2], event_values[3], event_values[4], event_values[5])
           
            elif fissure_event == "Multi-Stage Attack":
                self.logger.info("Starting Multi-Stage Attack...")
                self.multiStageAttackStart(event_values[0], event_values[1], event_values[2], event_values[3], event_values[4], event_values[5], event_values[6])
                #self.multiStageAttackStart(filenames, variable_names, variable_values, durations, repeat, file_types, autorun_index)

            elif fissure_event == "Autorun Playlist":
                self.logger.info("Starting Autorun Playlist...")
                playlist_dict = event_values[0]
                
                # Run at Startup
                # Read the Autorun Playlist File
                if not playlist_dict:
                    filename = os.path.join(fissure.utils.SENSOR_NODE_DIR, "Autorun_Playlists", "default.yaml")
                    with open(filename) as yaml_library_file:
                        playlist_dict = yaml.load(yaml_library_file, yaml.FullLoader)
                
                # Passed in from Dashboard
                if self.hiprfisr_socket:
                
                    # Send the Message
                    asyncio.run(self.autorunPlaylistStarted())
                
                # Make a New Thread
                self.autorun_playlist_stop_event = threading.Event()
                self.autorun_playlist_thread = threading.Thread(target=self.autorunPlaylistThreadStart, args=[playlist_dict])
                self.autorun_playlist_thread.start()
                

    async def autorunPlaylistStarted(self):
        """ Sends the Autorun Playlist Started message to the HIPRFISR/Dashboard.
        """
        # Send the Message
        if self.network_type == "IP":
            msg = {
                        fissure.comms.MessageFields.IDENTIFIER: self.identifier,
                        fissure.comms.MessageFields.MESSAGE_NAME: "autorunPlaylistStarted",
            }
            await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)
    

    #######################  Physical Fuzzing  #########################


    def physicalFuzzingThreadStart(self, fuzzing_variables, fuzzing_type, fuzzing_min, fuzzing_max, fuzzing_update_period, fuzzing_seed_step):
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
    
    def multiStageAttackStart(self, filenames=[], variable_names=[], variable_values=[], durations=[], repeat=False, file_types=[], autorun_index=0):
        """ Starts a new thread for running two flow graphs. A new thread is created to allow the Sensor Node to still perform normal functionality while waiting for an attack to finish.
        """
        # Make a New Thread
        if autorun_index == -1:
            self.multi_stage_stop_event = threading.Event()
        else:
            self.autorun_multistage_manager[autorun_index] = threading.Event()
        multi_stage_thread = threading.Thread(target=self.multiStageAttackThreadStart, args=(filenames, variable_names, variable_values, durations, repeat, file_types, autorun_index))

        multi_stage_thread.start()
    

    def multiStageAttackThreadStart(self, filenames, variable_names, variable_values, durations, repeat, file_types, autorun_index):
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
                        c_thread = threading.Thread(
                            target=self.runFlowGraphThread, 
                            args=(stop_event, flow_graph_filename, variable_names[n], variable_values[n], autorun_index)
                        )
                    elif file_types[n] == "Flow Graph - GUI":
                        flow_graph_filename = filenames[n]                        
                        c_thread = threading.Thread(
                            target=self.runFlowGraphGUI_Thread, 
                            args=(stop_event, flow_graph_filename, variable_names[n], variable_values[n], autorun_index)
                        )
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
                        c_thread = threading.Thread(
                            target=self.runPythonScriptThread, 
                            args=(stop_event, file_types[n], filenames[n], variable_names[n], variable_values[n], run_with_sudo, autorun_index, False)
                        )

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
                        self.attackFlowGraphStop("Flow Graph", autorun_index)
                        time.sleep(0.5)  # LimeSDR needs time to stop or there will be a busy error
                    elif file_types[n] == "Flow Graph - GUI":
                        self.attackFlowGraphStop("Flow Graph - GUI", autorun_index)
                        time.sleep(0.5)  # LimeSDR needs time to stop or there will be a busy error
                    else:
                        self.attackFlowGraphStop("Python Script", autorun_index)

                    # Break if Stop was Pressed while Running Flow Graph
                    if self.multi_stage_stop_event.is_set():
                        break

                # End the thread
                if repeat == False:
                    self.multiStageAttackStop(autorun_index)
        
        # Autorun
        else:            
            while(not self.autorun_multistage_manager[autorun_index].is_set()):
                for n in range(0,len(filenames)):

                    # Make a new Thread
                    stop_event = threading.Event()
                    if file_types[n] == "Flow Graph":
                        flow_graph_filename = filenames[n].replace(".py","")
                        c_thread = threading.Thread(
                            target=self.runFlowGraphThread, 
                            args=(stop_event, flow_graph_filename, variable_names[n], variable_values[n], autorun_index)
                        )
                    elif file_types[n] == "Flow Graph - GUI":
                        flow_graph_filename = filenames[n]
                        c_thread = threading.Thread(
                            target=self.runFlowGraphGUI_Thread, 
                            args=(stop_event, flow_graph_filename, variable_names[n], variable_values[n], autorun_index)
                        )
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
                        c_thread = threading.Thread(
                            target=self.runPythonScriptThread, 
                            args=(stop_event, file_types[n], filenames[n], variable_names[n], variable_values[n], run_with_sudo, autorun_index, False)
                        )

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
                        self.attackFlowGraphStop("Flow Graph", autorun_index)
                        time.sleep(0.5)  # LimeSDR needs time to stop or there will be a busy error
                    elif file_types[n] == "Flow Graph - GUI":
                        self.attackFlowGraphStop("Flow Graph - GUI", autorun_index)
                        time.sleep(0.5)  # LimeSDR needs time to stop or there will be a busy error
                    else:
                        self.attackFlowGraphStop("Python Script", autorun_index)

                    # Break if Stop was Pressed while Running Flow Graph
                    if self.autorun_multistage_manager[autorun_index].is_set():
                        break

                # End the thread
                if repeat == False:
                    self.multiStageAttackStop(autorun_index)


    async def multiStageAttackFinished(self):
        """ Signals to the other components that the multi-stage attack has finished.
        """
        # Send the Message
        msg = {
                    fissure.comms.MessageFields.IDENTIFIER: self.identifier,
                    fissure.comms.MessageFields.MESSAGE_NAME: "multiStageAttackFinished",
        }
        await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)
        

    def multiStageAttackStop(self, autorun_index=0):
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
                asyncio.run(self.multiStageAttackFinished())

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
  
    
    #######################  Autorun Playlists  ##########################

    def autorunPlaylistStart(self, playlist_dict={}, trigger_values=[]):
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
            if self.hiprfisr_socket:
                # Send the Message
                asyncio.run(self.autorunPlaylistStarted())
            
            # Make a New Thread
            self.autorun_playlist_stop_event = threading.Event()
            self.autorun_playlist_thread = threading.Thread(target=self.autorunPlaylistThreadStart, args=[playlist_dict])
            self.autorun_playlist_thread.start()
        else:            
            # Make a new Trigger Thread
            if self.settings_dict['Sensor Node']['autorun'] == True:
                autorun_index = -2  # Autorun on start with trigger
            else:
                autorun_index = -1  # Autorun through Dashboard with trigger
            unused_stop_event = threading.Event()
            fissure_event_values = [playlist_dict]
            c_thread = threading.Thread(target=self.triggerStart, args=(trigger_values, "Autorun Playlist", fissure_event_values, autorun_index))
            c_thread.daemon = True
            c_thread.start()


    def autorunPlaylistExecute(self, playlist_filename=""):
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
            self.autorunPlaylistStart(playlist_dict, trigger_dict)


    def autorunPlaylistThreadStart(self, playlist_dict):
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
                                            self.attackFlowGraphStart(get_details[4], get_variable_names, get_variable_values, get_details[5], get_details[6], playlist_index)
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
                                        self.attackFlowGraphStop(get_file_type, playlist_index)
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
                                            self.multiStageAttackStart(get_filenames, get_variable_names, get_variable_values, get_durations, autorun_playlist_repeat[playlist_index], get_file_types, playlist_index)
                                            autorun_playlist_start_times[playlist_index] = time.time() + float(attack_dict['timeout_seconds'])
                                            autorun_playlist_started[playlist_index] = True
                                            autorun_playlist_first_time[playlist_index] = False
                                    
                                # Timeout, Stop Attack
                                else:
                                    if autorun_playlist_started[playlist_index] == True:
                                        self.logger.info("Stop it")
                                        self.multiStageAttackStop(playlist_index)
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
        if self.hiprfisr_socket:
            asyncio.run(self.autorunPlaylistFinished())

                
    async def autorunPlaylistFinished(self):
        """ Sends the autorun playlist finished message to the HIPRFISR/Dashboard.
        """
        # Send the Message
        if self.network_type == "IP":
            msg = {
                        fissure.comms.MessageFields.IDENTIFIER: self.identifier,
                        fissure.comms.MessageFields.MESSAGE_NAME: "autorunPlaylistFinished",
            }
            await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


    async def gpsUpdate(self, gps_data):
        """
        Cache GPS updates.

        IP nodes no longer send node track CoT/TAK directly from this function.
        Heartbeat carries the cached GPS/status state to HIPRFISR, and HIPRFISR
        publishes node CoT from its normalized node state.

        Meshtastic is left on the existing direct TAK-return path for now.
        """
        now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

        # ---------------------------------------------------------
        # UPDATE LOCAL GPS CACHE
        # ---------------------------------------------------------
        if gps_data:
            for key in ["latitude", "longitude", "altitude"]:
                value = gps_data.get(key)
                if value is not None:
                    self.gps_position[key] = value

            self.gps_position["latitude_ddm"], self.gps_position["longitude_ddm"] = \
                fissure.utils.common.decimal_to_ddm(
                    self.gps_position["latitude"],
                    self.gps_position["longitude"]
                )

            self.gps_valid = True
            self.gps_time = now_iso
            self.gps_stale = False

            self.logger.info(f"Updating GPS position: {self.gps_position}")

        else:
            # Failed GPS probe. Keep fallback/last-known position available,
            # but mark it stale so HIPRFISR can report the distinction.
            self.gps_valid = bool(
                self.gps_position.get("latitude") is not None and
                self.gps_position.get("longitude") is not None
            )
            self.gps_stale = True

            if not getattr(self, "gps_time", None):
                self.gps_time = now_iso

            self.logger.info(
                f"Failed to update GPS position. Keeping last position: {self.gps_position}"
            )

        # ---------------------------------------------------------
        # IP: CACHE ONLY
        # ---------------------------------------------------------
        if self.network_type == "IP":
            return

        # ---------------------------------------------------------
        # MESHTASTIC: KEEP EXISTING DIRECT PATH FOR NOW
        # ---------------------------------------------------------
        if self.network_type == "Meshtastic":
            PARAMETERS = {
                "msg": [
                    "track",
                    now_iso,
                    self.uuid,
                    self.gps_position.get("latitude", 0.0),
                    self.gps_position.get("longitude", 0.0),
                    None,
                    self.current_status,
                    self.version_string,
                ]
            }

            msg = {
                fissure.comms.MessageFields.SOURCE: self.assigned_id,
                fissure.comms.MessageFields.DESTINATION: fissure.comms.Identifiers.HIPRFISR_LT,
                fissure.comms.MessageFields.MESSAGE_NAME: "takReturnLT",
                fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
            }

            await self.hiprfisr_socket.send_msg(
                fissure.comms.MessageTypes.COMMANDS,
                msg
            )

    
    async def publish_status_to_hiprfisr(self, status: str):
        """
        Publish node status.

        For IP nodes, status rides heartbeat. Force a heartbeat so status changes
        are reported immediately instead of waiting for the next heartbeat period.

        Meshtastic keeps the previous GPS/TAK-return behavior for now.
        """
        self.current_status = status

        if self.network_type == "IP":
            await self.send_heartbeat(force=True)
            return

        if self.network_type == "Meshtastic":
            await self.gpsUpdate(None)


    def get_local_ip_for_remote(self, remote_ip):
        """
        Returns the local interface IP address used to reach remote_ip.

        This is the sensor node's own IP address from the perspective of the route
        to HIPRFISR. It does not actually send UDP traffic.
        """
        if not remote_ip:
            return ""

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.connect((remote_ip, 9))
            local_ip = sock.getsockname()[0]
            sock.close()

            return local_ip

        except Exception:
            return ""


    def update_ip_address_settings(self):
        """
        Updates cached HIPRFISR and node IP address values from settings.

        hiprfisr_ip_address:
            IP address the Sensor Node connects to.

        node_ip_address:
            IP address displayed by HIPRFISR/Dashboard for this Sensor Node.
            If set to "auto", detect the local route IP used to reach HIPRFISR.
        """
        sensor_node_settings = self.settings_dict.get("Sensor Node", {})

        if self.local_remote == "local":
            self.network_type = "IP"
            self.hiprfisr_ip_address = "ipc"
            self.node_ip_address = "ipc"
            self.settings_dict["Sensor Node"]["nickname"] = "Local Sensor Node"
            return

        self.network_type = str(
            sensor_node_settings.get("network_type", "IP")
        )

        self.hiprfisr_ip_address = str(
            sensor_node_settings.get(
                "hiprfisr_ip_address",
                sensor_node_settings.get("ip_address", "")
            )
        ).strip()

        node_ip_setting = str(
            sensor_node_settings.get("node_ip_address", "auto")
        ).strip()

        if node_ip_setting and node_ip_setting.lower() != "auto":
            self.node_ip_address = node_ip_setting
        else:
            self.node_ip_address = self.get_local_ip_for_remote(
                self.hiprfisr_ip_address
            )

        if not self.node_ip_address:
            self.node_ip_address = "unknown"

        print(f"hiprfisr_ip_address={self.hiprfisr_ip_address}")
        print(f"node_ip_setting={node_ip_setting}")
        print(f"auto node_ip_address={self.node_ip_address}")

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
            

    async def _fetch_gps_once(self, gps_source, meshtastic_node):
        gps_data = None

        if gps_source == "Meshtastic":
            if meshtastic_node:
                gps_data = await self.fetch_gps_from_meshtastic(meshtastic_node)

        elif gps_source == "Meshtastic New Connection":
            if meshtastic_node:
                async with self.meshtastic_lock:
                    gps_data = await self.fetch_gps_from_meshtastic_new_connection(meshtastic_node)

        elif gps_source == "gpsd":
            gps_data = await self.fetch_gps_from_gpsd()

        elif gps_source == "saved":
            gps_data = await self.fetch_gps_from_saved()

        elif gps_source == "internet":
            gps_data = await self.fetch_gps_from_internet()

        return gps_data


    async def periodic_gps_update(self, gps_source, meshtastic_node):
        """Periodically updates GPS position from available sources."""
        self.running = True
        while self.running:
            gps_data = await self._fetch_gps_once(gps_source, meshtastic_node)

            # Send new GPS data to the callback function
            await self.gps_callback(gps_data)

            await asyncio.sleep(self.gps_update_interval_seconds)


    async def send_gps_update_now(self, gps_source, meshtastic_node):
        """
        Fetch GPS once and immediately invoke the callback.
        """
        gps_data = await self._fetch_gps_once(gps_source, meshtastic_node)
        await self.gps_callback(gps_data)


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
