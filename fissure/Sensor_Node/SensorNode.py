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
from contextvars import ContextVar


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
    sys.path.insert(0, os.path.join(fissure.utils.FISSURE_ROOT, "Flow Graph Library", "maint-3.8", "IQ Flow Graphs"))
    sys.path.insert(0, os.path.join(fissure.utils.FISSURE_ROOT, "Flow Graph Library", "maint-3.8", "Archive Flow Graphs"))
    sys.path.insert(0, os.path.join(fissure.utils.FISSURE_ROOT, "Flow Graph Library", "maint-3.8", "Sniffer Flow Graphs"))
    add_subdirectories_to_path(os.path.join(fissure.utils.FISSURE_ROOT, "Flow Graph Library", "maint-3.8", "TSI Flow Graphs"))
elif "maint-3.10" in fissure.utils.get_fg_library_dir(fissure.utils.get_os_info()):
    sys.path.insert(0, os.path.join(fissure.utils.FISSURE_ROOT, "Flow Graph Library", "maint-3.10", "PD Flow Graphs"))
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

        self.running_PD = False
        self.pd_bits_socket = None

        self.autorun_boot_requested = bool(self.settings_dict["Sensor Node"].get("autorun", False))

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

        self.autorun_state = "Idle"
        self.autorun_source = ""
        self.autorun_message = ""
        self.autorun_run_id = ""
        self.autorun_task = None
        self.autorun_stop_event = None
        self.autorun_detector_event = None
        self.autorun_detector_operation_ids = set()
        self.autorun_scheduler_tasks = set()
        self.autorun_action_tasks = set()
        self._operation_owner_context = ContextVar(f"sensor_node_operation_owner_{self.uuid}", default="")
        self._operation_owner_ids = {}

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

        await self._handle_autorun_detection(detection)

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


    def _autorun_node_status(self):
        """Return the node status that should be visible when no plugin operation is active."""
        if self.autorun_state == "Waiting":
            return "Autorun: Waiting"
        if self.autorun_state in {"Running", "Stopping"}:
            return "Autorun"
        return "Idle"


    async def _request_plugin_operation_stop(self, operation_id, op):
        """Request one plugin operation stop exactly once and wait for it to finish."""
        if not op:
            return

        stop_task = op.get("stop_task")
        if stop_task is None:
            stop_callback = op.get("stop")
            if not callable(stop_callback):
                self.logger.error(f"No callable stop method for operation {operation_id}.")
                return

            async def request_stop():
                try:
                    await stop_callback()
                except asyncio.CancelledError:
                    raise
                except Exception:
                    self.logger.error(
                        f"Error stopping plugin operation {operation_id}:\n{traceback.format_exc()}"
                    )

            stop_task = asyncio.create_task(request_stop(), name=f"op_stop:{operation_id}")
            op["stop_task"] = stop_task

        await asyncio.gather(stop_task, return_exceptions=True)


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
            s = (status_text or "").strip() or self._autorun_node_status()

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
            "stop_task": None,
            "finalize_task": None,
        }

        operation_owner = str(self._operation_owner_context.get() or "").strip()
        if operation_owner:
            self._operation_owner_ids.setdefault(operation_owner, set()).add(operation_id)
            self.operations[operation_id]["owner"] = operation_owner

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
            except asyncio.CancelledError:
                # Process/event-loop shutdown can cancel operation tasks before the
                # normal stop path runs. Request the operation stop exactly once
                # before teardown so stop and teardown never race each other.
                await self._request_plugin_operation_stop(
                    operation_id,
                    self.operations.get(operation_id),
                )
                raise
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
                    if err_str:
                        await _set_status_edge("Error")
                    else:
                        await _set_status_edge(self._autorun_node_status())

                if operation_owner:
                    owner_operations = self._operation_owner_ids.get(operation_owner)
                    if owner_operations is not None:
                        owner_operations.discard(operation_id)
                        if not owner_operations:
                            self._operation_owner_ids.pop(operation_owner, None)

        finalize_task = asyncio.create_task(_finalize_operation(), name=f"op_finalize:{operation_id}")
        self.operations[operation_id]["finalize_task"] = finalize_task

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
        component: object,  # Required for callback system
        operation_id: str
    ) -> None:
        """
        Stop one plugin operation and wait for its finalizer to finish.

        The run_plugin_operation finalizer remains the only owner of teardown and
        registry removal. A shared stop task guarantees that normal Stop, Autorun
        shutdown, and process cancellation cannot invoke stop() concurrently.
        """
        self.logger.info(f"Stopping plugin operation with ID: {operation_id}")

        op = self.operations.get(operation_id)
        if not op:
            self.logger.debug(f"Operation ID {operation_id} is no longer active.")
            return

        await self._request_plugin_operation_stop(operation_id, op)
        self.logger.info(f"Operation {operation_id} stop requested.")

        current_task = asyncio.current_task()
        operation_task = op.get("task")
        if operation_task is not None and operation_task is not current_task:
            await asyncio.gather(operation_task, return_exceptions=True)

        finalize_task = op.get("finalize_task")
        if (
            finalize_task is not None
            and finalize_task is not current_task
            and operation_task is not current_task
        ):
            await asyncio.gather(finalize_task, return_exceptions=True)


    async def stop_all_plugin_operations(
        self,
        component: object,  # Required for callback system
        requester_uid: str,
        requester_type: str
    ) -> None:
        """
        Stop all plugin activity on the Sensor Node.

        An active Autorun playlist is stopped first so detector gates, delayed
        rows, repeating schedulers, and pending action launches cannot create new
        operations after the current operation set has been stopped.
        """
        self.logger.info("Stopping all plugin operations.")

        if self.autorun_state in {"Waiting", "Running", "Stopping"}:
            await self.stop_autorun_playlist()

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
        """Run the Sensor Node lifecycle and optional boot Autorun."""
        self.logger.info("=== STARTING SENSOR NODE ===")

        heartbeat_task = None

        async def start_boot_autorun():
            """Start default.yaml after the configured boot-only Autorun delay."""
            autorun_delay = self.settings_dict["Sensor Node"].get("autorun_delay_seconds", 0)

            try:
                autorun_delay = max(0.0, float(autorun_delay or 0))
            except (TypeError, ValueError):
                self.logger.warning(
                    f"Invalid autorun_delay_seconds value {autorun_delay!r}; using 0 seconds."
                )
                autorun_delay = 0.0

            if autorun_delay > 0:
                self.logger.info(
                    f"Boot Autorun waiting {autorun_delay:g} seconds before starting default.yaml."
                )
                await asyncio.sleep(autorun_delay)

            if self.shutdown:
                return

            self.logger.info("Starting boot Autorun playlist: default.yaml")
            await self.start_autorun_playlist_file("default.yaml", source="default.yaml")

        try:
            if self.autorun_boot_requested:
                boot_autorun_task = asyncio.create_task(
                    start_boot_autorun(),
                    name=f"sensor_node_boot_autorun:{self.uuid}",
                )
                self.child_tasks.append(boot_autorun_task)

            # Connect to HIPRFISR when available. Autorun does not depend on this path.
            if self.network_type == "IP":
                ok = await self.hiprfisr_socket.connect(self.hiprfisr_address)

                if ok:
                    self.logger.info(f"Connected to HIPRFISR @ {self.hiprfisr_address}")
                    await asyncio.sleep(0.1)

                    artifact_host = (
                        "127.0.0.1"
                        if self.hiprfisr_address.protocol == "ipc"
                        else self.hiprfisr_address.address
                    )

                    self.artifact_transfer_client = fissure.comms.ArtifactTransferClient(
                        endpoint=fissure.comms.build_artifact_endpoint(artifact_host),
                        identity=f"sensor-artifacts-{self.uuid}",
                        role=fissure.comms.ROLE_SENSOR_NODE,
                        node_uid=self.uuid,
                        logger=self.logger,
                    )

                    await self.artifact_transfer_client.connect()

                    from fissure.Sensor_Node.SensorNodeFileTransferController import (
                        SensorNodeFileTransferController,
                    )

                    file_transfer_controller = SensorNodeFileTransferController(self)
                    file_transfer_task = asyncio.create_task(
                        file_transfer_controller.receive_loop(),
                        name=f"Sensor Node File Transfer Receiver {self.uuid}",
                    )
                    self.child_tasks.append(file_transfer_task)

                    heartbeat_task = asyncio.create_task(
                        self.heartbeat_loop(),
                        name=f"sensor_node_heartbeat:{self.uuid}",
                    )
                    self.child_tasks.append(heartbeat_task)

                    if self.local_remote == "local":
                        await self.announce_local_startup()

                else:
                    self.logger.warning(
                        "HIPRFISR is unavailable. Sensor Node will continue running locally; "
                        "boot Autorun and node-local detector handling remain available."
                    )

            elif self.network_type == "Meshtastic":
                try:
                    serial_port = self.pending_meshtastic_params["serial_port"]

                    self.hiprfisr_socket = fissure.comms.FissureMeshtasticNode(
                        serial_port,
                        self.pending_meshtastic_params["name"],
                        self.pending_meshtastic_params["context"],
                    )

                    self.logger.info(f"Connected to Meshtastic serial port: {serial_port}")

                    heartbeat_task = asyncio.create_task(
                        self.heartbeat_loop(),
                        name=f"sensor_node_heartbeat:{self.uuid}",
                    )
                    self.child_tasks.append(heartbeat_task)

                except Exception as error:
                    self.logger.error(f"Failed to initialize Meshtastic on {serial_port}: {error}")
                    return

            else:
                self.logger.error(
                    "Unknown network type. Enter IP or Meshtastic in node YAML config file."
                )
                return

            while not self.shutdown:
                await asyncio.sleep(DELAY)

                if self.network_type == "IP":
                    if heartbeat_task is not None:
                        await self.read_hiprfisr_messages()

                    if self.pd_bits_socket:
                        await self.read_pd_bits_messages()

        except asyncio.CancelledError:
            raise

        finally:
            self.shutdown = True

            if self.autorun_state in {"Waiting", "Running", "Stopping"}:
                try:
                    await self.stop_autorun_playlist()
                except Exception:
                    self.logger.debug(
                        "Error stopping Autorun during Sensor Node shutdown.",
                        exc_info=True,
                    )

            if self.operations:
                try:
                    await self.stop_all_plugin_operations(
                        self,
                        requester_uid=self.uuid,
                        requester_type="shutdown",
                    )
                except Exception:
                    self.logger.debug(
                        "Error stopping plugin operations during Sensor Node shutdown.",
                        exc_info=True,
                    )

            for task in list(self.child_tasks):
                if not task.done():
                    task.cancel()

            if self.child_tasks:
                await asyncio.gather(*self.child_tasks, return_exceptions=True)

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
                    "autorun_state": getattr(self, "autorun_state", "Idle"),
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
            elif flow_graph == "Sniffer":
                getattr(self.snifferflowtoexec,formatted_name)(float(value))
        else:
            if flow_graph == "Protocol Discovery":
                getattr(self.pdflowtoexec,formatted_name)(value)
            elif flow_graph == "Sniffer":
                getattr(self.snifferflowtoexec,formatted_name)(value)


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


    #######################  Autorun Playlists  ##########################

    def get_autorun_playlist_names(self):
        """Return YAML playlist filenames stored on this Sensor Node."""
        playlist_dir = os.path.join(fissure.utils.SENSOR_NODE_DIR, "Autorun_Playlists")
        os.makedirs(playlist_dir, exist_ok=True)
        return sorted(
            [
                name for name in os.listdir(playlist_dir)
                if os.path.isfile(os.path.join(playlist_dir, name)) and name.lower().endswith((".yaml", ".yml"))
            ],
            key=str.lower,
        )


    def load_autorun_playlist_file(self, playlist_filename=""):
        """Load one versioned Autorun YAML file from the Sensor Node playlist directory."""
        filename = os.path.basename(str(playlist_filename or "").strip())
        if not filename or filename != str(playlist_filename or "").strip():
            raise ValueError("Invalid Autorun playlist filename.")

        path = os.path.join(fissure.utils.SENSOR_NODE_DIR, "Autorun_Playlists", filename)
        with open(path, "r") as yaml_file:
            playlist_dict = yaml.safe_load(yaml_file) or {}

        self._validate_autorun_playlist(playlist_dict)
        return playlist_dict


    def save_autorun_playlist_file(self, playlist_filename="", playlist_dict=None):
        """Save one versioned Autorun playlist YAML file on the Sensor Node."""
        filename = os.path.basename(str(playlist_filename or "").strip())
        if not filename or filename != str(playlist_filename or "").strip():
            raise ValueError("Invalid Autorun playlist filename.")
        if not filename.lower().endswith((".yaml", ".yml")):
            filename += ".yaml"

        self._validate_autorun_playlist(playlist_dict)
        playlist_dir = os.path.join(fissure.utils.SENSOR_NODE_DIR, "Autorun_Playlists")
        os.makedirs(playlist_dir, exist_ok=True)
        path = os.path.join(playlist_dir, filename)
        with open(path, "w") as yaml_file:
            yaml.safe_dump(playlist_dict, yaml_file, sort_keys=False)
        return filename


    def _validate_autorun_playlist(self, playlist_dict):
        """Validate the plugin-backed Autorun playlist document shape."""
        if not isinstance(playlist_dict, dict):
            raise ValueError("Autorun playlist must be a dictionary.")
        if int(playlist_dict.get("schema_version", 0) or 0) != 1:
            raise ValueError("Unsupported Autorun playlist schema version.")
        if not isinstance(playlist_dict.get("detectors", []), list):
            raise ValueError("Autorun detectors must be a list.")
        if not isinstance(playlist_dict.get("playlist", []), list):
            raise ValueError("Autorun playlist rows must be a list.")

        for row in playlist_dict.get("playlist", []):
            if not isinstance(row, dict):
                raise ValueError("Each Autorun playlist row must be a dictionary.")
            if not str(row.get("plugin", "") or "").strip() or not str(row.get("action", "") or "").strip():
                raise ValueError("Each Autorun playlist row requires plugin and action names.")
            delay_seconds = float(row.get("delay_seconds", 0) or 0)
            interval_seconds = float(row.get("interval_seconds", 0) or 0)
            if delay_seconds < 0 or interval_seconds < 0:
                raise ValueError("Autorun Delay and Interval cannot be negative.")
            if bool(row.get("repeat", False)) and interval_seconds <= 0:
                raise ValueError("Repeating Autorun rows require an Interval greater than zero.")


    async def _publish_autorun_status(self, state, source="", message=""):
        """Publish authoritative Autorun state and keep the node's resting status in sync."""
        self.autorun_state = str(state or "Idle")
        self.autorun_source = str(source or "")
        self.autorun_message = str(message or "")

        active_operations = getattr(self, "_active_operation_ids", set())
        if not active_operations:
            resting_status = self._autorun_node_status()
            if self.current_status != resting_status:
                self.current_status = resting_status
                try:
                    await self.publish_status_to_hiprfisr(resting_status)
                except Exception:
                    self.logger.debug("Could not publish Autorun node status.", exc_info=True)

        if self.network_type != "IP" or not getattr(self, "hiprfisr_socket", None) or not self.hiprfisr_seen:
            return

        msg = {
            fissure.comms.MessageFields.IDENTIFIER: self.identifier,
            fissure.comms.MessageFields.MESSAGE_NAME: "autorunPlaylistStatus",
            fissure.comms.MessageFields.PARAMETERS: {
                "node_uid": self.uuid,
                "state": self.autorun_state,
                "source": self.autorun_source,
                "message": self.autorun_message,
            },
        }

        try:
            await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)
        except Exception:
            self.logger.debug("Could not publish Autorun status.", exc_info=True)


    def _autorun_action_task(self, run_id, plugin_name, action_name, parameters, task_name):
        """Launch one node-owned plugin action under the current Autorun ownership context."""
        async def invoke():
            token = self._operation_owner_context.set(run_id)
            try:
                await self.plugin_action(
                    self,
                    requester_uid=self.uuid,
                    requester_type="autorun",
                    plugin_name=plugin_name,
                    action_name=action_name,
                    parameters=dict(parameters or {}),
                )
            except asyncio.CancelledError:
                raise
            except Exception:
                self.logger.error(
                    f"Autorun action failed: {plugin_name} - {action_name}\n{traceback.format_exc()}"
                )
            finally:
                self._operation_owner_context.reset(token)

        task = asyncio.create_task(invoke(), name=task_name)
        self.autorun_action_tasks.add(task)
        task.add_done_callback(lambda done: self.autorun_action_tasks.discard(done))
        return task


    async def _autorun_wait(self, seconds):
        """Wait for a scheduler delay while remaining immediately stop-responsive."""
        seconds = max(0.0, float(seconds or 0))
        if seconds <= 0:
            return not self.autorun_stop_event.is_set()

        try:
            await asyncio.wait_for(self.autorun_stop_event.wait(), timeout=seconds)
            return False
        except asyncio.TimeoutError:
            return True


    async def _autorun_schedule_row(self, run_id, row_index, row):
        """Schedule one independent Autorun action row."""
        plugin_name = str(row.get("plugin", "") or "").strip()
        action_name = str(row.get("action", "") or "").strip()
        parameters = dict(row.get("parameters", {}) or {})
        delay_seconds = float(row.get("delay_seconds", 0) or 0)
        repeat_forever = bool(row.get("repeat", False))
        interval_seconds = float(row.get("interval_seconds", 0) or 0)

        if not await self._autorun_wait(delay_seconds):
            return

        launch_index = 0
        while not self.autorun_stop_event.is_set():
            launch_index += 1
            self._autorun_action_task(
                run_id,
                plugin_name,
                action_name,
                parameters,
                f"autorun:{run_id}:row:{row_index}:launch:{launch_index}",
            )

            if not repeat_forever:
                return
            if not await self._autorun_wait(interval_seconds):
                return


    async def _stop_autorun_operation_ids(self, operation_ids):
        """Stop the supplied operation IDs without touching unrelated Sensor Node operations."""
        for operation_id in list(operation_ids or []):
            if operation_id not in self.operations:
                continue
            try:
                await self.stop_plugin_operation(self, operation_id)
            except Exception:
                self.logger.debug(f"Could not stop Autorun operation {operation_id}.", exc_info=True)


    async def _autorun_detector_gate(self, run_id, detectors):
        """Arm reusable detector actions and release on the first matching Detection."""
        self.autorun_detector_operation_ids = set()
        self.autorun_detector_event = asyncio.Event()
        detector_tasks = set()

        for index, detector in enumerate(detectors):
            if not isinstance(detector, dict):
                continue

            plugin_name = str(detector.get("plugin", "") or "").strip()
            action_name = str(detector.get("action", "") or "").strip()
            if not plugin_name or not action_name:
                continue

            operation_id = str(uuid.uuid4())
            parameters = dict(detector.get("runtime_parameters", detector.get("parameters", {})) or {})
            parameters["operation_id"] = operation_id
            self.autorun_detector_operation_ids.add(operation_id)
            detector_tasks.add(
                self._autorun_action_task(
                    run_id,
                    plugin_name,
                    action_name,
                    parameters,
                    f"autorun:{run_id}:detector:{index}",
                )
            )

        if not self.autorun_detector_operation_ids:
            await self._publish_autorun_status("Error", self.autorun_source, "No valid detectors could be armed.")
            return False

        while not self.autorun_stop_event.is_set():
            if self.autorun_detector_event.is_set():
                await self._stop_autorun_operation_ids(self.autorun_detector_operation_ids)
                return True

            active_detector = any(operation_id in self.operations for operation_id in self.autorun_detector_operation_ids)
            pending_action = any(not task.done() for task in detector_tasks)
            if not active_detector and not pending_action:
                await self._publish_autorun_status(
                    "Error",
                    self.autorun_source,
                    "All Autorun detectors stopped without a Detection.",
                )
                return False

            try:
                await asyncio.wait_for(self.autorun_detector_event.wait(), timeout=0.25)
            except asyncio.TimeoutError:
                pass

        return False


    async def _handle_autorun_detection(self, detection):
        """Consume matching detector observations locally before network forwarding."""
        if self.autorun_state != "Waiting" or not self.autorun_detector_event:
            return

        operation_id = str(detection.get("opid") or detection.get("operation_id") or "").strip()
        if operation_id and operation_id in self.autorun_detector_operation_ids:
            self.autorun_detector_event.set()


    async def _run_autorun_playlist(self, run_id, playlist_dict, source):
        """Run one validated Autorun playlist until its schedulers and owned operations finish."""
        detectors = playlist_dict.get("detectors", []) or []
        rows = playlist_dict.get("playlist", []) or []

        try:
            if detectors:
                await self._publish_autorun_status("Waiting", source)
                released = await self._autorun_detector_gate(run_id, detectors)
                if not released:
                    return

            if self.autorun_stop_event.is_set():
                return

            await self._publish_autorun_status("Running", source)
            self.autorun_scheduler_tasks = {
                asyncio.create_task(
                    self._autorun_schedule_row(run_id, index, row),
                    name=f"autorun:{run_id}:scheduler:{index}",
                )
                for index, row in enumerate(rows)
            }

            if self.autorun_scheduler_tasks:
                await asyncio.gather(*self.autorun_scheduler_tasks, return_exceptions=True)

            while not self.autorun_stop_event.is_set():
                owned_operations = self._operation_owner_ids.get(run_id, set())
                pending_actions = any(not task.done() for task in self.autorun_action_tasks)
                if not owned_operations and not pending_actions:
                    break
                await asyncio.sleep(0.25)

        except asyncio.CancelledError:
            raise
        except Exception as error:
            self.logger.error(f"Autorun playlist failed: {error}")
            self.logger.debug(traceback.format_exc())
            await self._publish_autorun_status("Error", source, str(error))
        finally:
            if self.autorun_state == "Stopping":
                await self._publish_autorun_status("Idle", "")
            elif self.autorun_state not in {"Error"}:
                await self._publish_autorun_status("Idle", "")

            self.autorun_detector_operation_ids.clear()
            self.autorun_scheduler_tasks.clear()
            self.autorun_run_id = ""
            self.autorun_task = None


    async def start_autorun_playlist(self, playlist_dict, source="Dashboard Playlist"):
        """Start one in-memory plugin-backed Autorun playlist if the node is idle."""
        if self.autorun_state in {"Waiting", "Running", "Stopping"} or (self.autorun_task and not self.autorun_task.done()):
            self.logger.warning("Autorun start rejected because an Autorun playlist is already active.")
            await self._publish_autorun_status(self.autorun_state, self.autorun_source, "Autorun is already active.")
            return False

        try:
            self._validate_autorun_playlist(playlist_dict)
        except Exception as error:
            await self._publish_autorun_status("Error", source, str(error))
            return False

        if not playlist_dict.get("playlist"):
            await self._publish_autorun_status("Error", source, "Autorun playlist contains no actions.")
            return False

        self.autorun_run_id = str(uuid.uuid4())
        self.autorun_stop_event = asyncio.Event()
        self.autorun_detector_event = asyncio.Event()
        self.autorun_detector_operation_ids = set()
        self.autorun_scheduler_tasks = set()
        self.autorun_action_tasks = set()
        self.autorun_source = str(source or "Dashboard Playlist")
        self.autorun_state = "Waiting" if playlist_dict.get("detectors") else "Running"
        self.autorun_task = asyncio.create_task(
            self._run_autorun_playlist(self.autorun_run_id, playlist_dict, self.autorun_source),
            name=f"autorun:{self.autorun_run_id}",
        )
        return True


    async def start_autorun_playlist_file(self, playlist_filename="", source=""):
        """Load a stored Sensor Node Autorun YAML file and start it."""
        try:
            playlist_dict = self.load_autorun_playlist_file(playlist_filename)
        except Exception as error:
            await self._publish_autorun_status("Error", source or playlist_filename, str(error))
            return False
        return await self.start_autorun_playlist(playlist_dict, source=source or playlist_filename)


    async def stop_autorun_playlist(self):
        """Stop schedulers, detector waits, and operations owned by the active Autorun run."""
        if self.autorun_state not in {"Waiting", "Running", "Stopping"}:
            return
        if self.autorun_state == "Stopping":
            return

        run_id = self.autorun_run_id
        await self._publish_autorun_status("Stopping", self.autorun_source)
        self.autorun_stop_event.set()
        if self.autorun_detector_event:
            self.autorun_detector_event.set()

        await self._stop_autorun_operation_ids(self.autorun_detector_operation_ids)
        await self._stop_autorun_operation_ids(self._operation_owner_ids.get(run_id, set()))

        for task in list(self.autorun_scheduler_tasks):
            if not task.done():
                task.cancel()
        await asyncio.gather(*list(self.autorun_scheduler_tasks), return_exceptions=True)

        for task in list(self.autorun_action_tasks):
            if not task.done():
                task.cancel()
        await asyncio.gather(*list(self.autorun_action_tasks), return_exceptions=True)

        if self.autorun_task and self.autorun_task is not asyncio.current_task():
            try:
                await self.autorun_task
            except asyncio.CancelledError:
                pass


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
