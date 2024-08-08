#!/usr/bin/env python3

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
from typing import Dict, List, Union

import asyncio
import fissure.callbacks
import fissure.comms
import fissure.utils

import uuid
import logging

from concurrent.futures import ThreadPoolExecutor

import warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)  # Scapy warnings

IP_ADDRESS = "127.0.0.1"
CERT_DIR = "certificates"
CONFIG_FILE = os.path.join(fissure.utils.YAML_DIR, "sensor_node.yaml")

DELAY = 0.5  # Seconds

if "maint-3.8" in fissure.utils.get_fg_library_dir(fissure.utils.get_os_info()):
    sys.path.insert(0, os.path.join(fissure.utils.FISSURE_ROOT, "Flow Graph Library", "maint-3.8", "PD Flow Graphs"))
    sys.path.insert(0, os.path.join(fissure.utils.FISSURE_ROOT, "Flow Graph Library", "maint-3.8", "Single-Stage Flow Graphs"))
    sys.path.insert(0, os.path.join(fissure.utils.FISSURE_ROOT, "Flow Graph Library", "maint-3.8", "Fuzzing Flow Graphs"))
    sys.path.insert(0, os.path.join(fissure.utils.FISSURE_ROOT, "Flow Graph Library", "maint-3.8", "IQ Flow Graphs"))
    sys.path.insert(0, os.path.join(fissure.utils.FISSURE_ROOT, "Flow Graph Library", "maint-3.8", "Archive Flow Graphs"))
    sys.path.insert(0, os.path.join(fissure.utils.FISSURE_ROOT, "Flow Graph Library", "maint-3.8", "Sniffer Flow Graphs"))
    sys.path.insert(0, os.path.join(fissure.utils.FISSURE_ROOT, "Flow Graph Library", "maint-3.8", "TSI Flow Graphs"))
elif "maint-3.10" in fissure.utils.get_fg_library_dir(fissure.utils.get_os_info()):
    sys.path.insert(0, os.path.join(fissure.utils.FISSURE_ROOT, "Flow Graph Library", "maint-3.10", "PD Flow Graphs"))
    sys.path.insert(0, os.path.join(fissure.utils.FISSURE_ROOT, "Flow Graph Library", "maint-3.10", "Single-Stage Flow Graphs"))
    sys.path.insert(0, os.path.join(fissure.utils.FISSURE_ROOT, "Flow Graph Library", "maint-3.10", "Fuzzing Flow Graphs"))
    sys.path.insert(0, os.path.join(fissure.utils.FISSURE_ROOT, "Flow Graph Library", "maint-3.10", "IQ Flow Graphs"))
    sys.path.insert(0, os.path.join(fissure.utils.FISSURE_ROOT, "Flow Graph Library", "maint-3.10", "Archive Flow Graphs"))
    sys.path.insert(0, os.path.join(fissure.utils.FISSURE_ROOT, "Flow Graph Library", "maint-3.10", "Sniffer Flow Graphs"))
    sys.path.insert(0, os.path.join(fissure.utils.FISSURE_ROOT, "Flow Graph Library", "maint-3.10", "TSI Flow Graphs"))
sys.path.insert(0, '/tmp')


def run():
    asyncio.run(main())


async def main():
    print("[FISSURE][Sensor Node] start")
    sensor_node = SensorNode()
    await sensor_node.begin()

    print("[FISSURE][Sensor Node] end")
    fissure.utils.zmq_cleanup()

    sys.exit()


class SensorNode():
    """ 
    Class that contains the functions for the sensor node.
    """
    
    # settings: Dict
    identifier: str = fissure.comms.Identifiers.SENSOR_NODE_0
    logger: logging.Logger = fissure.utils.get_logger(fissure.comms.Identifiers.SENSOR_NODE_0)
    # ip_address: str
    hiprfisr_socket: fissure.comms.Server  # PAIR
    #hiprfisr_connected: bool
    # sensor_nodes: List[Listener]  # DEALER/DEALER
    # heartbeats: Dict[str, Union[float, Dict[int, float]]]  # {name: time, name: time, ... sensor_nodes: {node_id: time}}
    callbacks: Dict = {}
    # shutdown: bool
    
    #######################  FISSURE Functions  ########################

    def __init__(self):
        """ 
        The start of the sensor node execution.
        """
        self.hiprfisr_connected = False

        # Read Stored Settings
        self.os_info = fissure.utils.get_os_info()
        filename = os.path.join(fissure.utils.SENSOR_NODE_DIR, "Sensor_Node_Config", "default.yaml")
        with open(filename) as yaml_library_file:
            self.settings_dict = yaml.load(yaml_library_file, yaml.FullLoader)
        
        # Set Logging Levels
        fissure.utils.init_logging()
        self.updateLoggingLevels(self.settings_dict['Sensor Node']['console_logging_level'], self.settings_dict['Sensor Node']['file_logging_level'])  # Add these fields to the export, import, hardware configuration window

        # Initialize Connection/Heartbeat Variables
        self.ip_address = str(self.settings_dict['Sensor Node']['ip_address'])
        self.heartbeats = {
            fissure.comms.Identifiers.SENSOR_NODE_0: 0,
            fissure.comms.Identifiers.HIPRFISR: 0,
        }

        self.heartbeat_interval = 5
        self.sensor_node_heartbeat_time = 0
        self.attack_flow_graph_loaded = False
        self.archive_flow_graph_loaded = False
        self.physical_fuzzing_stop_event = False

        self.attack_script_name = ""
        self.inspection_script_name = ""

        self.triggers_running = False
        
        ############ TSI ################
        self.tsi_detector_socket = None
        #self.heartbeat_interval = 5
        #self.tsi_heartbeat_time = 0
        self.running_TSI = False
        self.running_TSI_simulator = False
        self.blacklist = []
        self.running_TSI_wideband = False
        self.configuration_update = False
        self.detector_script_name = ""

        ############# PD ################
        self.running_PD = False
        self.pd_bits_socket = None
        

        # # Create the Sensor Node ZMQ Sockets
        # self.connect()
        
        # Check for Autorun
        if self.settings_dict['Sensor Node']['autorun'] == True:
            # Read the Autorun Playlist File
            filename = os.path.join(fissure.utils.SENSOR_NODE_DIR, "Autorun_Playlists", "default.yaml")
            with open(filename) as yaml_library_file:
                playlist_dict = yaml.load(yaml_library_file, yaml.FullLoader)
                trigger_dict = playlist_dict['trigger_values']
            self.autorunPlaylistStart('', playlist_dict, trigger_dict)
            
        # Create the Sensor Node ZMQ Nodes
        self.initialize_comms()
        self.shutdown = False

        # Register Callbacks
        self.register_callbacks(fissure.callbacks.GenericCallbacks)
        self.register_callbacks(fissure.callbacks.SensorNodeCallbacks)    


    def initialize_comms(self):
        """
        """
        # To HIPRFISR
        sensor_node_pair_port = str(self.settings_dict['Sensor Node']['msg_port'])
        #sensor_node_hb_port = int(self.settings_dict['Sensor Node']['hb_port'])
        
        ################
        # temp_settings = fissure.utils.get_fissure_config()
        # comms_info = temp_settings.get("hiprfisr")
        # print(comms_info)
        # sensor_node_pair_address = fissure.comms.Address(address_config=comms_info.get("frontend"))

        sensor_node_pair_address = fissure.comms.Address(protocol="tcp", address=self.ip_address, hb_channel=5051, msg_channel=sensor_node_pair_port)

        # print(sensor_node_pair_address.get("address"))
        # print(sensor_node_pair_address["frontend"]["address"])

        # sensor_node_pair_address.address = self.ip_address
        # sensor_node_pair_address.message_channel = sensor_node_pair_port

        # sensor_node_pair_address = "tcp://" + self.ip_address + ":" + sensor_node_pair_port  #comms_info.get("frontend_address"), tcp://0.0.0.0:5051
        # {'backend': {'address': 'fissure-backend', 'protocol': 'ipc'}, 'frontend': {'address': '0.0.0.0', 'heartbeat_channel': 5051, 'message_channel': 5052, 'protocol': 'tcp'}}
        # sensor_node_pair_address = {'frontend':{'address': self.ip_address, 'heartbeat_channel': 5051, 'message_channel': sensor_node_pair_port, 'protocol': 'tcp'}}
        #ipc://fissure [-hb (hb), -msg (msg)]
        #ipc://fissure-backend [-hb (hb), -msg (msg)]
        # print(sensor_node_pair_address)
        ################        

        self.hiprfisr_socket = fissure.comms.Server(
            # schema=CONFIG_FILE,
            address=sensor_node_pair_address,
            sock_type=zmq.PAIR,
            name=f"{self.identifier}::sensor_node",
        )
        self.hiprfisr_socket.start()
        

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


    async def shutdown_comms(self):
        """
        """
        # Notify Dashboard Immediately
        PARAMETERS = {"component_name": self.identifier}
        msg = {            
            fissure.comms.MessageFields.IDENTIFIER: self.identifier,
            fissure.comms.MessageFields.MESSAGE_NAME: "componentDisconnected",
            fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
        }
        await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)
        time.sleep(DELAY * 2)
        
        # Future
        PARAMETERS = {"component_name": self.identifier}
        shutdown_notice = {            
            fissure.comms.MessageFields.IDENTIFIER: self.identifier,
            fissure.comms.MessageFields.MESSAGE_NAME: "shuttingDown",
            fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
        }
        await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.STATUS, shutdown_notice)

        time.sleep(DELAY * 2)
        self.hiprfisr_socket.shutdown()


    async def begin(self):
        """
        Main Event Loop
        """
        self.logger.info("=== STARTING SENSOR NODE ===")
        while self.shutdown is False:
            await asyncio.sleep(DELAY)

            # Heartbeats
            if self.hiprfisr_connected:
                try:
                    await asyncio.wait_for(self.send_heartbeat(), timeout=10.0)
                except asyncio.TimeoutError:
                    self.hiprfisr_connected = False
                    self.logger.warning("send_heartbeat() timed out")
            
            try:
                await asyncio.wait_for(self.check_heartbeats(), timeout=10.0)
            except asyncio.TimeoutError:
                self.hiprfisr_connected = False
                self.logger.warning("check_heartbeats() timed out")

            # Process Incoming Messages
            await self.read_hiprfisr_messages()

            # Read Incoming TSI Wideband Messages
            if self.tsi_detector_socket != None:
                await self.read_detector_messages()

            # Read Incoming PD Bits Messages
            if self.pd_bits_socket != None:
                await self.read_pd_bits_messages()

        # Clean up Sockets
        # await self.shutdown_comms()
        if self.tsi_detector_socket != None:
            self.stopTSI_Detector(-1)
            await asyncio.sleep(2)  # Causes non-critical error without sleep

        if self.pd_bits_socket != None:
            self.stopPD(-1)
            await asyncio.sleep(2)

        self.logger.info("=== SHUTDOWN ===")
        # self.hiprfisr_socket.shutdown()
        # fissure.utils.zmq_cleanup()
        # sys.exit()


    async def read_hiprfisr_messages(self):
        """
        Receive and parse messages from the Dashboard and carry out commands
        """
        parsed = ""
        while parsed is not None:
            parsed = await self.hiprfisr_socket.recv_msg()
            if parsed is not None:
                self.hiprfisr_connected = True
                msg_type = parsed.get(fissure.comms.MessageFields.TYPE)
                name = parsed.get(fissure.comms.MessageFields.MESSAGE_NAME)
                if msg_type == fissure.comms.MessageTypes.HEARTBEATS:
                    heartbeat_time = float(parsed.get(fissure.comms.MessageFields.TIME))
                    self.heartbeats[fissure.comms.Identifiers.HIPRFISR] = heartbeat_time
                elif msg_type == fissure.comms.MessageTypes.COMMANDS:
                    await self.hiprfisr_socket.run_callback(self, parsed)
                elif msg_type == fissure.comms.MessageTypes.STATUS:
                        pass
                else:
                    pass


    async def send_heartbeat(self):
        """
        Send Heartbeat Message
        """
        last_heartbeart = self.heartbeats[self.identifier]
        now = time.time()
        if (now - last_heartbeart) >= self.heartbeat_interval:
            heartbeat = {
                fissure.comms.MessageFields.IDENTIFIER: self.identifier,
                fissure.comms.MessageFields.MESSAGE_NAME: fissure.comms.MessageFields.HEARTBEAT,
                fissure.comms.MessageFields.TIME: now,
                fissure.comms.MessageFields.IP: self.ip_address,
            }
            await self.hiprfisr_socket.send_heartbeat(heartbeat)
            self.heartbeats[self.identifier] = now


    async def check_heartbeats(self):
        """
        Check hearbeat and set connection flags accordingly
        """        
        current_time = time.time()
        cutoff_interval = 15.0  #float(self.settings.get("failure_multiple")) * float(self.settings.get("heartbeat_interval"))
        cutoff_time = current_time - cutoff_interval

        if self.heartbeats.get(fissure.comms.Identifiers.HIPRFISR) > 0:
            last_heartbeat = self.heartbeats.get(fissure.comms.Identifiers.HIPRFISR)
            # Failed heartbeat check while previously connected
            if self.hiprfisr_connected and (last_heartbeat < cutoff_time):
                self.hiprfisr_connected = False
            # Passed heartbeat check while previously disconnected
            elif (not self.hiprfisr_connected) and (last_heartbeat > cutoff_time):
                self.hiprfisr_connected = True


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


    def isFloat(self, x):
        """ Returns "True" if the input is a Float. Returns "False" otherwise.
        """
        try:
            float(x)
        except ValueError:
            return False
        return True
        

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
            if self.settings_dict['Sensor Node']['local_remote'] == "remote":

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
                if self.settings_dict['Sensor Node']['local_remote'] == "remote":
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
                    proc = subprocess.Popen('gnome-terminal -- ' + osCommandString + " &", shell=True)
                    
                    # In FISSURE Dashboard
                    #proc = subprocess.Popen(osCommandString + " &", shell=True)#, stderr=subprocess.PIPE)
                    #output, error = proc.communicate()
                    
                    # Restore the Start Button for Scripts
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
            if self.settings_dict['Sensor Node']['local_remote'] == "remote":
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
                proc = subprocess.Popen('gnome-terminal -- ' + osCommandString + " &", shell=True)
                
                # In FISSURE Dashboard
                #proc = subprocess.Popen(osCommandString + " &", shell=True)#, stderr=subprocess.PIPE)
                #output, error = proc.communicate()
                
                # Restore the Start Button for Scripts
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
        # Check for string_variables
        for n in range(0,len(variable_names)):
            if variable_names[n] == "string_variables":
                fix_strings = True
                fix_strings_index = n
                break
            else:
                fix_strings = False
                fix_strings_index = None

        # Load New Flow Graph
        flow_graph_filename = flow_graph_filename.rsplit("/",1)[-1]
        flow_graph_filename = flow_graph_filename.replace(".py","")
        loadedmod = __import__(flow_graph_filename)  # Don't need to reload() because the original never changes

        # Update the Text in the Code
        stistr = inspect.getsource(loadedmod)
        variable_line_position = 0
        new_stistr = ""
        for line in iter(stistr.splitlines()):
            # Change Variable Values
            if variable_line_position == 2:

                # Reached the End of the Variables Section
                if line.strip() == "":
                    variable_line_position = 3

                # Change Value
                else:
                    variable_name = line.split("=",2)[1]  # Only the first two '=' in case value has '='

                    # Ignore Notes
                    if variable_name.replace(' ','') != "notes":
                        old_value = line.split("=",2)[-1]
                        index = variable_names.index(variable_name.replace(" ",""))
                        new_value = variable_values[index]

                        # A Number
                        if self.isFloat(new_value):
                            # Make Numerical Value a String
                            if fix_strings == True:
                                if variable_name.strip() in variable_values[fix_strings_index]:
                                    new_value = '"' + new_value + '"'

                        # A String
                        else:
                            new_value = '"' + new_value + '"'

                        new_line = line.split("=",2)[0] + " = " + line.split("=",2)[1] + ' = ' + new_value + "\n"
                        new_stistr += new_line

            # Write Unreplaced Contents
            if variable_line_position != 2:
                new_stistr += line + "\n"

            # Skip "#################################" Line after "# Variables"
            if variable_line_position == 1:
                variable_line_position = 2

            # Find Line Containing "# Variables"
            if "# Variables" in line:
                variable_line_position = 1

            # Find Class Name
            if "class " in line and "(gr." in line:
                class_name = line.split(" ")[1]
                class_name = class_name.split("(")[0]

        # Compile
        sticode=compile(new_stistr,'<string>','exec')
        loadedmod = types.ModuleType('stiimp')
        exec(sticode, loadedmod.__dict__)

        return loadedmod, class_name


    def setVariable(self, flow_graph="", variable="", value=""):
        """ Sets a variable of a specified running flow graph.
        """
        # Make it Match GNU Radio Format
        formatted_name = "set_" + variable
        isNumber = self.isFloat(value)
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
            #print(variable_names)
            #print(variable_values)
            #print(type(variable_values))
            #print(repr(variable_values))
            #print type(repr(variable_values))
            #for n in range(0,len(variable_values)):
                #print("asdfasd")
                #print(variable_values[n])
                #variable_values[n] = variable_values[n].replace('`','\`')
            #print("after")
            #print(variable_values)
            #print("function")
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
        
        # User Kills Python Scripts Manually
        if parameter == "Python Script":
            #pass
            #os.system("sudo pkill -f " + '"' + self.attack_script_name +'"')  # Make terminal responsible for killing scripts

            #script_pid = subprocess.check_output("pgrep -f '" + self.attack_script_name + "'", shell=True)
            #print(script_pid)
            #os.system("sudo kill " + str(script_pid))
            
            # Normal
            if autorun_index == -1:
                os.system("pkill -f " + '"' + self.attack_script_name +'"')
                self.attack_flow_graph_loaded = False
            # Autorun
            else:
                os.system("pkill -f " + '"' + self.autorun_playlist_manager[autorun_index] +'"')
                self.autorun_playlist_manager[autorun_index] = None
                
        elif parameter == "Flow Graph - GUI":
            # Normal
            if autorun_index == -1:
                os.system("pkill -f " + '"' + self.attack_script_name +'"')
                self.attack_flow_graph_loaded = False
            # Autorun
            else:
                os.system("pkill -f " + '"' + self.autorun_playlist_manager[autorun_index] +'"')
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
                if self.settings_dict['Sensor Node']['local_remote'] == "remote":
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
            if self.settings_dict['Sensor Node']['local_remote'] == "remote":
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
                if self.settings_dict['Sensor Node']['local_remote'] == "remote":
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
                if self.settings_dict['Sensor Node']['local_remote'] == "remote":
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
            if self.settings_dict['Sensor Node']['local_remote'] == "remote":
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
            if self.settings_dict['Sensor Node']['local_remote'] == "remote":
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
                autorun_playlist_thread = threading.Thread(target=self.autorunPlaylistThreadStart, args=[sensor_node_id, playlist_dict])
                autorun_playlist_thread.start()
                

    async def autorunPlaylistStarted(self, sensor_node_id):
        """ Sends the Autorun Playlist Started message to the HIPRFISR/Dashboard.
        """
        # Send the Message
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
                if self.isFloat((fuzzing_min[n])):
                    generic_value = float(fuzzing_min[n])
                # What Happens for a String?
                else:
                    generic_value = str(fuzzing_min[n])
            elif fuzzing_type[n] == "Random":
                # Check if it is a Float
                if self.isFloat((fuzzing_min[n])):
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
                    if self.isFloat(fuzzing_min[n]):
                        # Increment
                        generic_value = generic_value + float(fuzzing_seed_step[n])

                        # Max is Reached
                        if generic_value > float(fuzzing_max[n]):
                            generic_value = float(fuzzing_min[n])

                    # What Happens for a String?
                    else:
                        generic_value = str(fuzzing_min[n])

                elif fuzzing_type[n] == "Random":
                    if self.isFloat(fuzzing_min[n]):
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
                variable_names = ["tx_gain","tx_frequency","tx_channel","sample_rate","ip_address","filepath","ip_address","serial"]
                variable_values = [gains[n],frequencies[n],channels[n],sample_rates[n],"",filenames[n],ip_address, serial]
                
                # Adjust Filepath
                if self.settings_dict['Sensor Node']['local_remote'] == "remote":
                    variable_values[5] = os.path.join(fissure.utils.SENSOR_NODE_DIR, "Archive_Replay", filenames[n].split('/')[-1])

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
            print(f"Error in archivePlaylistStop: {e}")


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
            if self.settings_dict['Sensor Node']['local_remote'] == "remote":
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
            os.system("pkill -f " + '"' + self.detector_script_name +'"')
            self.detector_script_name = ""


    def detectorFlowGraphGUI_Thread(self, sensor_node_id, flow_graph_filename, variable_names, variable_values, detector_port):
        """ Runs the detector flow graph in the new thread.
        """
        try:
            # Start it
            filepath = os.path.join(fissure.utils.get_fg_library_dir(self.os_info), "TSI Flow Graphs", flow_graph_filename)
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
            
            # Passed in from the Dashboard
            if sensor_node_id != '':
                # Send the Message
                asyncio.run(self.autorunPlaylistStarted(sensor_node_id))
            
            # Make a New Thread
            self.autorun_playlist_stop_event = threading.Event()
            autorun_playlist_thread = threading.Thread(target=self.autorunPlaylistThreadStart, args=[sensor_node_id, playlist_dict])
            autorun_playlist_thread.start()
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
                self.logger.info("Sleeping until next playlist run.")
                time.sleep(get_repetition_interval)
                self.logger.info("Done sleeping.")
                
                # Exit if Stop is Clicked
                if self.autorun_playlist_stop_event.is_set():
                    break
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
        PARAMETERS = {"sensor_node_id": sensor_node_id}
        msg = {
                    fissure.comms.MessageFields.IDENTIFIER: self.identifier,
                    fissure.comms.MessageFields.MESSAGE_NAME: "autorunPlaylistFinished",
                    fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
        }
        await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


    ########################################################################


if __name__ == "__main__":
    rc = 0
    # try:
    run()
    # except Exception:
        # rc = 1

    sys.exit(rc)