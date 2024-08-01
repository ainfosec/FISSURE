from collections import Counter
from inspect import isfunction
from types import ModuleType
from typing import Dict

import asyncio
import fissure.callbacks
import fissure.comms
import fissure.utils
import fissure.utils.library
import logging
import numpy as np
import os
import re
import sys
import time
import uuid
import yaml
import zmq


def run():
    asyncio.run(main())


async def main():
    print("[FISSURE][ProtocolDiscovery] start")
    protocol_discovery = ProtocolDiscovery()
    await protocol_discovery.begin()

    print("[FISSURE][ProtocolDiscovery] end")
    fissure.utils.zmq_cleanup()


class ProtocolDiscovery:
    """Fissure ProtocolDiscovery Class"""

    settings: Dict
    identifier: str = fissure.comms.Identifiers.PD
    logger: logging.Logger = fissure.utils.get_logger(fissure.comms.Identifiers.PD)
    ip_address: str
    pd_library: any
    hiprfisr_address: fissure.comms.Address
    hiprfisr_socket: fissure.comms.Listener
    hiprfisr_connected: bool
    heartbeats: Dict[str, float]  # {name: time, name: time}
    heartbeat_interval: float
    callbacks: Dict = {}
    shutdown: bool


    def __init__(self):

        self.logger.debug("=== INITIALIZING ===")
        self.settings = fissure.utils.get_fissure_config()
        self.ip_address = "localhost"
        self.os_info = fissure.utils.get_os_info()
        self.pd_library = fissure.utils.load_library(self.os_info)

        # Initialize Connection/Heartbeat Variables
        self.heartbeats = {
            fissure.comms.Identifiers.HIPRFISR: None,
            fissure.comms.Identifiers.PD: None,
        }
        self.hiprfisr_connected = False

        # Initialze ZMQ Nodes
        self.initialize_comms()

        self.shutdown = False
        self.pd_running = False

        # Buffer
        self.circular_buffer = ""
        self.min_buffer = 100   
        self.max_buffer = 2 ** 18  # 200K Buffer for Receiving Bits, Change to Make Bigger for Binary (Rewrite Receiver Function)  
        self.buffer_size_time = time.time()
        self.flush_buffer = False

        # Find Preambles
        self.min_size = 4
        self.max_size = 24
        self.ranking = 10  # top number of strings of length between min_size and max_size    
        self.num_std = 2  # find those preambles within 2 std deviations of the mean packet length 
        # self.finding_preambles = False    
        # self.lib_search = False

        # Register Callbacks
        self.register_callbacks(fissure.callbacks.GenericCallbacks)
        self.register_callbacks(fissure.callbacks.ProtocolDiscoveryCallbacks)

        self.logger.debug("=== READY ===")


    def initialize_comms(self):
        """
        Setup ZMQ Sockets
        """
        comms_info = self.settings.get("hiprfisr")
        self.hiprfisr_address = fissure.comms.Address(address_config=comms_info.get("backend"))
        self.socket_id = f"{self.identifier}-{uuid.uuid4()}"
        self.hiprfisr_socket = fissure.comms.Listener(sock_type=zmq.DEALER, name=f"{self.identifier}::backend")
        self.hiprfisr_socket.set_identity(self.socket_id)


    async def shutdown_comms(self):
        """
        Send shutdown notice, disconnect and shutdown ZMQ sockets
        """
        shutdown_notice = {
            fissure.comms.MessageFields.IDENTIFIER: self.identifier,
            fissure.comms.MessageFields.MESSAGE_NAME: "Shutting Down",
            fissure.comms.MessageFields.PARAMETERS: "",
        }
        await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.STATUS, shutdown_notice)

        self.hiprfisr_socket.disconnect(self.hiprfisr_address)
        self.hiprfisr_socket.shutdown()


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


    async def begin(self):
        self.logger.info("=== STARTING PROTOCOL DISCOVERY COMPONENT ===")

        # Connect to HiprFisr
        if await self.hiprfisr_socket.connect(self.hiprfisr_address):
            self.logger.info(f"connected to HiprFisr @ {self.hiprfisr_address}")

        # Main Event Loop
        while self.shutdown is False:
            # Heartbeats
            await self.send_heartbeat()
            await self.recv_heartbeat()
            self.check_heartbeat()

            # Process Incoming Messages
            await self.read_HIPRFISR_messages()

        # Clean Up
        self.stopPD()

        await self.shutdown_comms()
        self.logger.info("=== SHUTDOWN ===")


    async def send_heartbeat(self):
        """
        Send Hearbeat Message
        """
        last_heartbeat = self.heartbeats[fissure.comms.Identifiers.PD]
        now = time.time()
        if (last_heartbeat is None) or (now - last_heartbeat) >= float(self.settings.get("heartbeat_interval")):
            heartbeat = {
                fissure.comms.MessageFields.IDENTIFIER: fissure.comms.Identifiers.PD,
                fissure.comms.MessageFields.MESSAGE_NAME: fissure.comms.MessageFields.HEARTBEAT,
                fissure.comms.MessageFields.TIME: now,
                fissure.comms.MessageFields.IP: self.ip_address,
            }
            await self.hiprfisr_socket.send_heartbeat(heartbeat)
            self.heartbeats[fissure.comms.Identifiers.PD] = now
            self.logger.debug(f"sent heartbeat ({fissure.utils.get_timestamp(now)})")


    async def recv_heartbeat(self):
        """
        Receive Heartbeat Messages
        """
        heartbeat = await self.hiprfisr_socket.recv_heartbeat()

        if heartbeat is not None:
            heartbeat_time = float(heartbeat.get(fissure.comms.MessageFields.TIME))
            self.heartbeats[fissure.comms.Identifiers.HIPRFISR] = heartbeat_time
            self.logger.debug(f"received HiprFisr heartbeat ({fissure.utils.get_timestamp(heartbeat_time)})")


    def check_heartbeat(self):
        """
        Check hearbeat and set connection flags accordingly
        """
        current_time = time.time()
        cutoff_interval = float(self.settings.get("failure_multiple")) * float(self.settings.get("heartbeat_interval"))
        cutoff_time = current_time - cutoff_interval

        last_heartbeat = self.heartbeats.get(fissure.comms.Identifiers.HIPRFISR)
        if last_heartbeat is not None:
            # Failed heartbeat check while previously connected
            if self.hiprfisr_connected and (last_heartbeat < cutoff_time):
                self.hiprfisr_connected = False
            # Passed heartbeat check while previously disconnected
            elif (not self.hiprfisr_connected) and (last_heartbeat > cutoff_time):
                self.hiprfisr_connected = True


    async def read_HIPRFISR_messages(self):
        """
        Receive and parse messages from the HiprFisr and carry out commands
        """
        received_message = ""
        while received_message is not None:
            received_message = await self.hiprfisr_socket.recv_msg()
            if received_message is not None:
                type = received_message.get(fissure.comms.MessageFields.TYPE)
                if type == fissure.comms.MessageTypes.HEARTBEATS:
                    self.logger.warning("received heartbeat on message channel")
                elif type == fissure.comms.MessageTypes.COMMANDS:
                    await self.hiprfisr_socket.run_callback(self, received_message)
                elif type == fissure.comms.MessageTypes.STATUS:
                    # TODO
                    pass


    def updateLoggingLevels(self, new_console_level="", new_file_level=""):
        """Update the logging levels on PD."""
        # Update New Levels for PD
        for n in range(0, len(self.logger.parent.handlers)):
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


    def update_FISSURE_Configuration(self):
        """Reload fissure_config.yaml after changes."""
        # Update PD Dictionary
        self.settings = fissure.utils.get_fissure_config()


    def startPD(self):
        """
        Threaded function to update buffer running in background.
        Change the size of the buffer by setting global variable "max_buffer" to the correct size.
        (Note that zmq buffer appears to be 32kb)
        Flush the buffer by changing global variable "flush_buffer" to True.
        """
        self.pd_running = True

        # Add Incoming Bits to Circular Buffer 
        while self.pd_running == True:  # Loop causes RuntimeError on shut down
            # Check for Overflow
            if len(self.circular_buffer) > self.max_buffer:
                self.circular_buffer = self.circular_buffer[(len(self.circular_buffer) - self.max_buffer) :]

            # Check for Buffer Flush
            if self.flush_buffer:
                self.circular_buffer = ""
                self.flush_buffer = False

            # Report the Buffer Size to the Dashboard
            if float(self.buffer_size_time) < time.time() - (float(self.settings["buffer_size_interval"])):
                self.buffer_size_time = time.time()

                # Send the Message to the HIPRFISR
                asyncio.run(self.bufferSizeReturn())

            time.sleep(0.5)


    async def bufferSizeReturn(self):
        """
        Sends the size of the circular buffer for bits to the HIPRFISR/Dashboard.
        """
        # Send the Message
        if self.shutdown == False:
            PARAMETERS = {"buffer_size": len(self.circular_buffer)}
            msg = {
                fissure.comms.MessageFields.IDENTIFIER: self.identifier,
                fissure.comms.MessageFields.MESSAGE_NAME: "bufferSizeReturn",
                fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
            }
            await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


    def stopPD(self):
        """ 
        Stops the protocol discovery bit listener and processing.
        """
        # Stop Looping
        self.logger.info("PD: Stopping PD bit listener...")
        self.pd_running = False


    def searchLibraryForFlowGraphs(self, soi_data, hardware):
        """
        Look up the SOI to recommend a best-fit demodulation flow graph from the library.
        """
        # Check Hardware
        if len(hardware) == 0:
            hardware = None

        # Search the Library for SOI
        get_sois = self.searchLibrary(soi_data, "")

        # Get All Flow Graphs for Each Protocol
        flow_graph_names = []
        if soi_data[1] == "":
            for s in get_sois:
                flow_graph_names.extend(
                    fissure.utils.library.getDemodulationFlowGraphs(
                        self.pd_library, s[list(s.keys())[0]]["Protocol"], None, hardware
                    )
                )

        # Keep Names with Same Modulation
        else:
            for s in get_sois:
                flow_graph_names.extend(
                    fissure.utils.library.getDemodulationFlowGraphs(
                        self.pd_library, s[list(s.keys())[0]]["Protocol"], soi_data[1], hardware
                    )
                )

        # Unique Values
        unique_flow_graph_names = list(set(flow_graph_names))

        # Send the Message to the HIPRFISR
        asyncio.run(self.demodFG_LibrarySearchReturn(unique_flow_graph_names))


    async def demodFG_LibrarySearchReturn(self, flow_graphs=[]):
        """ 
        Returns the search library for flow graphs message results to the HIPRFISR/Dashboard.
        """
        PARAMETERS = {"flow_graphs": flow_graphs}
        msg = {
                    fissure.comms.MessageFields.IDENTIFIER: self.identifier,
                    fissure.comms.MessageFields.MESSAGE_NAME: "demodFG_LibrarySearchReturn",
                    fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
        }
        await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


    def searchSOIsAndFields(self, soi_data, field_data):
        """
        Called from searchLibrary callback. Exists because searchLibrary() is used in multiple places.
        """
        # Search the Library
        message = self.searchLibrary(soi_data, field_data)

        # Send the Message
        asyncio.run(self.searchLibraryReturn(message))


    async def searchLibraryReturn(self, message=[]):
        """ 
        Returns the search library message results to the HIPRFISR/Dashboard.
        """
        PARAMETERS = {"message": message}
        msg = {
                    fissure.comms.MessageFields.IDENTIFIER: self.identifier,
                    fissure.comms.MessageFields.MESSAGE_NAME: "searchLibraryReturn",
                    fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
        }
        await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


    def searchLibrary(self, soi_data, field_data):
        """
        Callback to search for the Candidate preamble in Library
        preambles passed in as list, returns pakets and protocols found in
        (returns packet type as key so if found for multiple packets of same protocol,
        we can report to user)
        soi_data = [
                'center_freq',
                'modulation',
                'bandwidth',
                'continuous',
                'start_freq',
                'end_freq',
                'center_freq+-',
                'bandwidth+-',
                'start_freq+-',
                'end_freq+-'
            ]

        """
        # Find Matching SOI Data
        return_list = []

        # Check if soi_data is Empty
        soi_data_empty = True
        for get_item in soi_data:
            if get_item != "":
                soi_data_empty = False
                break

        if not soi_data_empty:
            # Get the SOI Data from the Library
            all_soi = fissure.utils.library.getAllSOIs(self.pd_library)

            # Cycle through each Protocol
            for protocol, soi_items in all_soi.items():
                soi_data_item_found = [False, False, False, False, False, False]
                and_cases = [True, True, True, True, True, True]

                # Cycle through each SOI
                for soi_item in soi_items:

                    # Cycle through each SOI Data Element
                    for n in range(0, len(soi_data_item_found)):
                        # Check if the Element is Empty (Don't Search For It)
                        if soi_data[n] == "":
                            soi_data_item_found[n] = False
                            and_cases[n] = False
                        else:
                            # Frequency
                            if n == 0:
                                if (
                                    float(soi_data[n]) - float(soi_data[6]) <= float(soi_items[soi_item]["Frequency"])
                                ) and (
                                    float(soi_data[n]) + float(soi_data[6]) >= float(soi_items[soi_item]["Frequency"])
                                ):
                                    soi_data_item_found[n] = True
                            # Modulation
                            if n == 1:
                                if (
                                    soi_data[n].lower() in soi_items[soi_item]["Modulation"].lower()
                                ):  # Not case-specific
                                    soi_data_item_found[n] = True
                            # Bandwidth
                            if n == 2:
                                if (
                                    float(soi_data[n]) - float(soi_data[7]) <= float(soi_items[soi_item]["Bandwidth"])
                                ) and (
                                    float(soi_data[n]) + float(soi_data[7]) >= float(soi_items[soi_item]["Bandwidth"])
                                ):
                                    soi_data_item_found[n] = True
                            # Continuous
                            if n == 3:
                                if soi_data[n] == str(soi_items[soi_item]["Continuous"]):
                                    soi_data_item_found[n] = True
                            # Start Frequency
                            if n == 4:
                                if (
                                    float(soi_data[n]) - float(soi_data[8])
                                    <= float(soi_items[soi_item]["Start Frequency"])
                                ) and (
                                    float(soi_data[n]) + float(soi_data[8])
                                    >= float(soi_items[soi_item]["Start Frequency"])
                                ):
                                    soi_data_item_found[n] = True
                            # End Frequency
                            if n == 5:
                                if (
                                    float(soi_data[n]) - float(soi_data[9])
                                    <= float(soi_items[soi_item]["End Frequency"])
                                ) and (
                                    float(soi_data[n]) + float(soi_data[9])
                                    >= float(soi_items[soi_item]["End Frequency"])
                                ):
                                    soi_data_item_found[n] = True

                    # Save the SOI if there is a Match
                    if and_cases == soi_data_item_found:
                        soi_items[soi_item]["Protocol"] = protocol
                        return_dict = {}
                        return_dict.update({soi_item: soi_items[soi_item]})
                        return_list.append(return_dict)

                    # Reset
                    soi_data_item_found = [False, False, False, False, False, False]

        # Find Matching Field Data
        # Check if Field Data is Empty
        field_data_empty = True
        packet_type_protocol_dict = {}
        if field_data != "":
            field_data_empty = False

            # Get the Defaults from the Library
            def_dict = {}
            for prots in fissure.utils.library.getProtocols(self.pd_library):
                for pkts in fissure.utils.library.getPacketTypes(self.pd_library, prots):
                    mydefs = fissure.utils.library.getDefaults(self.pd_library, prots, pkts)
                    mydefs = "".join(mydefs).replace(" ", "")
                    if mydefs:
                        # ~ mydefs = str(hex(int(mydefs,2))[2:-1])  # Convert to Hex

                        # Update the Complete "Protocol:Packet Type:Default Hex Values" Dictionary
                        if prots in def_dict.keys():
                            def_dict[prots].update({pkts: mydefs})
                        else:
                            def_dict.update({prots: {pkts: mydefs}})

            # Search for Field Data Instances in the Entire Hex Dictionary of the Packet Types,
            # Returns {Packet Type: Protocol}
            for protocols, vals in def_dict.items():
                for packets, packet_vals in vals.items():
                    if field_data in packet_vals:
                        packet_type_protocol_dict[packets] = {
                            "End Frequency": "",
                            "Protocol": protocols,
                            "Modulation": "",
                            "Notes": "",
                            "Continuous": "",
                            "Bandwidth": "",
                            "Frequency": "",
                            "Start Frequency": "",
                        }

        # field_data Attempted to Search
        if not field_data_empty:
            return_list.append(packet_type_protocol_dict)


        return return_list


    # def readBits(self):
    #     """Read all the data in the bit listener and handle it accordingly."""
    #     # PD is Running
    #     if not self.gr_processing.is_set():
    #         # had trouble that protocol discovery was starting up before flowgraph was loading
    #         # giving Sensor Node 0.25 secs to start, then we start threading the preambles
    #         # this can be adjusted if necessary later, or if running non-locally
    #         time.sleep(1)

    #         # starts threaded callback to return value to HIPRFISR
    #         if self.finding_preambles:
    #             if len(self.circular_buffer) >= self.min_buffer:
    #                 # ~ print("Searching for preambles")
    #                 self.finding_preambles = False
    #                 self.findPreambles()
    #             else:
    #                 pass
    #                 # ~ print("Filling Buffer...")
    #         else:
    #             try:
    #                 # ~ print("waiting for Preamble return from thread")
    #                 self.FindPreamblesThreaded.returnval
    #             except AttributeError:
    #                 # Thread Hasn't Returned Yet
    #                 pass
    #             else:
    #                 # Starts Threaded Callback to Search Library with already Searched Return Value
    #                 # (could also do this from HIPRFISR/Dashboard Selected result
    #                 if self.lib_search:
    #                     self.lib_search = False
    #                     self.findPreamblesInLibrary(list(self.FindPreamblesThreaded.returnval.keys())[0])

    # ~ def findPacketLengths(data,preambles):
    # ~ """ Finds the packet lengths of the data for each selected preamble???
    # ~ """
    # ~ packet_lengths = {}
    # ~ for preamble in preambles:
    # ~ idxs = findAll(data,preamble)
    # ~ packet_lengths.update({preamble: Counter(np.diff(idxs))})

    # ~ def listensocket():
    # ~ """ Not used yet.
    # ~ """
    # ~ c = zmq.Context()
    # ~ s = c.socket(zmq.SUB)
    # ~ s.setsockopt(zmq.SUBSCRIBE,'')
    # ~ s.connect("tcp://localhost:5555")
    # ~ alphabet='01'


    def longestCommonSubstring(self, s1, s2):
        """Returns the longest common substring between two strings."""
        m = [[0] * (1 + len(s2)) for i in range(1 + len(s1))]
        longest, x_longest = 0, 0
        for x in range(1, 1 + len(s1)):
            for y in range(1, 1 + len(s2)):
                if s1[x - 1] == s2[y - 1]:
                    m[x][y] = m[x - 1][y - 1] + 1
                    if m[x][y] > longest:
                        longest = m[x][y]
                        x_longest = x
                else:
                    m[x][y] = 0
        return s1[(x_longest - longest) : x_longest]


    def findCommonSubs(self, data, winmin, winmax, topx):
        """Searches a sliding window for the most common substrings within."""
        frequent_common_subs = {}
        for winlen in range(winmin, winmax + 1):
            frequent_common_subs.update(
                Counter(data[i : (i + winlen)] for i in range(len(data) - winlen)).most_common(topx)
            )
        return frequent_common_subs


    def findAll(self, findin, tofind):
        """Finds all matching strings in a string?"""
        return [idxs.start() for idxs in re.finditer(tofind.lower(), findin.lower())]


    def slicingStats(self, preambles, datablob):
        """Calculates the slicing stats for each preamble."""
        slicestats = {}
        idxs = {}
        for preamble in preambles.keys():
            idxs = self.findAll(datablob, preamble)
            mdian = np.median(np.diff(idxs))
            meanie = np.mean(np.diff(idxs))
            stddev = np.std(np.diff(idxs))
            slicestats.update({preamble: (len(preamble), mdian, meanie, stddev, preambles[preamble])})
        return slicestats


    def findPreambles(self):
        """
        Find topx most common preambles that are between winmin and winmax
        that are within num_std standard deviations of the mean length (we assume
        a single type of packet is more common than the others).
        """
        data = self.circular_buffer
        winmin = self.min_size
        winmax = self.max_size
        topx = self.ranking
        num_std_dev = self.num_std

        # Find Frequent Common Substrings as Initial Guess at Preamble
        fcs = self.findCommonSubs(data, winmin, winmax, topx)  # Return the top values to the Dashboard?

        # Calculate Number of Packets in Data Blob, Median/Mean Length, Length Variance
        # When Sliced with that Preamble, and Length of Preamble
        slice_medians = self.slicingStats(fcs, data)

        # Filter Preambles that Minimize (within 2) Standard Deviation on Packet Length
        # (i.e. only Looking for one Packet Type)
        min_std_dev = np.min(list(zip(*slice_medians.values()))[3])

        # we could also filter out preambles that don't contain the most common
        # "letters" of the alphabet over the data blob, but that's for a future task
        min_std_dev_preambles = {
            keys: values for keys, values in slice_medians.items() if values[3] <= num_std_dev * min_std_dev
        }

        # Find the Median Number of Slices Across all Preambles
        # (preambles that produce the average number of packets should be a common enough preamble)
        # print(min_std_dev_preambles.values())
        median_num_slices = np.floor(np.median(list(zip(*min_std_dev_preambles.values()))[4]))

        # Find the Median Packet Length when using those Preambles
        # (we're assuming a single type of packet pops up more than others to give us a bit of something to go on)
        # median_length = np.median(list(zip(*slice_medians.values()))[1])  # Not used?

        # Filter out Preambles that don't give us the Median Number of Slices
        # (we're allowing for multiple preambles to pass through)
        candidate_preambles = {
            keys: values for keys, values in slice_medians.items() if values[4] == median_num_slices
        }  # Not used?

        # Pick the Longest Preambles of those that are Left
        # (the longest common substring that minimizes the standard deviation and produces packets of the median length)
        max_length_min_std_dev = np.max(list(zip(*min_std_dev_preambles.values()))[0])
        min_std_dev_max_length_preambles = {
            keys: values for keys, values in min_std_dev_preambles.items() if values[0] == max_length_min_std_dev
        }

        # ~ print("FCS")
        # ~ print(fcs)
        # ~ print("SLICE MEDIANS")
        # ~ print(slice_medians)
        # ~ print("MIN STD DEV")
        # ~ print(min_std_dev)
        # ~ print("MIN STD DEV PREAMBLES")
        # ~ print(min_std_dev_preambles)
        # ~ print("MEDIAN LENGTH")
        # ~ print(median_length)
        # ~ print("CANDIDATE PREAMBLES")
        # ~ print(candidate_preambles)
        # ~ print("MAX LENGTH MIN STD DEV")
        # ~ print(max_length_min_std_dev)
        # ~ print("MIN STD DEV MAX LENGTH PREAMBLES")
        # ~ print(min_std_dev_max_length_preambles)

        # 
        # return [slice_medians, candidate_preambles, min_std_dev_max_length_preambles]

        # Send the Message
        asyncio.run(self.findPreamblesReturn(slice_medians, candidate_preambles, min_std_dev_max_length_preambles))


    async def findPreamblesReturn(self, slice_medians, candidate_preambles, min_std_dev_max_length_preambles):
        """
        Sends potential preambles found in the circular buffer to the HIPRFISR/Dashboard.
        """
        PARAMETERS = {
            "slice_medians": slice_medians,
            "candidate_preambles": candidate_preambles,
            "min_std_dev_max_length_preambles": min_std_dev_max_length_preambles,
        }
        msg = {
            fissure.comms.MessageFields.IDENTIFIER: self.identifier,
            fissure.comms.MessageFields.MESSAGE_NAME: "findPreamblesReturn",
            fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
        }
        await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


    def findEntropy(self, message_length, preamble):
        """Finds the entropy for the bit positions of a fixed length message."""
        # Take a Snapshot of the Buffer
        current_buffer = self.circular_buffer

        # Get the Preamble Locations in the Data
        idxs = self.findAll(current_buffer, preamble)

        # Get Packets of Length 'message_length'
        packet_list = []
        idxs_diff = np.diff(idxs)
        for n in range(0, len(idxs_diff)):
            if idxs_diff[n] >= int(message_length / 4):  # Message Length is in Bits, Divide by Four Converts to Hex
                packet_list.append(current_buffer[idxs[n] : idxs[n] + int(message_length / 4)])

        # Convert Hex to Binary
        binary_packet_list = []
        # ~ print(len(packet_list))
        for packet in packet_list:
            hex_len = len(packet)
            bin_str = bin(int(packet, 16))[2:].zfill(hex_len * 4)
            binary_packet_list.append(bin_str)

        # Convert Packets into Lists of Bit Positions
        # ~ print(len(binary_packet_list[0]))
        bit_pos = []
        for i in range(0, len(binary_packet_list[0])):
            bit_pos.append([])
        for i in binary_packet_list:
            for j in range(0, len(i)):
                bit_pos[j].append(i[j])

        # Find Entropy for Bit Positions
        ents = []
        for bit in range(0, len(bit_pos)):
            ent = self.calculateEntropy(bit_pos[bit])
            ents.append(ent)

        # Send the Message to the HIPRFISR
        asyncio.run(self.findEntropyFinished(ents))
    

    async def findEntropyFinished(self, ents):
        """ 
        Returns the findEntropy results to the HIPRFISR/Dashboard.
        """
        # Send Message
        PARAMETERS = {"ents": ents}
        msg = {
            fissure.comms.MessageFields.IDENTIFIER: self.identifier,
            fissure.comms.MessageFields.MESSAGE_NAME: "findEntropyReturn",
            fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
        }
        await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


    def calculateEntropy(self, vals):
        """Calculates Entropy for a list of values."""
        # Calculate Entropy
        num_vals = len(vals)
        counts = np.bincount(vals)
        if len(counts) == 1:
            counts = np.array([counts[0], 0])
        if len(counts) != 2:
            pass
            # ~ raise ValueError('Error calculating entropy. Unexpected number of counts.')
        freqs = counts / float(num_vals)
        ent = 0.0
        for val in freqs:
            if val != 0:
                ent += val * np.log2(val)
        if ent < 0:
            ent = -ent

        # Round Entropy
        ent = round(ent, 2)

        return ent


if __name__ == "__main__":
    rc = 0
    try:
        run()
    except Exception:
        rc = 1

    sys.exit(rc)
