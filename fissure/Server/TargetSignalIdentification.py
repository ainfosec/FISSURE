from inspect import isfunction
from scipy.fftpack import fft, next_fast_len
from types import ModuleType
from typing import Dict

import asyncio
import fissure.callbacks
import fissure.comms
import fissure.utils
import logging
import numpy as np
import os
import scipy.stats as stats
import struct
import subprocess
import sys
import time
import uuid
import zmq

HEARTBEAT_LOOP_DELAY = 0.1  # Seconds
EVENT_LOOP_DELAY = 0.1

def run():
    asyncio.run(main())


async def main():
    """
    Server __main__.py does not call this function. Do not edit! Edit __init__() or begin().
    """
    # Initialize TSI
    # sys.path.insert(0, os.path.join(fissure.utils.FISSURE_ROOT, "Flow Graph Library", "TSI Flow Graphs"))
    print("[FISSURE][TargetSignalIdentification] start")
    tsi = TargetSignalIdentification()

    # Start Event Loop
    await tsi.begin()

    # End and Clean Up
    print("[FISSURE][TargetSignalIdentification] end")
    fissure.utils.zmq_cleanup()


class TargetSignalIdentification:
    """Fissure TargetSignalIdentification Class"""

    settings: Dict
    identifier: str = fissure.comms.Identifiers.TSI
    logger: logging.Logger = fissure.utils.get_logger(fissure.comms.Identifiers.TSI)
    ip_address: str
    hiprfisr_address: str
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

        # Initialize Connection/Heartbeat Variables
        self.heartbeats = {
            fissure.comms.Identifiers.HIPRFISR: None,
            fissure.comms.Identifiers.TSI: None,
        }
        self.hiprfisr_connected = False

        # Initialze ZMQ Nodes
        self.initialize_comms()

        self.shutdown = False
        self.conditioner_running = False
        self.fe_running = False

        # Register Callbacks
        self.register_callbacks(fissure.callbacks.GenericCallbacks)
        self.register_callbacks(fissure.callbacks.TargetSignalIdentificationCallbacks)

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


    async def heartbeat_loop(self):
        """
        Sends and reads heartbeat messages, separate from event loop to prevent freezing on blocking events.
        """
        while self.shutdown is False:
            # Heartbeats
            await self.send_heartbeat()
            await self.recv_heartbeat()
            self.check_heartbeat()

            await asyncio.sleep(HEARTBEAT_LOOP_DELAY)


    async def begin(self):
        self.logger.info("=== STARTING TARGET SIGNAL IDENTIFICATION COMPONENT ===")

        # Connect to HiprFisr
        if await self.hiprfisr_socket.connect(self.hiprfisr_address):
            self.logger.info(f"connected to HiprFisr @ {self.hiprfisr_address}")

        # Start Heartbeat Loop
        heartbeat_task = asyncio.create_task(self.heartbeat_loop())

        # Main Event Loop
        while self.shutdown is False:
            # Process Incoming Messages
            await self.read_HIPRFISR_messages()

            await asyncio.sleep(EVENT_LOOP_DELAY)

        # Ensure the Heartbeat Loop is Stopped
        heartbeat_task.cancel()
        try:
            await heartbeat_task
        except asyncio.CancelledError:
            pass  # Heartbeat task was cancelled cleanly

        # Clean Up
        if self.conditioner_running == True:
            self.conditioner_running = False
            await asyncio.sleep(2)
        if self.fe_running == True:
            self.fe_running = False
            await asyncio.sleep(2)

        await self.shutdown_comms()
        self.logger.info("=== SHUTDOWN ===")


    async def send_heartbeat(self):
        """
        Send Hearbeat Message
        """
        last_heartbeat = self.heartbeats[fissure.comms.Identifiers.TSI]
        now = time.time()
        if (last_heartbeat is None) or (now - last_heartbeat) >= float(self.settings.get("heartbeat_interval")):
            heartbeat = {
                fissure.comms.MessageFields.IDENTIFIER: fissure.comms.Identifiers.TSI,
                fissure.comms.MessageFields.MESSAGE_NAME: fissure.comms.MessageFields.HEARTBEAT,
                fissure.comms.MessageFields.TIME: now,
                fissure.comms.MessageFields.IP: self.ip_address,
            }
            await self.hiprfisr_socket.send_heartbeat(heartbeat)
            self.heartbeats[fissure.comms.Identifiers.TSI] = now
            self.logger.debug(f"sent heartbeat {fissure.utils.get_timestamp(now)}")


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
        parsed = ""
        while parsed is not None:
            parsed = await self.hiprfisr_socket.recv_msg()
            if parsed is not None:
                type = parsed.get(fissure.comms.MessageFields.TYPE)
                if type == fissure.comms.MessageTypes.HEARTBEATS:
                    self.logger.warning("received heartbeat on message channel")
                elif type == fissure.comms.MessageTypes.COMMANDS:
                    await self.hiprfisr_socket.run_callback(self, parsed)
                elif type == fissure.comms.MessageTypes.STATUS:
                    # TODO
                    pass


    def updateLoggingLevels(self, new_console_level="", new_file_level=""):
        """
        Update the logging levels on TSI.
        """
        # Update New Levels for the HIPRFISR
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


    def startTSI_ConditionerThread(
        self,
        common_parameter_names,
        common_parameter_values,
        method_parameter_names,
        method_parameter_values,
    ):
        """
        Performs the signal conditioning actions.
        """
        # Common Parameters
        for n in range(len(common_parameter_names)):
            if common_parameter_names[n] == "category":
                get_category = common_parameter_values[n]
            elif common_parameter_names[n] == "method":
                get_method = common_parameter_values[n]
            elif common_parameter_names[n] == "output_directory":
                get_output_directory = common_parameter_values[n]
            elif common_parameter_names[n] == "prefix":
                get_prefix = common_parameter_values[n]
            elif common_parameter_names[n] == "sample_rate":
                get_sample_rate = common_parameter_values[n]
            elif common_parameter_names[n] == "tuned_frequency":
                get_tuned_freq = common_parameter_values[n]
            elif common_parameter_names[n] == "data_type":
                get_type = common_parameter_values[n]
            # elif common_parameter_names[n] == "max_files":
            #     get_max_files = common_parameter_values[n]
            elif common_parameter_names[n] == "min_samples":
                get_min_samples = common_parameter_values[n]
            elif common_parameter_names[n] == "all_filepaths":
                get_all_filepaths = common_parameter_values[n]
            elif common_parameter_names[n] == "detect_saturation":
                get_detect_saturation = common_parameter_values[n]
            elif common_parameter_names[n] == "saturation_min":
                get_saturation_min = common_parameter_values[n]
            elif common_parameter_names[n] == "saturation_max":
                get_saturation_max = common_parameter_values[n]
            elif common_parameter_names[n] == "normalize_output":
                get_normalize_output = common_parameter_values[n]
            elif common_parameter_names[n] == "normalize_min":
                try:
                    get_normalize_min = float(common_parameter_values[n])
                except (TypeError, ValueError):
                    get_normalize_min = ""
            elif common_parameter_names[n] == "normalize_max":
                try:
                    get_normalize_max = float(common_parameter_values[n])
                except (TypeError, ValueError):
                    get_normalize_max = ""

        # Flow Graph Directory
        if get_type == "Complex Float 32":
            fg_directory = os.path.join(
                fissure.utils.get_fg_library_dir(self.os_info),
                "TSI Flow Graphs",
                "Conditioner",
                "Flow_Graphs",
                "ComplexFloat32",
            )
        elif get_type == "Complex Int 16":
            fg_directory = os.path.join(
                fissure.utils.get_fg_library_dir(self.os_info), "TSI Flow Graphs", "Conditioner", "Flow_Graphs", "ComplexInt16"
            )

        # Method1: burst_tagger
        if (get_category == "Energy - Burst Tagger") and (get_method == "Normal"):
            count = 0
            new_files = []
            original_filenames = []

            # Create a List of Files in Output Directory
            if get_output_directory != "":
                file_names = []
                for fname in os.listdir(get_output_directory):
                    if os.path.isfile(os.path.join(get_output_directory, fname)):
                        file_names.append(fname)

            for n in range(0, len(get_all_filepaths)):

                # Stop Conditioner Triggered
                if self.conditioner_running == False:
                    self.logger.info("TSI Conditioner Stopped")
                    return

                # Update Progress Bar
                progress_value = 1 + int((float((n + 1) / len(get_all_filepaths)) * 90))
                asyncio.run(self.conditionerProgressBarReturn(progress_value, n))
                
                # Method Parameters
                for m in range(len(method_parameter_names)):
                    if method_parameter_names[m] == "threshold":
                        get_threshold = method_parameter_values[m]

                # Run the Flow Graph
                cmd = (
                    "python3 '"
                    + fg_directory
                    + "/burst_tagger/normal.py' --filepath '"
                    + get_all_filepaths[n]
                    + "' --sample-rate "
                    + get_sample_rate
                    + " --threshold "
                    + get_threshold
                )
                p1 = subprocess.Popen(cmd, shell=True, cwd=get_output_directory)
                (output, err) = p1.communicate()
                p1.wait()

                # Rename the New Files
                if get_output_directory != "":
                    for fname in os.listdir(get_output_directory):
                        if os.path.isfile(os.path.join(get_output_directory, fname)):
                            if fname not in file_names:
                                count = count + 1
                                os.rename(
                                    os.path.join(get_output_directory, fname),
                                    os.path.join(get_output_directory, get_prefix + str(count).zfill(5) + ".iq"),
                                )
                                new_files.append(get_prefix + str(count).zfill(5) + ".iq")
                                file_names.append(get_prefix + str(count).zfill(5) + ".iq")
                                original_filenames.append(get_all_filepaths[n])

            # Update Progress Bar
            progress_value = 95
            asyncio.run(self.conditionerProgressBarReturn(progress_value, n))

        # Method2: burst_tagger with Decay
        elif (get_category == "Energy - Burst Tagger") and (get_method == "Normal Decay"):
            count = 0
            new_files = []
            original_filenames = []

            # Create a List of Files in Output Directory
            if get_output_directory != "":
                file_names = []
                for fname in os.listdir(get_output_directory):
                    if os.path.isfile(os.path.join(get_output_directory, fname)):
                        file_names.append(fname)

            for n in range(0, len(get_all_filepaths)):

                # Stop Conditioner Triggered
                if self.conditioner_running == False:
                    self.logger.info("TSI Conditioner Stopped")
                    return

                # Update Progress Bar
                progress_value = 1 + int((float((n + 1) / len(get_all_filepaths)) * 90))
                asyncio.run(self.conditionerProgressBarReturn(progress_value, n))

                # Method Parameters
                for m in range(len(method_parameter_names)):
                    if method_parameter_names[m] == "threshold":
                        get_threshold = method_parameter_values[m]
                    elif method_parameter_names[m] == "decay":
                        get_decay = method_parameter_values[m]

                # Run the Flow Graph
                cmd = (
                    "python3 '"
                    + fg_directory
                    + "/burst_tagger/normal_decay.py' --filepath '"
                    + get_all_filepaths[n]
                    + "' --sample-rate "
                    + get_sample_rate
                    + " --threshold "
                    + get_threshold
                    + " --decay "
                    + get_decay
                )
                p1 = subprocess.Popen(cmd, shell=True, cwd=get_output_directory)
                (output, err) = p1.communicate()
                p1.wait()

                # Rename the New Files
                if get_output_directory != "":
                    for fname in os.listdir(get_output_directory):
                        if os.path.isfile(os.path.join(get_output_directory, fname)):
                            if fname not in file_names:
                                count = count + 1
                                os.rename(
                                    os.path.join(get_output_directory, fname),
                                    os.path.join(get_output_directory, get_prefix + str(count).zfill(5) + ".iq"),
                                )
                                new_files.append(get_prefix + str(count).zfill(5) + ".iq")
                                file_names.append(get_prefix + str(count).zfill(5) + ".iq")
                                original_filenames.append(get_all_filepaths[n])

            # Update Progress Bar
            progress_value = 95
            asyncio.run(self.conditionerProgressBarReturn(progress_value, n))

        # Method3: power_squelch_with_burst_tagger
        elif (get_category == "Energy - Burst Tagger") and (get_method == "Power Squelch"):
            count = 0
            new_files = []
            original_filenames = []

            # Create a List of Files in Output Directory
            if get_output_directory != "":
                file_names = []
                for fname in os.listdir(get_output_directory):
                    if os.path.isfile(os.path.join(get_output_directory, fname)):
                        file_names.append(fname)

            for n in range(0, len(get_all_filepaths)):

                # Stop Conditioner Triggered
                if self.conditioner_running == False:
                    self.logger.info("TSI Conditioner Stopped")
                    return

                # Update Progress Bar
                progress_value = 1 + int((float((n + 1) / len(get_all_filepaths)) * 90))
                asyncio.run(self.conditionerProgressBarReturn(progress_value, n))

                # Method Parameters
                for m in range(len(method_parameter_names)):
                    if method_parameter_names[m] == "squelch":
                        get_squelch = method_parameter_values[m]
                    elif method_parameter_names[m] == "threshold":
                        get_threshold = method_parameter_values[m]

                # Run the Flow Graph
                cmd = (
                    "python3 '"
                    + fg_directory
                    + "/burst_tagger/power_squelch.py' --filepath '"
                    + get_all_filepaths[n]
                    + "' --sample-rate "
                    + get_sample_rate
                    + " --threshold "
                    + get_threshold
                    + " --squelch "
                    + get_squelch
                )
                p1 = subprocess.Popen(cmd, shell=True, cwd=get_output_directory)
                (output, err) = p1.communicate()
                p1.wait()

                # Rename the New Files
                if get_output_directory != "":
                    for fname in os.listdir(get_output_directory):
                        if os.path.isfile(os.path.join(get_output_directory, fname)):
                            if fname not in file_names:
                                count = count + 1
                                os.rename(
                                    os.path.join(get_output_directory, fname),
                                    os.path.join(get_output_directory, get_prefix + str(count).zfill(5) + ".iq"),
                                )
                                new_files.append(get_prefix + str(count).zfill(5) + ".iq")
                                file_names.append(get_prefix + str(count).zfill(5) + ".iq")
                                original_filenames.append(get_all_filepaths[n])

            # Update Progress Bar
            progress_value = 95
            asyncio.run(self.conditionerProgressBarReturn(progress_value, n))

        # Method4: lowpass_filter
        elif (get_category == "Energy - Burst Tagger") and (get_method == "Lowpass"):
            count = 0
            new_files = []
            original_filenames = []

            # Create a List of Files in Output Directory
            if get_output_directory != "":
                file_names = []
                for fname in os.listdir(get_output_directory):
                    if os.path.isfile(os.path.join(get_output_directory, fname)):
                        file_names.append(fname)

            for n in range(0, len(get_all_filepaths)):

                # Stop Conditioner Triggered
                if self.conditioner_running == False:
                    self.logger.info("TSI Conditioner Stopped")
                    return

                # Update Progress Bar
                progress_value = 1 + int((float((n + 1) / len(get_all_filepaths)) * 90))
                asyncio.run(self.conditionerProgressBarReturn(progress_value, n))

                # Method Parameters
                for m in range(len(method_parameter_names)):
                    if method_parameter_names[m] == "threshold":
                        get_threshold = method_parameter_values[m]
                    elif method_parameter_names[m] == "cutoff":
                        get_cutoff = method_parameter_values[m]
                    elif method_parameter_names[m] == "transition":
                        get_transition = method_parameter_values[m]
                    elif method_parameter_names[m] == "beta":
                        get_beta = method_parameter_values[m]

                # Run the Flow Graph
                cmd = (
                    "python3 '"
                    + fg_directory
                    + "/burst_tagger/lowpass.py' --filepath '"
                    + get_all_filepaths[n]
                    + "' --sample-rate "
                    + get_sample_rate
                    + " --threshold "
                    + get_threshold
                    + " --cutoff-freq "
                    + get_cutoff
                    + " --transition-width "
                    + get_transition
                    + " --beta "
                    + get_beta
                )
                p1 = subprocess.Popen(cmd, shell=True, cwd=get_output_directory)
                (output, err) = p1.communicate()
                p1.wait()

                # Rename the New Files
                if get_output_directory != "":
                    for fname in os.listdir(get_output_directory):
                        if os.path.isfile(os.path.join(get_output_directory, fname)):
                            if fname not in file_names:
                                count = count + 1
                                os.rename(
                                    os.path.join(get_output_directory, fname),
                                    os.path.join(get_output_directory, get_prefix + str(count).zfill(5) + ".iq"),
                                )
                                new_files.append(get_prefix + str(count).zfill(5) + ".iq")
                                file_names.append(get_prefix + str(count).zfill(5) + ".iq")
                                original_filenames.append(get_all_filepaths[n])

            # Update Progress Bar
            progress_value = 95
            asyncio.run(self.conditionerProgressBarReturn(progress_value, n))

        # Method5: power_squelch_lowpass
        elif (get_category == "Energy - Burst Tagger") and (get_method == "Power Squelch then Lowpass"):
            count = 0
            new_files = []
            original_filenames = []

            # Create a List of Files in Output Directory
            if get_output_directory != "":
                file_names = []
                for fname in os.listdir(get_output_directory):
                    if os.path.isfile(os.path.join(get_output_directory, fname)):
                        file_names.append(fname)

            for n in range(0, len(get_all_filepaths)):

                # Stop Conditioner Triggered
                if self.conditioner_running == False:
                    self.logger.info("TSI Conditioner Stopped")
                    return

                # Update Progress Bar
                progress_value = 1 + int((float((n + 1) / len(get_all_filepaths)) * 90))
                asyncio.run(self.conditionerProgressBarReturn(progress_value, n))

                # Method Parameters
                for m in range(len(method_parameter_names)):
                    if method_parameter_names[m] == "squelch":
                        get_squelch = method_parameter_values[m]
                    elif method_parameter_names[m] == "cutoff":
                        get_cutoff = method_parameter_values[m]
                    elif method_parameter_names[m] == "transition":
                        get_transition = method_parameter_values[m]
                    elif method_parameter_names[m] == "beta":
                        get_beta = method_parameter_values[m]
                    elif method_parameter_names[m] == "threshold":
                        get_threshold = method_parameter_values[m]

                # Run the Flow Graph
                cmd = (
                    "python3 '"
                    + fg_directory
                    + "/burst_tagger/power_squelch_lowpass.py' --filepath '"
                    + get_all_filepaths[n]
                    + "' --sample-rate "
                    + get_sample_rate
                    + " --threshold "
                    + get_threshold
                    + " --cutoff-freq "
                    + get_cutoff
                    + " --transition-width "
                    + get_transition
                    + " --beta "
                    + get_beta
                    + " --squelch "
                    + get_squelch
                )
                p1 = subprocess.Popen(cmd, shell=True, cwd=get_output_directory)
                (output, err) = p1.communicate()
                p1.wait()

                # Rename the New Files
                if get_output_directory != "":
                    for fname in os.listdir(get_output_directory):
                        if os.path.isfile(os.path.join(get_output_directory, fname)):
                            if fname not in file_names:
                                count = count + 1
                                os.rename(
                                    os.path.join(get_output_directory, fname),
                                    os.path.join(get_output_directory, get_prefix + str(count).zfill(5) + ".iq"),
                                )
                                new_files.append(get_prefix + str(count).zfill(5) + ".iq")
                                file_names.append(get_prefix + str(count).zfill(5) + ".iq")
                                original_filenames.append(get_all_filepaths[n])

            # Update Progress Bar
            progress_value = 95
            asyncio.run(self.conditionerProgressBarReturn(progress_value, n))

        # Method6: bandpass_filter
        elif (get_category == "Energy - Burst Tagger") and (get_method == "Bandpass"):
            count = 0
            new_files = []
            original_filenames = []

            # Create a List of Files in Output Directory
            if get_output_directory != "":
                file_names = []
                for fname in os.listdir(get_output_directory):
                    if os.path.isfile(os.path.join(get_output_directory, fname)):
                        file_names.append(fname)

            for n in range(0, len(get_all_filepaths)):

                # Stop Conditioner Triggered
                if self.conditioner_running == False:
                    self.logger.info("TSI Conditioner Stopped")
                    return

                # Update Progress Bar
                progress_value = 1 + int((float((n + 1) / len(get_all_filepaths)) * 90))
                asyncio.run(self.conditionerProgressBarReturn(progress_value, n))

                # Method Parameters
                for m in range(len(method_parameter_names)):
                    if method_parameter_names[m] == "bandpass_frequency":
                        get_bandpass_freq = method_parameter_values[m]
                    elif method_parameter_names[m] == "bandpass_width":
                        get_bandpass_width = method_parameter_values[m]
                    elif method_parameter_names[m] == "transition":
                        get_transition = method_parameter_values[m]
                    elif method_parameter_names[m] == "beta":
                        get_beta = method_parameter_values[m]
                    elif method_parameter_names[m] == "threshold":
                        get_threshold = method_parameter_values[m]

                # Run the Flow Graph
                cmd = (
                    "python3 '"
                    + fg_directory
                    + "/burst_tagger/bandpass.py' --filepath '"
                    + get_all_filepaths[n]
                    + "' --sample-rate "
                    + get_sample_rate
                    + " --threshold "
                    + get_threshold
                    + " --bandpass-freq "
                    + get_bandpass_freq
                    + " --transition-width "
                    + get_transition
                    + " --beta "
                    + get_beta
                    + " --bandpass-width "
                    + get_bandpass_width
                )
                p1 = subprocess.Popen(cmd, shell=True, cwd=get_output_directory)
                (output, err) = p1.communicate()
                p1.wait()

                # Rename the New Files
                if get_output_directory != "":
                    for fname in os.listdir(get_output_directory):
                        if os.path.isfile(os.path.join(get_output_directory, fname)):
                            if fname not in file_names:
                                count = count + 1
                                os.rename(
                                    os.path.join(get_output_directory, fname),
                                    os.path.join(get_output_directory, get_prefix + str(count).zfill(5) + ".iq"),
                                )
                                new_files.append(get_prefix + str(count).zfill(5) + ".iq")
                                file_names.append(get_prefix + str(count).zfill(5) + ".iq")
                                original_filenames.append(get_all_filepaths[n])

            # Update Progress Bar
            progress_value = 95
            asyncio.run(self.conditionerProgressBarReturn(progress_value, n))

        # Method7: strongest
        elif (get_category == "Energy - Burst Tagger") and (get_method == "Strongest Frequency then Bandpass"):
            # self.textEdit_tsi_settings_bt_sfb_freq.setPlainText("?")
            # self.textEdit_tsi_settings_bt_sfb_freq.setAlignment(QtCore.Qt.AlignCenter)
            count = 0
            new_files = []
            original_filenames = []

            # Create a List of Files in Output Directory
            if get_output_directory != "":
                file_names = []
                for fname in os.listdir(get_output_directory):
                    if os.path.isfile(os.path.join(get_output_directory, fname)):
                        file_names.append(fname)

            for n in range(0, len(get_all_filepaths)):

                # Stop Conditioner Triggered
                if self.conditioner_running == False:
                    self.logger.info("TSI Conditioner Stopped")
                    return

                # Update Progress Bar
                progress_value = 1 + int((float((n + 1) / len(get_all_filepaths)) * 90))
                asyncio.run(self.conditionerProgressBarReturn(progress_value, n))

                # Method Parameters
                for m in range(len(method_parameter_names)):
                    if method_parameter_names[m] == "fft_size":
                        get_fft_size = method_parameter_values[m]
                    elif method_parameter_names[m] == "fft_threshold":
                        get_fft_threshold = method_parameter_values[m]
                    elif method_parameter_names[m] == "bandpass_width":
                        get_bandpass_width = method_parameter_values[m]
                    elif method_parameter_names[m] == "transition":
                        get_transition = method_parameter_values[m]
                    elif method_parameter_names[m] == "beta":
                        get_beta = method_parameter_values[m]
                    elif method_parameter_names[m] == "threshold":
                        get_threshold = method_parameter_values[m]

                # Acquire Number of Samples
                file_bytes = os.path.getsize(get_all_filepaths[n])
                file_samples = "-1"
                if file_bytes > 0:
                    if get_type == "Complex Float 32":
                        file_samples = str(int(file_bytes / 8))
                    elif get_type == "Float/Float 32":
                        file_samples = str(int(file_bytes / 4))
                    elif get_type == "Short/Int 16":
                        file_samples = str(int(file_bytes / 2))
                    elif get_type == "Int/Int 32":
                        file_samples = str(int(file_bytes / 4))
                    elif get_type == "Byte/Int 8":
                        file_samples = str(int(file_bytes / 1))
                    elif get_type == "Complex Int 16":
                        file_samples = str(int(file_bytes / 4))
                    elif get_type == "Complex Int 8":
                        file_samples = str(int(file_bytes / 2))
                    elif get_type == "Complex Float 64":
                        file_samples = str(int(file_bytes / 16))
                    elif get_type == "Complex Int 64":
                        file_samples = str(int(file_bytes / 16))
                else:
                    continue

                # Where to Store Strongest Frequency Results
                peak_file_location = os.path.join(
                    fissure.utils.get_fg_library_dir(self.os_info), "TSI Flow Graphs", "Conditioner", "peaks.txt"
                )

                # Run the Flow Graph
                cmd = (
                    "python3 '"
                    + fg_directory
                    + "/fft/strongest.py' --filepath '"
                    + get_all_filepaths[n]
                    + "' --sample-rate "
                    + get_sample_rate
                    + " --fft-threshold "
                    + get_fft_threshold
                    + " --samples "
                    + file_samples
                    + " --peak-file-location "
                    + peak_file_location
                    + " --fft-size "
                    + get_fft_size
                )
                p1 = subprocess.Popen(cmd, shell=True, cwd=get_output_directory)
                (output, err) = p1.communicate()
                p1.wait()

                # Read the Frequency Result
                file = open(peak_file_location.replace("\\", ""), "r")
                freq_result = str(round(float(file.read()), 2))
                file.close()

                # Bandpass Filter is Applied to Negative and Positive Sides
                if float(freq_result) < 0:
                    freq_result = str(abs(float(freq_result)))

                # Avoid Errors with Filter Width
                if (float(freq_result) + float(get_bandpass_width) / 2) > float(get_sample_rate) / 2:
                    freq_result = str(float(get_sample_rate) / 2 - float(get_bandpass_width) / 2)
                elif (float(freq_result) - float(get_bandpass_width) / 2) < 0:
                    freq_result = str(float(get_bandpass_width) / 2)

                # Strongest Frequency Result
                self.logger.info("Strongest Frequency Detected at: " + str(freq_result))
                # self.textEdit_settings_bt_sfb_freq.setPlainText(freq_result)
                # self.textEdit_settings_bt_sfb_freq.setAlignment(QtCore.Qt.AlignCenter)
                # get_bandpass_freq = str(self.textEdit_settings_bt_sfb_freq.toPlainText())

                # Run the Bandpass Flow Graph
                cmd = (
                    "python3 '"
                    + fg_directory
                    + "/burst_tagger/bandpass.py' --filepath '"
                    + get_all_filepaths[n]
                    + "' --sample-rate "
                    + get_sample_rate
                    + " --threshold "
                    + get_threshold
                    + " --bandpass-freq "
                    + freq_result
                    + " --transition-width "
                    + get_transition
                    + " --beta "
                    + get_beta
                    + " --bandpass-width "
                    + get_bandpass_width
                )
                p1 = subprocess.Popen(cmd, shell=True, cwd=get_output_directory)
                (output, err) = p1.communicate()
                p1.wait()

                # Rename the New Files
                if get_output_directory != "":
                    for fname in os.listdir(get_output_directory):
                        if os.path.isfile(os.path.join(get_output_directory, fname)):
                            if fname not in file_names:
                                count = count + 1
                                os.rename(
                                    os.path.join(get_output_directory, fname),
                                    os.path.join(get_output_directory, get_prefix + str(count).zfill(5) + ".iq"),
                                )
                                new_files.append(get_prefix + str(count).zfill(5) + ".iq")
                                file_names.append(get_prefix + str(count).zfill(5) + ".iq")
                                original_filenames.append(get_all_filepaths[n])

            # Update Progress Bar
            progress_value = 95
            asyncio.run(self.conditionerProgressBarReturn(progress_value, n))

        # Invalid Method
        else:
            self.logger.error("Invalid method")
            self.finishedTSI_Conditioner()
            return

        # Remove Files with Too Few Samples
        temp_files = new_files
        for n, fname in reversed(list(enumerate(temp_files))):
            get_bytes = os.path.getsize(os.path.join(get_output_directory, fname))
            get_samples = "-1"
            if get_bytes > 0:
                if get_type == "Complex Float 32":
                    get_samples = int(get_bytes / 8)
                elif get_type == "Float/Float 32":
                    get_samples = int(get_bytes / 4)
                elif get_type == "Short/Int 16":
                    get_samples = int(get_bytes / 2)
                elif get_type == "Int/Int 32":
                    get_samples = int(get_bytes / 4)
                elif get_type == "Byte/Int 8":
                    get_samples = int(get_bytes / 1)
                elif get_type == "Complex Int 16":
                    get_samples = int(get_bytes / 4)
                elif get_type == "Complex Int 8":
                    get_samples = int(get_bytes / 2)
                elif get_type == "Complex Float 64":
                    get_samples = int(get_bytes / 16)
                elif get_type == "Complex Int 64":
                    get_samples = int(get_bytes / 16)

            # Remove File
            if get_samples < get_min_samples:
                temp_files.pop(n)
        new_files = temp_files

        # # File Count
        # file_count = str(len(new_files))

        # Generate Results for Table
        table_strings = []
        for n, fname in enumerate(new_files):
            new_table_row = ["", "", "", "", "", "", "", "", ""]

            # Filename
            new_table_row[0] = fname

            # File Size
            get_bytes = os.path.getsize(os.path.join(get_output_directory, fname))
            new_table_row[1] = str(round(get_bytes / 1048576, 2))

            # Samples
            get_samples = "-1"
            if get_bytes > 0:
                if get_type == "Complex Float 32":
                    get_samples = str(int(get_bytes / 8))
                elif get_type == "Float/Float 32":
                    get_samples = str(int(get_bytes / 4))
                elif get_type == "Short/Int 16":
                    get_samples = str(int(get_bytes / 2))
                elif get_type == "Int/Int 32":
                    get_samples = str(int(get_bytes / 4))
                elif get_type == "Byte/Int 8":
                    get_samples = str(int(get_bytes / 1))
                elif get_type == "Complex Int 16":
                    get_samples = str(int(get_bytes / 4))
                elif get_type == "Complex Int 8":
                    get_samples = str(int(get_bytes / 2))
                elif get_type == "Complex Float 64":
                    get_samples = str(int(get_bytes / 16))
                elif get_type == "Complex Int 64":
                    get_samples = str(int(get_bytes / 16))
            new_table_row[2] = str(get_samples)

            # Format
            new_table_row[3] = get_type

            # Sample Rate
            new_table_row[4] = get_sample_rate

            # Saturated
            new_table_row[5] = ""
            if get_detect_saturation == "True":
                get_original_file = os.path.join(get_output_directory, fname)
                if (len(get_original_file) > 0) and (len(fname) > 0):
                    # Read the Data
                    file = open(get_original_file, "rb")
                    plot_data = file.read()
                    file.close()

                    # Complex Float 64
                    if get_type == "Complex Float 64":
                        # Normalize and Write
                        number_of_bytes = os.path.getsize(get_original_file)
                        plot_data_formatted = struct.unpack(int(number_of_bytes / 8) * "d", plot_data)
                        np_data = np.asarray(plot_data_formatted, dtype=np.float64)
                        array_min = float(min(np_data))
                        array_max = float(max(np_data))

                    # Complex Float 32
                    elif (get_type == "Complex Float 32") or (get_type == "Float/Float 32"):
                        # Normalize and Write
                        number_of_bytes = os.path.getsize(get_original_file)
                        plot_data_formatted = struct.unpack(int(number_of_bytes / 4) * "f", plot_data)
                        np_data = np.asarray(plot_data_formatted, dtype=np.float32)
                        array_min = float(min(np_data))
                        array_max = float(max(np_data))

                    # Complex Int 16
                    elif (get_type == "Complex Int 16") or (get_type == "Short/Int 16"):
                        # Convert and Write
                        number_of_bytes = os.path.getsize(get_original_file)
                        plot_data_formatted = struct.unpack(int(number_of_bytes / 2) * "h", plot_data)
                        np_data = np.array(plot_data_formatted, dtype=np.int16)
                        array_min = float(min(np_data))
                        array_max = float(max(np_data))

                    # Complex Int 64
                    elif get_type == "Complex Int 64":
                        # Convert and Write
                        number_of_bytes = os.path.getsize(get_original_file)
                        plot_data_formatted = struct.unpack(int(number_of_bytes / 8) * "l", plot_data)
                        np_data = np.array(plot_data_formatted, dtype=np.int64)
                        array_min = float(min(np_data))
                        array_max = float(max(np_data))

                    # Int/Int 32
                    elif get_type == "Int/Int 32":
                        # Convert and Write
                        number_of_bytes = os.path.getsize(get_original_file)
                        plot_data_formatted = struct.unpack(int(number_of_bytes / 4) * "h", plot_data)
                        np_data = np.array(plot_data_formatted, dtype=np.int32)
                        array_min = float(min(np_data))
                        array_max = float(max(np_data))

                    # Complex Int 8
                    elif (get_type == "Complex Int 8") or (get_type == "Byte/Int 8"):
                        # Convert and Write
                        number_of_bytes = os.path.getsize(get_original_file)
                        plot_data_formatted = struct.unpack(int(number_of_bytes) * "b", plot_data)
                        np_data = np.array(plot_data_formatted, dtype=np.int8)
                        array_min = float(min(np_data))
                        array_max = float(max(np_data))

                    # Unknown
                    else:
                        self.logger.error("Cannot normalize " + get_type + ".")

                    # Detect
                    if (array_min <= float(get_saturation_min)) or (array_max >= float(get_saturation_max)):
                        new_table_row[5] = "Yes"
                    else:
                        new_table_row[5] = "No"

            # Tuned Frequency
            new_table_row[6] = get_tuned_freq

            # Source
            new_table_row[7] = original_filenames[n]

            # Notes
            new_table_row[8] = ""

            # Append the Row
            table_strings.append(new_table_row)

        # Normalize Output
        if get_normalize_output == "True":
            # Load the Data
            get_original_file = os.path.join(get_output_directory,fname)
            get_new_file = get_original_file

            # Files Selected
            if (len(get_output_directory) > 0) and (len(fname) > 0):
                # Read the Data
                file = open(get_original_file, "rb")
                plot_data = file.read()
                file.close()

                # Complex Float 64
                if get_type == "Complex Float 64":
                    # Normalize and Write
                    number_of_bytes = os.path.getsize(get_original_file)
                    plot_data_formatted = struct.unpack(int(number_of_bytes / 8) * "d", plot_data)
                    np_data = np.asarray(plot_data_formatted, dtype=np.float64)
                    array_min = float(min(np_data))
                    array_max = float(max(np_data))
                    for n in range(0, len(np_data)):
                        np_data[n] = (np_data[n] - array_min) * (get_normalize_max - get_normalize_min) / (
                            array_max - array_min
                        ) + get_normalize_min
                    np_data.tofile(get_new_file)

                # Complex Float 32
                elif (get_type == "Complex Float 32") or (get_type == "Float/Float 32"):
                    # Normalize and Write
                    number_of_bytes = os.path.getsize(get_original_file)
                    plot_data_formatted = struct.unpack(int(number_of_bytes / 4) * "f", plot_data)
                    np_data = np.asarray(plot_data_formatted, dtype=np.float32)
                    array_min = float(min(np_data))
                    array_max = float(max(np_data))
                    for n in range(0, len(np_data)):
                        np_data[n] = (np_data[n] - array_min) * (get_normalize_max - get_normalize_min) / (
                            array_max - array_min
                        ) + get_normalize_min
                    np_data.tofile(get_new_file)

                # Complex Int 16
                elif (get_type == "Complex Int 16") or (get_type == "Short/Int 16"):
                    # Convert and Write
                    number_of_bytes = os.path.getsize(get_original_file)
                    plot_data_formatted = struct.unpack(int(number_of_bytes / 2) * "h", plot_data)
                    np_data = np.array(plot_data_formatted, dtype=np.int16)
                    array_min = float(min(np_data))
                    array_max = float(max(np_data))
                    for n in range(0, len(np_data)):
                        np_data[n] = (float(np_data[n]) - array_min) * (get_normalize_max - get_normalize_min) / (
                            array_max - array_min
                        ) + get_normalize_min
                    np_data.tofile(get_new_file)

                # Complex Int 64
                elif get_type == "Complex Int 64":
                    # Convert and Write
                    number_of_bytes = os.path.getsize(get_original_file)
                    plot_data_formatted = struct.unpack(int(number_of_bytes / 8) * "l", plot_data)
                    np_data = np.array(plot_data_formatted, dtype=np.int64)
                    array_min = float(min(np_data))
                    array_max = float(max(np_data))
                    for n in range(0, len(np_data)):
                        np_data[n] = (float(np_data[n]) - array_min) * (get_normalize_max - get_normalize_min) / (
                            array_max - array_min
                        ) + get_normalize_min
                    np_data.tofile(get_new_file)

                # Int/Int 32
                elif get_type == "Int/Int 32":
                    # Convert and Write
                    number_of_bytes = os.path.getsize(get_original_file)
                    plot_data_formatted = struct.unpack(int(number_of_bytes / 4) * "h", plot_data)
                    np_data = np.array(plot_data_formatted, dtype=np.int32)
                    array_min = float(min(np_data))
                    array_max = float(max(np_data))
                    for n in range(0, len(np_data)):
                        np_data[n] = (float(np_data[n]) - array_min) * (get_normalize_max - get_normalize_min) / (
                            array_max - array_min
                        ) + get_normalize_min
                    np_data.tofile(get_new_file)

                # Complex Int 8
                elif (get_type == "Complex Int 8") or (get_type == "Byte/Int 8"):
                    # Convert and Write
                    number_of_bytes = os.path.getsize(get_original_file)
                    plot_data_formatted = struct.unpack(int(number_of_bytes) * "b", plot_data)
                    np_data = np.array(plot_data_formatted, dtype=np.int8)
                    array_min = float(min(np_data))
                    array_max = float(max(np_data))
                    for n in range(0, len(np_data)):
                        np_data[n] = (float(np_data[n]) - array_min) * (get_normalize_max - get_normalize_min) / (
                            array_max - array_min
                        ) + get_normalize_min
                    np_data.tofile(get_new_file)

                # Unknown
                else:
                    self.logger.error("Cannot normalize " + get_type + ".")

        # Return the Table Data
        asyncio.run(self.finishedTSI_Conditioner(table_strings))


    async def conditionerProgressBarReturn(self, progress, file_index):
        """
        Returns the conditioner progress to the HIPRFISR/Dashboard.
        """
        # Send the Message
        PARAMETERS = {"progress": progress, "file_index": file_index}
        msg = {
            fissure.comms.MessageFields.IDENTIFIER: self.identifier,
            fissure.comms.MessageFields.MESSAGE_NAME: "conditionerProgressBarReturn",
            fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
        }
        await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


    async def finishedTSI_Conditioner(self, table_strings=[]):
        """Sends a message to the HIPRFISR to signal the signal conditioner operation is complete."""
        # Send the Message
        self.logger.info("TSI Conditioner Complete. Returning Table Data...")
        PARAMETERS = {"table_strings": table_strings}
        msg = {
            fissure.comms.MessageFields.IDENTIFIER: self.identifier,
            fissure.comms.MessageFields.MESSAGE_NAME: "tsiConditionerFinished",
            fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
        }
        await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


    def startTSI_FE_Thread(self, common_parameter_names, common_parameter_values):
        """Performs the feature extractor actions."""
        # Common Parameters
        for n in range(len(common_parameter_names)):
            if common_parameter_names[n] == "checkboxes":
                get_checkboxes = common_parameter_values[n]
            elif common_parameter_names[n] == "data_type":
                get_data_type = common_parameter_values[n]
            elif common_parameter_names[n] == "all_filepaths":
                get_all_filepaths = common_parameter_values[n]

        # Table Headers
        header_strings = ["File"]
        for n in range(0, len(get_checkboxes)):
            header_strings.append(get_checkboxes[n])
        table_strings = [header_strings]

        # Features that Require FFT Operation
        fft_features = [
            "Mean of Band Power Spectrum",
            "Max of Band Power Spectrum",
            "Sum of Total Band Power",
            "Peak of Band Power",
            "Variance of Band Power",
            "Standard Deviation of Band Power",
            "Skewness of Band Power",
            "Kurtosis of Band Power",
            "Relative Spectral Peak per Band",
        ]

        # Cycle Through Each File
        for n in range(0, len(get_all_filepaths)):

            # Start a New Row
            new_table_row = [""]

            # Files Selected
            if len(get_all_filepaths[n]) > 0:

                # Filepath
                new_table_row[0] = str(get_all_filepaths[n].split("/")[-1])

                # Read the Data
                file = open(get_all_filepaths[n], "rb")
                plot_data = file.read()
                file.close()
                number_of_bytes = os.path.getsize(get_all_filepaths[n])

                # Complex Float 64
                if get_data_type == "Complex Float 64":
                    plot_data_formatted = struct.unpack(int(number_of_bytes / 8) * "d", plot_data)
                    np_data = np.asarray(plot_data_formatted, dtype=np.float64)

                # Complex Float 32
                elif (get_data_type == "Complex Float 32") or (get_data_type == "Float/Float 32"):
                    plot_data_formatted = struct.unpack(int(number_of_bytes / 4) * "f", plot_data)
                    np_data = np.asarray(plot_data_formatted, dtype=np.float32)

                # Complex Int 16
                elif (get_data_type == "Complex Int 16") or (get_data_type == "Short/Int 16"):
                    plot_data_formatted = struct.unpack(int(number_of_bytes / 2) * "h", plot_data)
                    np_data = np.array(plot_data_formatted, dtype=np.int16)

                # Complex Int 64
                elif get_data_type == "Complex Int 64":
                    plot_data_formatted = struct.unpack(int(number_of_bytes / 8) * "l", plot_data)
                    np_data = np.array(plot_data_formatted, dtype=np.int64)

                # Int/Int 32
                elif get_data_type == "Int/Int 32":
                    plot_data_formatted = struct.unpack(int(number_of_bytes / 4) * "h", plot_data)
                    np_data = np.array(plot_data_formatted, dtype=np.int32)

                # Complex Int 8
                elif (get_data_type == "Complex Int 8") or (get_data_type == "Byte/Int 8"):
                    plot_data_formatted = struct.unpack(int(number_of_bytes) * "b", plot_data)
                    np_data = np.array(plot_data_formatted, dtype=np.int8)

                # Unknown
                else:
                    self.logger.error("Cannot read  " + get_data_type + ".")
                    continue

                # Do FFT Once
                for m in get_checkboxes:
                    if m in fft_features:
                        ft = fft(np_data, next_fast_len(len(np_data)))
                        S = np.abs(ft**2) / len(np_data)
                        break

                # Time Domain: Mean
                # col_count = 0
                if "Mean" in get_checkboxes:
                    # Obtain the Value
                    array_mean = str(float(np.mean(np_data)))

                    # Add Value to Table
                    new_table_row.append(array_mean)

                # Time Domain: Max
                if "Max" in get_checkboxes:
                    # Obtain the Value
                    array_max = str(float(max(np_data)))

                    # Add Value to Table
                    new_table_row.append(array_max)

                # Time Domain: Peak
                if "Peak" in get_checkboxes:
                    # Obtain the Value
                    array_peak = str(float(np.max(np.abs(np_data))))

                    # Add Value to Table
                    new_table_row.append(array_peak)

                # Time Domain: Peak to Peak
                if "Peak to Peak" in get_checkboxes:
                    # Obtain the Value
                    array_peak_to_peak = str(float(np.ptp(np_data)))

                    # Add Value to Table
                    new_table_row.append(array_peak_to_peak)

                # Time Domain: RMS
                if "RMS" in get_checkboxes:
                    # Obtain the Value
                    array_rms = str(float(np.sqrt(np.mean(np_data**2))))

                    # Add Value to Table
                    new_table_row.append(array_rms)

                # Time Domain: Variance
                if "Variance" in get_checkboxes:
                    # Obtain the Value
                    array_variance = str(float(np.var(np_data)))

                    # Add Value to Table
                    new_table_row.append(array_variance)

                # Time Domain: Standard Deviation
                if "Standard Deviation" in get_checkboxes:
                    # Obtain the Value
                    array_std_dev = str(float(np.std(np_data)))

                    # Add Value to Table
                    new_table_row.append(array_std_dev)

                # Time Domain: Power
                if "Power" in get_checkboxes:
                    # Obtain the Value
                    array_power = str(float(np.mean(np_data**2)))

                    # Add Value to Table
                    new_table_row.append(array_power)

                # Time Domain: Crest Factor
                if "Crest Factor" in get_checkboxes:
                    # Obtain the Value
                    array_crest_factor = str(float(np.max(np.abs(np_data)) / np.sqrt(np.mean(np_data**2))))

                    # Add Value to Table
                    new_table_row.append(array_crest_factor)

                # Time Domain: Pulse Indicator
                if "Pulse Indicator" in get_checkboxes:
                    # Obtain the Value
                    array_pulse_indicator = str(float(np.max(np.abs(np_data)) / np.mean(np_data)))

                    # Add Value to Table
                    new_table_row.append(array_pulse_indicator)

                # Time Domain: Margin
                if "Margin" in get_checkboxes:
                    # Obtain the Value
                    array_margin = str(
                        float(np.max(np.abs(np_data)) / (np.abs(np.mean(np.sqrt(np.abs(np_data)))) ** 2))
                    )

                    # Add Value to Table
                    new_table_row.append(array_margin)

                # Time Domain: Kurtosis
                if "Kurtosis" in get_checkboxes:
                    # Obtain the Value
                    array_kurtosis = str(float(stats.kurtosis(np_data)))

                    # Add Value to Table
                    new_table_row.append(array_kurtosis)

                # Time Domain: Skewness
                if "Skewness" in get_checkboxes:
                    # Obtain the Value
                    array_skewness = str(float(stats.skew(np_data)))

                    # Add Value to Table
                    new_table_row.append(array_skewness)

                # Time Domain: Zero Crossings
                if "Zero Crossings" in get_checkboxes:
                    # Obtain the Value
                    count1 = np.where(np.diff(np.sign([i for i in np_data[::2] if i])))[0].shape[0]
                    count2 = np.where(np.diff(np.sign([i for i in np_data[1::2] if i])))[0].shape[0]
                    array_zero_crossings = str(count1 + count2)

                    # Add Value to Table
                    new_table_row.append(array_zero_crossings)

                # Time Domain: Samples
                if "Samples" in get_checkboxes:
                    # Obtain the Value
                    if "Complex" in get_data_type:
                        array_samples = str(int(len(np_data) / 2))
                    else:
                        array_samples = str(int(len(np_data)))

                    # Add Value to Table
                    new_table_row.append(array_samples)

                # Frequency Domain: Mean of Band Power Spectrum
                if "Mean of Band Power Spectrum" in get_checkboxes:
                    # Obtain the Value
                    array_mean_bps = str(float(np.mean(S)))

                    # Add Value to Table
                    new_table_row.append(array_mean_bps)

                # Frequency Domain: Max of Band Power Spectrum
                if "Max of Band Power Spectrum" in get_checkboxes:
                    # Obtain the Value
                    array_max_bps = str(float(np.max(S)))

                    # Add Value to Table
                    new_table_row.append(array_max_bps)

                # Frequency Domain: Sum of Total Band Power
                if "Sum of Total Band Power" in get_checkboxes:
                    # Obtain the Value
                    array_sum_tbp = str(float(np.sum(S)))

                    # Add Value to Table
                    new_table_row.append(array_sum_tbp)

                # Frequency Domain: Peak of Band Power
                if "Peak of Band Power" in get_checkboxes:
                    # Obtain the Value
                    array_peak_bp = str(float(np.max(np.abs(S))))

                    # Add Value to Table
                    new_table_row.append(array_peak_bp)

                # Frequency Domain: Variance of Band Power
                if "Variance of Band Power" in get_checkboxes:
                    # Obtain the Value
                    array_var_bp = str(float(np.var(S)))

                    # Add Value to Table
                    new_table_row.append(array_var_bp)

                # Frequency Domain: Standard Deviation of Band Power
                if "Standard Deviation of Band Power" in get_checkboxes:
                    # Obtain the Value
                    array_std_dev_bp = str(float(np.std(S)))

                    # Add Value to Table
                    new_table_row.append(array_std_dev_bp)

                # Frequency Domain: Skewness of Band Power
                if "Skewness of Band Power" in get_checkboxes:
                    # Obtain the Value
                    array_skewness_bp = str(float(stats.skew(S)))

                    # Add Value to Table
                    new_table_row.append(array_skewness_bp)

                # Frequency Domain: Kurtosis of Band Power
                if "Kurtosis of Band Power" in get_checkboxes:
                    # Obtain the Value
                    array_kurtosis_bp = str(float(stats.kurtosis(S)))

                    # Add Value to Table
                    new_table_row.append(array_kurtosis_bp)

                # Frequency Domain: Relative Spectral Peak per Band
                if "Relative Spectral Peak per Band" in get_checkboxes:
                    # Obtain the Value
                    array_rsppb = str(float(np.max(S) / np.mean(S)))

                    # Add Value to Table
                    new_table_row.append(array_rsppb)

            # Append the Row
            table_strings.append(new_table_row)

            # Update Progress Bar
            progress_value = 1 + int((float((n + 1) / len(get_all_filepaths)) * 99))
            asyncio.run(self.feProgressBarReturn(progress_value, n))

            # Check for Break
            if self.fe_running == False:
                self.logger.info("TSI Feature Extractor Stopped")
                return

        # Return the Table Data
        asyncio.run(self.finishedTSI_FE(table_strings))


    async def feProgressBarReturn(self, progress, file_index):
        """
        Returns the feature extractor progress to the HIPRFISR/Dashboard.
        """
        # Send the Message
        PARAMETERS = {"progress": progress, "file_index": file_index}
        msg = {
            fissure.comms.MessageFields.IDENTIFIER: self.identifier,
            fissure.comms.MessageFields.MESSAGE_NAME: "feProgressBarReturn",
            fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
        }
        await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


    async def finishedTSI_FE(self, table_strings=[]):
        """
        Sends a message to the HIPRFISR to signal the feature extractor operation is complete.
        """
        # Send the Message
        self.logger.info("TSI Feature Extractor Complete. Returning Table Data...")
        PARAMETERS = {"table_strings": table_strings}
        msg = {
            fissure.comms.MessageFields.IDENTIFIER: self.identifier,
            fissure.comms.MessageFields.MESSAGE_NAME: "tsiFE_Finished",
            fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
        }
        await self.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


if __name__ == "__main__":
    rc = 0
    # try:
    run()
    # except Exception:
    # rc = 1

    sys.exit(rc)
