import binascii
import fissure.comms
import fissure.utils
import fissure.utils.hardware
from fissure.utils import plugin
from fissure.utils.artifacts import ArtifactManager
import logging
import os
import shutil
import subprocess
import threading
import traceback
import time
import yaml
from concurrent.futures import ThreadPoolExecutor
import asyncio
import zmq
from typing import List
import re
from typing import Optional
import importlib.util


async def updateLoggingLevels(component: object, new_console_level="", new_file_level=""):
    """ 
    Update the logging levels on the Sensor Node.
    """
    # Update New Levels for Sensor Node
    component.updateLoggingLevels(new_console_level, new_file_level)


async def hiprfisrDisconnecting(component: object):
    """
    HIPRFISR is intentionally disconnecting from this Sensor Node.
    Stop sending messages, mark connection down, and shut down socket cleanly.
    """
    component.logger.info("Received hiprfisrDisconnecting")

    # Mark HIPRFISR as disconnected
    component.hiprfisr_connected = False


async def transferSensorNodeFile(
    component: object, local_file_data="", remote_filepath="", refresh_file_list=False
):
    """
    Saves file data sent by the HIPRFISR to a sensor node folder.
    """
    # Save to Same File on IQ Data Playback
    if len(remote_filepath) > 0:
        if remote_filepath.startswith("/IQ_Data_Playback"):
            new_filepath = os.path.join(fissure.utils.SENSOR_NODE_DIR, "IQ_Data_Playback", "playback.iq")
        elif remote_filepath.startswith("/Archive_Replay"):
            new_filepath = os.path.join(fissure.utils.SENSOR_NODE_DIR, remote_filepath.lstrip('/'))
        else:
            new_filepath = os.path.join(fissure.utils.SENSOR_NODE_DIR, remote_filepath.lstrip('/'))

        # Save
        with open(new_filepath, "wb") as file:
            file.write(binascii.a2b_hex(local_file_data))

        # Refresh the File List in Dashboard
        if str(refresh_file_list) == "True":
            await refreshSensorNodeFiles(component, os.path.dirname(remote_filepath))


async def deleteArchiveReplayFiles(component: object):
    """
    Deletes all the files in the Archive_Replay folder on the sensor node ahead of file transfer for replay.
    """
    # Delete Files
    folder_location = os.path.join(fissure.utils.SENSOR_NODE_DIR, "Archive_Replay")
    for filename in os.listdir(folder_location):
        if os.path.isfile(os.path.join(folder_location, filename)):
            if filename != ".gitkeep":
                os.remove(os.path.join(folder_location, filename))


async def overwriteDefaultAutorunPlaylist(component: object, playlist_dict={}):
    """
    Overwrites the default autorun playlist yaml file with a dictionary configured in the Dashboard.
    """
    # Overwrite default.yaml
    component.logger.info("OVERWRITE!")
    filename = os.path.join(fissure.utils.SENSOR_NODE_DIR, "Autorun_Playlists", "default.yaml")
    with open(filename, "w") as stream:
        yaml.dump(playlist_dict, stream, default_flow_style=False, indent=5)


async def downloadSensorNodeFile(component: object, sensor_node_file="", download_folder=""):
    """
    Transfers a file from the sensor node to the other computer.
    """
    # Retrieve the File
    if os.path.exists(sensor_node_file):
        # File
        if os.path.isfile(sensor_node_file):
            return_file_name = sensor_node_file.split("/")[-1]

            # Read the File
            try:
                with open(sensor_node_file, "rb") as f:
                    get_data = f.read()
                get_data = binascii.hexlify(get_data)
                get_data = get_data.decode("utf-8").upper()
            except:
                component.logger.error("Error reading file")
                return

            # Send the Data
            if download_folder[-1] != "/":
                download_folder = download_folder + "/"
            return_filepath = download_folder + return_file_name

            PARAMETERS = {
                "operation": "Download",
                "filepath": return_filepath,
                "data": get_data,
            }
            msg = {
                fissure.comms.MessageFields.IDENTIFIER: component.identifier,
                fissure.comms.MessageFields.MESSAGE_NAME: "saveFile",
                fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
            }
            await component.hiprfisr_socket.send_msg(
                fissure.comms.MessageTypes.COMMANDS, msg
            )  # Replace with data socket connection

        # Folder
        elif os.path.isdir(sensor_node_file):
            # Zip the Folder
            if sensor_node_file[-1] == "/":
                zip_file_name = sensor_node_file.split("/")[-2]
            else:
                zip_file_name = sensor_node_file.split("/")[-1]
            zip_folder_path = os.path.join(fissure.utils.SENSOR_NODE_DIR, "Recordings")
            shutil.make_archive(zip_folder_path + zip_file_name, "zip", sensor_node_file)
            return_file_name = zip_folder_path + zip_file_name + ".zip"

            # Read the File
            try:
                with open(return_file_name, "rb") as f:
                    get_data = f.read()
                get_data = binascii.hexlify(get_data)
                get_data = get_data.decode("utf-8").upper()
            except:
                component.logger.error("Error reading file")
                return

            # Send the Data
            if download_folder[-1] != "/":
                download_folder = download_folder + "/"
            return_filepath = download_folder + zip_file_name + ".zip"

            PARAMETERS = {
                "operation": "Download",
                "filepath": return_filepath,
                "data": get_data,
            }
            msg = {
                fissure.comms.MessageFields.IDENTIFIER: component.identifier,
                fissure.comms.MessageFields.MESSAGE_NAME: "saveFile",
                fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
            }
            await component.hiprfisr_socket.send_msg(
                fissure.comms.MessageTypes.COMMANDS, msg
            )  # Replace with data socket connection

            # Delete the .zip File
            if os.path.isfile(return_file_name):
                os.system('rm "' + return_file_name + '"')

        # Invalid
        else:
            component.logger.error("File/folder not found on the sensor node")
            return


async def deleteSensorNodeFile(component: object, sensor_node_file=""):
    """
    Deletes a file or folder local to the sensor node.
    """
    # Delete the File
    if os.path.exists(sensor_node_file):
        os.system('rm -Rf "' + sensor_node_file + '"')


async def refreshSensorNodeFiles(component: object, sensor_node_folder=""):
    """
    Returns file details for a specified folder.
    """
    # Update the Tree Widget
    if len(sensor_node_folder) > 0:
        folder_path = os.path.join(fissure.utils.SENSOR_NODE_DIR, sensor_node_folder.replace("/",""))
        path_item = []
        size_item = []
        type_item = []
        modified_item = []
        for fname in os.listdir(folder_path):
            if os.path.isfile(os.path.join(folder_path,fname)):
                get_type = "File"
            else:
                get_type = "Folder"
            path_item.append(os.path.join(folder_path,fname))
            size_item.append(str(os.path.getsize(os.path.join(folder_path,fname))))
            type_item.append(get_type)
            modified_item.append(
                str(time.strftime("%m/%d/%Y %-I:%M %p", time.gmtime(os.path.getmtime(os.path.join(folder_path,fname)))))
            )

        # Return File Details
        PARAMETERS = {
            "filepaths": path_item,
            "file_sizes": size_item,
            "file_types": type_item,
            "modified_dates": modified_item,
        }
        msg = {
            fissure.comms.MessageFields.IDENTIFIER: component.identifier,
            fissure.comms.MessageFields.MESSAGE_NAME: "refreshSensorNodeFilesResults",
            fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
        }
        await component.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def autorunPlaylistStart(component: object, playlist_dict={}, trigger_values=[]):
    """
    Starts a new thread for cycling through the autorun playlist.
    """
    # Run Event and Do Not Block
    loop = asyncio.get_event_loop()
    loop.run_in_executor(None, component.autorunPlaylistStart, playlist_dict, trigger_values)
    # component.autorunPlaylistStart(sensor_node_id, playlist_dict, trigger_values)


async def autorunPlaylistExecute(component: object, playlist_filename=""):
    """
    Starts a new thread for loading and cycling through the autorun playlist.
    """
    # Run Event and Do Not Block
    loop = asyncio.get_event_loop()
    loop.run_in_executor(None, component.autorunPlaylistExecute, playlist_filename)


async def autorunPlaylistStop(component: object):
    """
    Stops an autorun playlist already in progress.
    """
    component.logger.info("STOP!")
    try:
        # Stop Triggers
        if component.triggers_running == True:
            component.triggers_running = False
            component.trigger_done.set()

        # Stop the Thread
        component.autorun_playlist_stop_event.set()
    except:
        pass


async def physicalFuzzingStart(
    component: object,
   
    fuzzing_variables=[],
    fuzzing_type=[],
    fuzzing_min=[],
    fuzzing_max=[],
    fuzzing_update_period=0,
    fuzzing_seed_step=0,
):
    """
    Sets variables within a flow graph as specified by the Dashboard.
    """
    # Run Event and Do Not Block
    loop = asyncio.get_event_loop()
    loop.run_in_executor(
        None, 
        component.physicalFuzzingThreadStart, 
        fuzzing_variables,
        fuzzing_type,
        fuzzing_min,
        fuzzing_max,
        fuzzing_update_period,
        fuzzing_seed_step,
    )


async def physicalFuzzingStop(component: object):
    """
    Stop physical fuzzing on the currently running attack flow graph.
    """
    # Stop the Thread
    component.physical_fuzzing_stop_event = True


async def multiStageAttackStart(
    component: object,
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
    Starts a new thread for running two flow graphs.
    A new thread is created to allow the Sensor Node to still perform normal
    functionality while waiting for an attack to finish.
    """
    # Use the Function that is Called Frequently in SensorNode.py
    if len(trigger_values) == 0:
        # Run Event and Do Not Block
        loop = asyncio.get_event_loop()
        loop.run_in_executor(None, component.multiStageAttackStart, filenames, variable_names, variable_values, durations, repeat, file_types, autorun_index)
    else:
        # Make a new Trigger Thread
        fissure_event_values = [filenames, variable_names, variable_values, durations, repeat, file_types, autorun_index]
        loop = asyncio.get_event_loop()
        loop.run_in_executor(None, component.triggerStart, trigger_values, "Multi-Stage Attack", fissure_event_values, autorun_index)
    await asyncio.sleep(0.1)


async def multiStageAttackStop(component: object, autorun_index=0):
    """Stops a multi-stage attack already in progress"""
    # Use the Function that is Called Frequently in SensorNode.py
    loop = asyncio.get_event_loop()
    loop.run_in_executor(None, component.multiStageAttackStop, autorun_index)


async def archivePlaylistStart(
    component: object,
   
    flow_graph="",
    filenames=[],
    frequencies=[],
    sample_rates=[],
    formats=[],
    channels=[],
    gains=[],
    durations=[],
    repeat=False,
    ip_address="",
    serial="",
    trigger_values=[]
):
    """
    Starts a new thread for running the same replay flow graph multiple times for a specified duration.
    """
    if len(trigger_values) == 0:
        # Run Event and Do Not Block
        loop = asyncio.get_event_loop()
        component.archive_playlist_stop_event = asyncio.Event()
        loop.run_in_executor(None, component.archivePlaylistThreadStart, flow_graph, filenames, frequencies, sample_rates, formats, channels, gains, durations, repeat, ip_address, serial)
    else:
        # Run Event and Do Not Block
        fissure_event_values = [flow_graph, filenames, frequencies, sample_rates, formats, channels, gains, durations, repeat, ip_address, serial]
        loop = asyncio.get_event_loop()
        loop.run_in_executor(None, component.triggerStart, trigger_values, "Archive Replay", fissure_event_values, -1)
    await asyncio.sleep(0.1)


async def archivePlaylistStop(component: object):
    """
    Stops a multi-stage attack already in progress
    """
    # Use the Function that is Called Frequently in SensorNode.py
    loop = asyncio.get_event_loop()
    loop.run_in_executor(None, component.archivePlaylistStop)
    # component.archivePlaylistStop(sensor_node_id)
    await asyncio.sleep(0.1)


async def attackFlowGraphStart(
    component: object,
    flow_graph_filepath="",
    variable_names=[],
    variable_values=[],
    file_type="",
    run_with_sudo=False,
    autorun_index=0,
    trigger_values=[]
):
    """
    Runs the flow graph with the specified file path.
    """
    # Use the Function that is Called Frequently in SensorNode.py
    if len(trigger_values) == 0:
        # Run Event and Do Not Block
        loop = asyncio.get_event_loop()
        loop.run_in_executor(None, component.attackFlowGraphStart, flow_graph_filepath, variable_names, variable_values, file_type, run_with_sudo, autorun_index)
    else:
        # Run Event and Do Not Block
        fissure_event_values = [flow_graph_filepath, variable_names, variable_values, file_type, run_with_sudo, autorun_index]
        loop = asyncio.get_event_loop()
        loop.run_in_executor(None, component.triggerStart, trigger_values, "Single-Stage Attack", fissure_event_values, autorun_index)
    await asyncio.sleep(0.1)


async def attackFlowGraphStop(component: object, parameter="", autorun_index=0):
    """
    Stop the currently running attack flow graph.
    """
    # Use the Function that is Called Frequently in SensorNode.py
    component.attackFlowGraphStop(parameter, autorun_index)
    # loop = asyncio.get_event_loop()
    # loop.run_in_executor(None, component.attackFlowGraphStop, parameter, autorun_index)


async def iqFlowGraphStart(
    component: object,
    flow_graph_filepath="",
    variable_names=[],
    variable_values=[],
    file_type="",
):
    """
    Run the legacy IQ playback flow graph.
    """
    if component.settings_dict["Sensor Node"]["local_remote"] == "remote":
        for index, variable_name in enumerate(
            variable_names
        ):
            if variable_name != "filepath":
                continue

            variable_values[index] = os.path.join(
                fissure.utils.SENSOR_NODE_DIR,
                "IQ_Data_Playback",
                "playback.iq",
            )

    loop = asyncio.get_event_loop()

    loop.run_in_executor(
        None,
        component.iqFlowGraphThread,
        flow_graph_filepath,
        variable_names,
        variable_values,
    )


async def iqFlowGraphStop(component: object, parameter=""):
    """
    Stop the currently running IQ flow graph.
    """
    # Use the Function that is Called Frequently in SensorNode.py
    component.iqFlowGraphStop(parameter)


async def inspectionFlowGraphStart(
    component: object, flow_graph_filepath="", variable_names=[], variable_values=[], file_type=""
):
    """Runs the flow graph with the specified file path."""
    # Only Supports Flow Graphs with GUIs
    if file_type == "Flow Graph - GUI":

        # Run Event and Do Not Block
        loop = asyncio.get_event_loop()
        loop.run_in_executor(
            None, 
            component.inspectionFlowGraphGUI_Thread, 
            flow_graph_filepath,
            variable_names,
            variable_values,
    )


async def inspectionFlowGraphStop(component: object, parameter=""):
    """
    Stop the currently running inspection flow graph.
    """
    # Only Supports Flow Graphs with GUIs
    if parameter == "Flow Graph - GUI":
        os.system("pkill -f " + '"' + component.inspection_script_name + '"')


async def snifferFlowGraphStart(
    component: object, flow_graph_filepath="", variable_names=[], variable_values=[]
):
    """
    Runs the flow graph with the specified file path.
    """
    # Run Event and Do Not Block
    class_name = flow_graph_filepath.replace(".py", "")
    loop = asyncio.get_event_loop()
    loop.run_in_executor(None, component.snifferFlowGraphThread, class_name, variable_names, variable_values)


async def snifferFlowGraphStop(component: object, parameter=""):
    """
    Stop the currently running flow graph.
    """
    # Stop Sniffer Flow Graph (Wireshark Keeps Going)
    component.snifferflowtoexec.stop()
    component.snifferflowtoexec.wait()
    del component.snifferflowtoexec  # Free up the ports

    if parameter == "Stream":
        await component.flowGraphFinished("Sniffer - Stream")
    elif parameter == "TaggedStream":
        await component.flowGraphFinished("Sniffer - Tagged Stream")
    elif parameter == "Message/PDU":
        await component.flowGraphFinished("Sniffer - Message/PDU")


async def startScapy(component: object, interface="", interval=0, loop=False, operating_system=""):
    """
    Start a new Scapy operation.
    """
    # Start Transmitting
    if len(interface) > 0:
        scapy_send_directory = os.path.join(fissure.utils.TOOLS_DIR)

        if fissure.utils.get_default_expect_terminal(operating_system) == "gnome-terminal":
            subprocess.Popen(
                "gnome-terminal -- sudo python2 scapy_send.py " + interface + " " + interval + " " + loop,
                cwd=scapy_send_directory,
                shell=True,
            )
        elif fissure.utils.get_default_expect_terminal(operating_system) == "qterminal":
            subprocess.Popen(
                "qterminal -e sudo python2 scapy_send.py " + interface + " " + interval + " " + loop,
                cwd=scapy_send_directory,
                shell=True,
            )
        elif fissure.utils.get_default_expect_terminal(operating_system) == "lxterminal":
            subprocess.Popen(
                "lxterminal -e sudo python2 scapy_send.py " + interface + " " + interval + " " + loop,
                cwd=scapy_send_directory,
                shell=True,
            )
            
    else:
        component.logger.error("Specify wireless interface for Scapy")


async def stopScapy(component: object):
    """
    Stop the currently running Scapy operation.
    """
    # Stop the Thread
    os.system('sudo pkill -f "python2 scapy"')


async def setVariable(component: object, flow_graph="", variable="", value=""):
    """
    Sets a variable of a specified running flow graph.
    """
    # Make it Match GNU Radio Format
    formatted_name = "set_" + variable
    isNumber = fissure.utils.isFloat(value)
    if isNumber:
        if flow_graph == "Protocol Discovery":
            getattr(component.pdflowtoexec, formatted_name)(float(value))
        elif flow_graph == "Attack":
            getattr(component.attackflowtoexec, formatted_name)(float(value))
        elif flow_graph == "Sniffer":
            getattr(component.snifferflowtoexec, formatted_name)(float(value))
    else:
        if flow_graph == "Protocol Discovery":
            getattr(component.pdflowtoexec, formatted_name)(value)
        elif flow_graph == "Attack":
            getattr(component.attackflowtoexec, formatted_name)(value)
        elif flow_graph == "Sniffer":
            getattr(component.snifferflowtoexec, formatted_name)(value)


async def protocolDiscoveryFG_Start(
    component: object, flow_graph_filepath="", variable_names=[], variable_values=[]
):
    """
    Runs the flow graph with the specified file path.
    """
    # Run Event and Do Not Block
    class_name = flow_graph_filepath.replace(".py", "")
    loop = asyncio.get_event_loop()
    loop.run_in_executor(None, component.protocolDiscoveryFG_ThreadStart, class_name, variable_names, variable_values)


async def protocolDiscoveryFG_Stop(component: object):
    """
    Stop the currently running flow graph.
    """
    component.pdflowtoexec.stop()
    component.pdflowtoexec.wait()
    del component.pdflowtoexec  # Free up the ports


async def startPD(component: object):
    """
    Starts a ZMQ SUB for forwarding bits from demodulation flow graphs to the PD circular buffer.
    """
    component.logger.info("PD: Starting Protocol Discovery...")
    component.running_PD = True

    # Create the Temporary ZMQ SUB
    component.pd_bits_context = zmq.Context()
    component.pd_bits_socket = component.pd_bits_context.socket(zmq.SUB)
    component.pd_bits_socket.connect("tcp://127.0.0.1:" + str(5066))  # pd_bits_port
    component.pd_bits_socket.setsockopt_string(zmq.SUBSCRIBE, "")


async def stopPD(component: object):
    """
    Closes the ZMQ SUB listening for bits.
    """
    # Call the Function used Multiple Times
    component.stopPD()


async def terminateSensorNode(component: object):
    """
    Stops sensor_node.py entirely (local or remote) by triggering shutdown.
    """
    component.logger.info("terminateSensorNode callback triggered — shutting down sensor node")

    # Tell begin loop to exit
    component.shutdown = True

    # Let task termination and socket shutdown fall naturally through the checks at the end of begin()


async def nodeSelectIP(component: object):
    """
    Return current in-memory sensor node settings to HIPRFISR.
    """
    component.logger.info("nodeSelectIP/Recall Settings")

    PARAMETERS = {
        "settings_dict": component.settings_dict
    }

    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "recallSettingsReturn",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }

    await component.hiprfisr_socket.send_msg(
        fissure.comms.MessageTypes.COMMANDS,
        msg
    )


async def probeHardware(component: object, table_row_text=[]):
    """
    Probe the selected hardware from the table and return the information.
    """
    get_hardware = str(table_row_text[0])
    output = ""
    height_width = ["", ""]

    if get_hardware == "USRP X3x0":
        get_ip = str(table_row_text[5])
        output = await fissure.utils.hardware.probeUSRP_X3x0(get_ip)

    elif (get_hardware == "USRP B2x0") or (get_hardware == "USRP B20xmini"):
        output = await fissure.utils.hardware.probeUSRP_B2x0()

    elif get_hardware == "bladeRF":
        output = await fissure.utils.hardware.probe_bladeRF()
        if not output.startswith("Error:"):
            height_width = [140, 400]

    elif get_hardware == "LimeSDR":
        output = await fissure.utils.hardware.probeLimeSDR()
        if not output.startswith("Error:"):
            height_width = [75, 700]

    elif get_hardware == "HackRF":
        output = await fissure.utils.hardware.probeHackRF()
        if not output.startswith("Error:"):
            height_width = [300, 500]

    elif get_hardware == "PlutoSDR":
        output = await fissure.utils.hardware.probePlutoSDR()
        if not output.startswith("Error:"):
            height_width = [600, 900]

    elif get_hardware == "USRP2":
        get_ip = str(table_row_text[5])
        output = await fissure.utils.hardware.probeUSRP2(get_ip)

    elif get_hardware == "USRP N2xx":
        # Get IP Address
        get_ip = str(table_row_text[5])
        output = await fissure.utils.hardware.probeUSRP_N2xx(get_ip)

    elif get_hardware == "bladeRF 2.0":
        output = await fissure.utils.hardware.probe_bladeRF2()
        if not output.startswith("Error:"):
            height_width = [140, 400]

    elif get_hardware == "USRP X410":
        get_ip = str(table_row_text[5])
        output = await fissure.utils.hardware.probeUSRP_X410(get_ip)

    elif get_hardware == "RTL2832U":
        output = await fissure.utils.hardware.probeRTL2832U()
        if not output.startswith("Error:"):
            height_width = [300, 500]

    elif get_hardware == "RSPduo":
        output = await fissure.utils.hardware.probeRSPduo()
        if not output.startswith("Error:"):
            height_width = [300, 500]

    elif get_hardware == "RSPdx":
        output = await fissure.utils.hardware.probeRSPdx()
        if not output.startswith("Error:"):
            height_width = [300, 500]

    elif get_hardware == "RSPdx R2":
        output = await fissure.utils.hardware.probeRSPdxR2()
        if not output.startswith("Error:"):
            height_width = [300, 500]
    
    elif get_hardware == "802.11x Adapter":
        output = await fissure.utils.hardware.probe80211x()
        if not output.startswith("Error:"):
            height_width = [300, 500]

    elif get_hardware == "CaribouLite":
        output = await fissure.utils.hardware.probeCaribouLite()
        if not output.startswith("Error:"):
            height_width = [300, 500]

    # Return the Text
    PARAMETERS = {
        "output": output, 
        "height_width": height_width
    }
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "hardwareProbeResults",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    await component.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def scanHardware(component: object, hardware_list=[]):
    """
    Scans all types of hardware included in the hardware_list and returns the information.
    """
    # Scan Hardware
    all_scan_results = []
    for n in range(0, len(hardware_list)):
        get_hardware = hardware_list[n]
        if get_hardware == "USRP X3x0":
            all_scan_results.append(fissure.utils.hardware.findX310()[0])
        elif get_hardware == "USRP B2x0":
            all_scan_results.append(fissure.utils.hardware.findB2x0())
        elif get_hardware == "HackRF":
            all_scan_results.append(fissure.utils.hardware.findHackRF()[0])
        elif get_hardware == "RTL2832U":
            all_scan_results.append(fissure.utils.hardware.findRTL2832U()[0])
        elif get_hardware == "802.11x Adapter":
            all_scan_results.append(fissure.utils.hardware.find80211x()[0])
        elif get_hardware == "USRP B20xmini":
            all_scan_results.append(fissure.utils.hardware.findB205mini())
        elif get_hardware == "LimeSDR":
            all_scan_results.append(fissure.utils.hardware.findLimeSDR())
        elif get_hardware == "bladeRF":
            bladerf_results = fissure.utils.hardware.find_bladeRF2()[0]
            bladerf_results[0] = "bladeRF"  # Instead of bladeRF 2.0
            all_scan_results.append(bladerf_results)
        elif get_hardware == "Open Sniffer":
            all_scan_results.append(["Open Sniffer", "", "", "", "", "", ""])
        elif get_hardware == "PlutoSDR":
            all_scan_results.append(fissure.utils.hardware.findPlutoSDR()[0])
        elif get_hardware == "USRP2":
            all_scan_results.append(fissure.utils.hardware.findUSRP2())
        elif get_hardware == "USRP N2xx":
            all_scan_results.append(fissure.utils.hardware.findUSRP_N2xx())
        elif get_hardware == "bladeRF 2.0":
            all_scan_results.append(fissure.utils.hardware.find_bladeRF2()[0])
        elif get_hardware == "USRP X410":
            all_scan_results.append(fissure.utils.hardware.findX410())
        elif get_hardware == "RSPduo":
            all_scan_results.append(fissure.utils.hardware.findRSPduo()[0])
        elif get_hardware == "RSPdx":
            all_scan_results.append(fissure.utils.hardware.findRSPdx()[0])
        elif get_hardware == "RSPdx R2":
            all_scan_results.append(fissure.utils.hardware.findRSPdxR2()[0])
        elif get_hardware == "CaribouLite":
            all_scan_results.append(fissure.utils.hardware.findCaribouLite())            

    # Return Scan Results
    PARAMETERS = {
        "hardware_scan_results": all_scan_results
    }
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "hardwareScanResults",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    await component.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def guessHardware(component: object, table_row=[], table_row_text=[], guess_index=0):
    """
    Probe the selected hardware from the table and return the information.
    """
    get_hardware = str(table_row_text[0])
    scan_results = ["", "", "", "", "", "", ""]
    new_guess_index = guess_index
    if get_hardware == "USRP X3x0":
        # Get IP Address
        get_ip = str(table_row_text[5])

        # self.parent.findX310(self.textEdit_ip, self.textEdit_serial, self.comboBox_daughterboard, self.label2_probe)

    elif get_hardware == "USRP B2x0":
        get_serial = str(table_row_text[3])
        scan_results = fissure.utils.hardware.findB2x0(get_serial)
    elif get_hardware == "USRP B20xmini":
        get_serial = str(table_row_text[3])
        scan_results = fissure.utils.hardware.findB205mini(get_serial)
    elif get_hardware == "bladeRF":
        get_serial = str(table_row_text[3])
        scan_results = fissure.utils.hardware.find_bladeRF2(get_serial)
    elif get_hardware == "LimeSDR":
        pass
    elif get_hardware == "HackRF":
        get_serial = str(table_row_text[3])
        scan_results, new_guess_index = fissure.utils.hardware.findHackRF(get_serial, guess_index)
    elif get_hardware == "PlutoSDR":
        pass
    elif get_hardware == "USRP2":
        # Get IP Address
        get_ip = str(table_row_text[5])

        # Update Serial, IP Address, Daughterboard
        scan_results = fissure.utils.hardware.findUSRP2(get_ip)

    elif get_hardware == "USRP N2xx":
        # Get IP Address
        get_ip = str(table_row_text[5])

        # Update Serial, IP Address, Daughterboard
        scan_results = fissure.utils.hardware.findUSRP_N2xx(get_ip)

    elif get_hardware == "bladeRF 2.0":
        get_serial = str(table_row_text[3])
        scan_results = fissure.utils.hardware.find_bladeRF2(get_serial)
    elif get_hardware == "USRP X410":
        # Get IP Address
        get_ip = str(table_row_text[5])

        # Update Serial, IP Address, Daughterboard
        scan_results = fissure.utils.hardware.findX410(get_ip)

    elif get_hardware == "802.11x Adapter":
        get_network_interface = str(table_row_text[4])
        scan_results, new_guess_index = fissure.utils.hardware.find80211x(get_network_interface, guess_index)

    elif get_hardware == "RTL2832U":
        get_serial = str(table_row_text[3])
        scan_results, new_guess_index = fissure.utils.hardware.findRTL2832U(get_serial, guess_index)

    elif get_hardware == "RSPduo":
        get_serial = str(table_row_text[3])
        scan_results, new_guess_index = fissure.utils.hardware.findRSPduo(get_serial, guess_index)

    elif get_hardware == "RSPdx":
        get_serial = str(table_row_text[3])
        scan_results, new_guess_index = fissure.utils.hardware.findRSPdx(get_serial, guess_index)        

    elif get_hardware == "RSPdx R2":
        get_serial = str(table_row_text[3])
        scan_results, new_guess_index = fissure.utils.hardware.findRSPdxR2(get_serial, guess_index)

    elif get_hardware == "CaribouLite":
        scan_results = fissure.utils.hardware.findCaribouLite()

    # Return Guess Results
    PARAMETERS = {
        "table_row": table_row,
        "hardware_type": get_hardware,
        "scan_results": scan_results,
        "new_guess_index": new_guess_index,
    }
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "hardwareGuessResults",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    await component.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def checkPlugin(component: object, plugin_names: List[str]):
    """Check Plugin Status

    Check for the existence and installation status of the plugin on the sensor node.

    Parameters
    ----------
    component : object
        Component
    plugin_names : List[str]
        Plugin names with file extension or no extension if folder
    """
    plugin_dir_list = os.listdir(fissure.utils.PLUGIN_DIR)
    status = {}
    for plugin_name in plugin_names:
        status[plugin_name] = {'deployed': plugin_name in plugin_dir_list, 'installed': plugin.installed(plugin_name)}

    # return status
    PARAMETERS = {
        "plugin_status": status
    }
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "checkSensorNodePluginResults",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    await component.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


def unpackPlugin(plugin_name: str, plugin_data: str):
    """Unpack Plugin

    Parameters
    ----------
    plugin_name : str
        Plugin file name
    plugin_data : str
        Plugin data as binary ascii
    """
    # save file to plugin directory
    filename = os.path.join(fissure.utils.PLUGIN_DIR, plugin_name)
    with open(filename, "wb") as file:
        file.write(binascii.a2b_hex(plugin_data))

    if plugin_name[-4:] == '.zip':
        # unzip package and remove zip file
        shutil.unpack_archive(filename, filename[:-4], 'zip')
        os.system('rm "' + filename + '"')
        filename = filename[:-4]

    return filename


async def transferPlugins(component: object, plugins: List[tuple]):
    """Save Plugin Sent by HIPRFISR

    Parameters
    ----------
    component : object
        Component
    plugins : List[tuple]
        Plugin file data as (file name, binary ascii file data)
    """
    for (plugin_name, plugin_data) in plugins:
        # unpack plugin data
        plugin_name = unpackPlugin(plugin_name, plugin_data)


async def __installPlugin(component: object, plugin_name: str):
    """Install Plugin to Sensor Node

    Parameters
    ----------
    component : object
        Component
    plugin_name : str
        Plugin name
    """
    # run installation
    plugin.install(plugin_name)

    # activate plugin on hiprfisr for sensor node
    PARAMETERS = {
        "plugin_name": plugin_name
    }
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "registerPlugin",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    await component.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def installPlugins(component: object, plugin_names: str):
    """Install Plugin

    Parameters
    ----------
    component : object
        Component
    plugin_name : str
        Plugin name with file extension or no extension if folder
    """
    # identify plugins on system and those needing to transfer
    transfer_request = []
    to_install = []
    for plugin_name in plugin_names:
        if not plugin_name in os.listdir(fissure.utils.PLUGIN_DIR):
            transfer_request += [plugin_name]
        else:
            to_install += [plugin_name]

    refresh_frontend_widgets = True
    if len(transfer_request) > 0:
        # request transfer and installation of plugins
        PARAMETERS = {
            "plugin_names": transfer_request,
            "install": True
        }
        msg = {
            fissure.comms.MessageFields.IDENTIFIER: component.identifier,
            fissure.comms.MessageFields.MESSAGE_NAME: "transferPlugins",
            fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
        }
        await component.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)

        # do not update dashboard
        refresh_frontend_widgets = False

    # install available plugins
    for plugin_name in to_install:
        # sensor node installation
        await __installPlugin(component, plugin_name)

    # update database and dashboard
    PARAMETERS = {
        "refresh_frontend_widgets": refresh_frontend_widgets
    }
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "installPluginsDatabase",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    await component.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def transferPluginsInstall(component: object, plugins: List[tuple]):
    """Transfer and Install Plugins

    Parameters
    ----------
    component : object
        Component
    plugins : List[tuple]
        Plugin file data as (file name, binary ascii file data)
    """
    for (plugin_name, plugin_data) in plugins:
        # unpack plugin data
        plugin_name = unpackPlugin(plugin_name, plugin_data)

        # run installation
        await __installPlugin(component, plugin_name)

    # update database and dashboard
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "installPluginsDatabase",
    }
    await component.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def uninstallPlugins(component: object, plugin_names: str):
    """Uninstall Plugins

    Parameters
    ----------
    component : object
        Component
    plugin_names : str
        Plugin names with file extension
    """
    for plugin_name in plugin_names:
        # run uninstallation
        plugin.uninstall(plugin_name)

        # deregister plugin on hiprfisr for sensor node
        PARAMETERS = {
            "plugin_name": plugin_name
        }
        msg = {
            fissure.comms.MessageFields.IDENTIFIER: component.identifier,
            fissure.comms.MessageFields.MESSAGE_NAME: "deregisterPlugin",
            fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
        }
        await component.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)

    # update database and dashboard
    PARAMETERS = {
        "plugin_names": plugin_names
    }
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "uninstallPluginsDatabase",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    await component.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def removePlugin(component: object, node_uid: str, plugin_name: str):
    """Remove Plugin

    **WARNING**: This will remove the plugin from the sensor node file system

    Parameters
    ----------
    component : object
        Component
    node_uid : str
        Sensor node UID
    plugin_name : str
        Plugin name with file extension
    """
    # Remove plugin
    plugin.remove(plugin_name)


async def sendPluginNamesTak(
    component: object, 
    requester_uid: str, 
    requester_type: str, 
    node_uid: str, 
    tak_context: str
):
    """Send Plugin Names for TAK

    Parameters
    ----------
    component : object
        Component
    requester_uid : str
        TAK UID
    requester_type : str
        dashboard, tak, or broadcast        
    node_uid : str
        Sensor node UID
    tak_context : str
        node or ecosystem
    """
    try:
        plugin_names = plugin.get_local_plugin_names()

        # send plugin names
        PARAMETERS = {
            "requester_uid": requester_uid,
            "requester_type": requester_type,
            "node_uid": node_uid,
            "plugin_names": plugin_names,
            "tak_context": tak_context
        }
        msg = {
            fissure.comms.MessageFields.IDENTIFIER: component.identifier,
            fissure.comms.MessageFields.MESSAGE_NAME: "sendPluginNamesTakResults",
            fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
        }
        component.logger.debug(f"Sending plugin names for TAK UID {requester_uid}: {plugin_names}")
        await component.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)
    except Exception as e:
        component.logger.error(f"Error sending plugin names for TAK UID {requester_uid}: {e}")
        tb = traceback.format_exc()
        component.logger.debug(tb)


async def sendPluginActionNamesTak(
    component: object, 
    requester_uid: str, 
    requester_type: str, 
    plugin_name: str, 
    node_uid: str, 
    tak_context: str
):
    """Send Plugin Action Names for TAK

    Parameters
    ----------
    component : object
        Component
    requester_uid : str
        TAK UID
    requester_type : str
        dashboard, tak, or broadcast         
    plugin_name : str
        Plugin name
    node_uid : str
        Sensor node UID
    tak_context : str
        node or ecosystem
    """
    try:
        action_names = plugin.get_plugin_actions(plugin_name, component.settings_dict, component.logger)

        # send action names
        PARAMETERS = {
            "requester_uid": requester_uid,
            "requester_type": requester_type,
            "node_uid": node_uid,
            "plugin_name": plugin_name,
            "action_names": action_names,
            "tak_context": tak_context
        }
        msg = {
            fissure.comms.MessageFields.IDENTIFIER: component.identifier,
            fissure.comms.MessageFields.MESSAGE_NAME: "sendPluginActionNamesTakResults",
            fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
        }
        component.logger.debug(f"Sending action names for plugin {plugin_name} and TAK UID {requester_uid}: {action_names}")
        await component.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)
    except Exception as e:
        component.logger.error(f"Error sending action names for plugin {plugin_name} and TAK UID {requester_uid}: {e}")
        tb = traceback.format_exc()
        component.logger.debug(tb)


def _load_plugin_actions_module(plugin_name: str, logger=None):
    """
    Load <plugin>/actions.py so ACTION_TAGS and ACTION_HARDWARE can be inspected.
    """
    actions_path = os.path.join(
        fissure.utils.PLUGIN_DIR,
        plugin_name,
        "actions.py",
    )

    if not os.path.isfile(actions_path):
        return None

    module_name = f"fissure_plugin_{plugin_name}_actions"

    try:
        spec = importlib.util.spec_from_file_location(module_name, actions_path)
        if spec is None or spec.loader is None:
            return None

        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    except Exception as e:
        if logger:
            logger.error(f"Failed loading actions.py for plugin {plugin_name}: {e}")
            logger.debug(traceback.format_exc())
        return None


def _action_hardware_matches(selected_hardware: str, compatible_hardware) -> bool:
    """
    Loose hardware compatibility match for Dashboard display strings.

    Empty ACTION_HARDWARE entry means the action is not hardware-restricted.
    """
    if not compatible_hardware:
        return True

    selected = str(selected_hardware or "").strip().lower()
    if not selected:
        return True

    for hw in compatible_hardware:
        hw_text = str(hw or "").strip().lower()

        if not hw_text:
            continue

        if hw_text in selected or selected in hw_text:
            return True

    return False


def _action_tags_match(tags, include_tags, exclude_tags) -> bool:
    tag_set = set(tags or [])
    include_set = set(include_tags or [])
    exclude_set = set(exclude_tags or [])

    if include_set and not include_set.issubset(tag_set):
        return False

    if exclude_set and exclude_set.intersection(tag_set):
        return False

    return True


async def queryPluginActions(
    component: object,
    requester_uid: str,
    requester_type: str,
    node_uid: str,
    context: str = "",
    scope: str = "all_plugins",
    plugin_name: str = "",
    include_tags: List[str] = None,
    exclude_tags: List[str] = None,
    hardware: str = "",
):
    """
    Return plugin/action pairs matching generic tag and hardware filters.
    """
    try:
        include_tags = include_tags or []
        exclude_tags = exclude_tags or []

        if scope == "plugin" and plugin_name:
            plugin_names = [plugin_name]
        else:
            plugin_names = plugin.get_local_plugin_names()

        matches = []

        for candidate_plugin in plugin_names:
            plugin_path = os.path.join(fissure.utils.PLUGIN_DIR, candidate_plugin)
            if not os.path.isdir(plugin_path):
                continue

            actions_module = _load_plugin_actions_module(
                candidate_plugin,
                component.logger,
            )
            if actions_module is None:
                continue

            action_tags = getattr(actions_module, "ACTION_TAGS", {}) or {}
            action_hardware = getattr(actions_module, "ACTION_HARDWARE", {}) or {}

            # Use existing utility so disabled/invalid actions stay consistent
            # with the current plugin action list path.
            available_actions = plugin.get_plugin_actions(
                candidate_plugin,
                component.settings_dict,
                component.logger,
            )

            for action_name in available_actions:
                tags = action_tags.get(action_name, [])

                if not _action_tags_match(tags, include_tags, exclude_tags):
                    continue

                compatible_hardware = action_hardware.get(action_name, [])

                if not _action_hardware_matches(hardware, compatible_hardware):
                    continue

                matches.append(
                    {
                        "plugin": candidate_plugin,
                        "action": action_name,
                    }
                )

        PARAMETERS = {
            "requester_uid": requester_uid,
            "requester_type": requester_type,
            "node_uid": node_uid,
            "context": context,
            "actions": matches,
        }

        msg = {
            fissure.comms.MessageFields.IDENTIFIER: component.identifier,
            fissure.comms.MessageFields.MESSAGE_NAME: "queryPluginActionsResults",
            fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
        }

        component.logger.debug(
            f"queryPluginActions context={context}, "
            f"scope={scope}, plugin={plugin_name}, "
            f"include_tags={include_tags}, hardware={hardware}, "
            f"matches={matches}"
        )

        await component.hiprfisr_socket.send_msg(
            fissure.comms.MessageTypes.COMMANDS,
            msg,
        )

    except Exception as e:
        component.logger.error(f"queryPluginActions failed: {e}")
        component.logger.debug(traceback.format_exc())


async def findGPS_Coordinates(component: object, gps_source="", format=""):
    """
    Find the sensor node GPS coordinates using gpsd and return the information.
    """
    # Retrieve Coordinates
    if gps_source == "gpsd":
        get_coordinates = fissure.utils.hardware.probe_gpsd(component.logger, format, component.gpsd_serial_port, False)
    elif gps_source == "Meshtastic":
        # Use Existing Serial Connection
        if component.network_type == "Meshtastic":
            gps_data = await component.hiprfisr_socket.get_gps_position()
            if gps_data is None:
                get_coordinates = "No GPS data returned"
            else:
                get_coordinates = fissure.utils.format_coordinates(
                    gps_data['latitude'], 
                    gps_data['longitude'],
                    format
                )

        # Establish Serial Connection
        else:
            async with component.meshtastic_lock:  # Prevent multiple calls to serial port with beacon
                gps_data = await fissure.utils.hardware.probeMeshtasticGPS(component.meshtastic_serial_port, 10)

            if gps_data is None:
                get_coordinates = "No GPS data returned"
            else:
                get_coordinates = fissure.utils.format_coordinates(
                    gps_data['latitude'], 
                    gps_data['longitude'],
                    format
                )

    elif gps_source == "Saved":
        get_coordinates = fissure.utils.format_coordinates(
            component.gps_position['latitude'], 
            component.gps_position['longitude'], 
            format
        )
    elif gps_source == "Internet":
        gps_data = await fissure.utils.hardware.probeInternetGPS(component.logger)

        if gps_data is None:
            get_coordinates = "No GPS data returned"
        else:
            get_coordinates = fissure.utils.format_coordinates(
                gps_data["latitude"],
                gps_data["longitude"],
                format
            )
    else:
        get_coordinates = "Invalid GPS Source"

    # Return the Text
    # if get_coordinates:
    # Only return lat, lon
    PARAMETERS = {
        "coordinates": get_coordinates
    }
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "findGPS_CoordinatesResults",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    await component.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def gpsBeaconEnableDisableIP(component: object):
    """
    Deprecated compatibility callback.

    Node GPS/status publication is no longer controlled by a per-node
    gps_tak_beacon flag. TAK output is controlled by HIPRFISR TAK settings.
    """
    component.logger.info(
        "gpsBeaconEnableDisableIP is deprecated. "
        "Node position/status updates are always published to HIPRFISR."
    )

    PARAMETERS = {
        # Keep the old return key so existing Dashboard code does not break.
        "gps_tak_beacon_status": True
    }

    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "gpsBeaconEnableDisableIP_Return",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }

    await component.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def rebootIP(component: object):
    """
    Reboots the sensor node computer.
    """
    component.logger.info("Rebooting")
    
    # Reboot
    os.system("sudo reboot")


async def uptimeIP(component: object):
    """
    Retrieves the uptime of the sensor node computer.
    """
    # Get Uptime
    result = subprocess.check_output("uptime", shell=True, text=True)
    result = result.strip()

    # Extract current time and uptime duration
    match = re.search(r'(\d{1,2}:\d{2}(?::\d{2})?)\s+up\s+([^,]+)', result)
    if match:
        current_time = match.group(1)
        uptime_short = match.group(2).strip()
        uptime_string = f"{current_time} up {uptime_short}"
        component.logger.info(uptime_string)
    else:
        component.logger.error("Uptime format not recognized")
        uptime_string = "Uptime format not recognized"

    # Send Status
    PARAMETERS = {
        "uptime": uptime_string
    }
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "uptimeIP_Return",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    await component.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def memoryIP(component: object):
    """
    Retrieves the memory usage of the sensor node computer.
    """
    # Run the command
    output = subprocess.check_output("free -h", shell=True, text=True)

    # Send Status
    PARAMETERS = {
        "memory": output
    }
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "memoryIP_Return",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    await component.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def diskIP(component: object):
    """
    Retrieves the disk usage of the sensor node computer.
    """
    # Get disk usage for root
    disk_string = subprocess.check_output("df -h /", shell=True, text=True)

    # Send Status
    PARAMETERS = {
        "disk": disk_string
    }
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "diskIP_Return",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    await component.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def cpuIP(component: object):
    """
    Retrieves the CPU percentrage of the sensor node computer.
    """
    # Get CPU Percentage
    cpu_result = subprocess.check_output("top -bn1 | grep 'Cpu(s)' | awk '{print $2 + $4}'", shell=True, text=True).strip()
    cpu_result = f"{cpu_result}%"

    # Send Status
    PARAMETERS = {
        "cpu": cpu_result
    }
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "cpuIP_Return",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    await component.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def processesIP(component: object):
    """
    Retrieves the processes on the sensor node computer.
    """
    # Get Processes
    processes_result = subprocess.check_output("ps aux | grep -i fissure", shell=True, text=True).strip()

    # Send Status
    PARAMETERS = {
        "processes": processes_result
    }
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "processesIP_Return",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    await component.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def ifconfigIP(component: object):
    """
    Retrieves the ifconfig output on the sensor node computer.
    """
    # Get Processes
    ifconfig_result = subprocess.check_output("ifconfig", shell=True, text=True).strip()

    # Send Status
    PARAMETERS = {
        "ifconfig": ifconfig_result
    }
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "ifconfigIP_Return",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    await component.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def iwconfigIP(component: object):
    """
    Retrieves the iwconfig output on the sensor node computer.
    """
    # Get Processes
    iwconfig_result = subprocess.check_output("iwconfig", shell=True, text=True).strip()

    # Send Status
    PARAMETERS = {
        "iwconfig": iwconfig_result
    }
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "iwconfigIP_Return",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    await component.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def updateNodeSettings(component: object, settings_dict: dict):
    if not isinstance(settings_dict, dict):
        component.logger.error("updateNodeSettings received invalid settings_dict.")
        return

    if "Sensor Node" not in settings_dict:
        settings_dict = {"Sensor Node": settings_dict}

    component.settings_dict = settings_dict
    component.logger.info("Sensor Node settings updated in memory.")


async def streamArtifact(
    component: object,
    transfer_id: str,
    artifact_id: str,
) -> None:
    """
    Stream every declared file belonging to one logical artifact.

    Transfer framing:
        START          one per file
        CHUNK          zero or more per file
        FILE_COMPLETE  one per file
        COMPLETE       once after the entire artifact succeeds

    CHUNK sequence numbers restart at zero for each START frame.
    """
    logger: logging.Logger = component.logger
    artifact_manager: ArtifactManager = (
        component.artifact_manager
    )
    transfer_client = getattr(
        component,
        "artifact_transfer_client",
        None,
    )

    if transfer_client is None:
        logger.error(
            "Artifact transfer client is unavailable"
        )
        return

    artifact = artifact_manager.get_artifact(
        artifact_id
    )

    if artifact is None:
        await transfer_client.send_error(
            transfer_id,
            f"Artifact not found: {artifact_id}",
        )
        return

    if not artifact.files:
        await transfer_client.send_error(
            transfer_id,
            "Artifact has no declared files",
        )
        return

    artifact_file_count = int(artifact.file_count)
    artifact_total_size = int(artifact.total_size)

    total_bytes_sent = 0
    total_chunks_sent = 0
    completed_file_ids = []

    try:
        for file_index, artifact_file in enumerate(
            artifact.files,
            start=1,
        ):
            try:
                file_path = (
                    artifact_manager.resolve_artifact_file_path(
                        artifact.id,
                        artifact_file.id,
                    )
                )
            except Exception as exc:
                raise RuntimeError(
                    "Unable to resolve declared artifact file "
                    f"artifact_id={artifact.id} "
                    f"file_id={artifact_file.id}: {exc}"
                ) from exc

            actual_size = os.path.getsize(file_path)

            if actual_size != int(artifact_file.size):
                raise RuntimeError(
                    "Artifact file size no longer matches its manifest: "
                    f"{artifact_file.relative_path}"
                )

            actual_checksum = (
                fissure.utils.artifacts.calculate_file_checksum(
                    file_path
                )
            )

            if actual_checksum != artifact_file.sha256:
                raise RuntimeError(
                    "Artifact file checksum no longer matches its manifest: "
                    f"{artifact_file.relative_path}"
                )

            start_metadata = {
                "artifact_id": artifact.id,
                "source_id": artifact.source_id,
                "operation_id": artifact.operation_id,
                "artifact_name": artifact.name,
                "artifact_type": artifact.artifact_type,
                "artifact_file_count": artifact_file_count,
                "artifact_total_size": artifact_total_size,
                "file_index": file_index,
                "file_id": artifact_file.id,
                "filename": artifact_file.name,
                "relative_path": artifact_file.relative_path,
                "file_size": actual_size,
                "sha256": artifact_file.sha256,
                "role": artifact_file.role,
                "content_type": artifact_file.content_type,
                "file_metadata": dict(
                    artifact_file.metadata or {}
                ),
                "chunk_size": (
                    fissure.comms.ARTIFACT_CHUNK_SIZE
                ),
            }

            await transfer_client.send_start(
                transfer_id,
                start_metadata,
            )

            sequence = 0
            file_bytes_sent = 0

            with open(file_path, "rb") as handle:
                while True:
                    chunk = handle.read(
                        fissure.comms.ARTIFACT_CHUNK_SIZE
                    )

                    if not chunk:
                        break

                    await transfer_client.send_chunk(
                        transfer_id,
                        sequence,
                        chunk,
                    )

                    sequence += 1
                    file_bytes_sent += len(chunk)
                    total_bytes_sent += len(chunk)
                    total_chunks_sent += 1

                    await asyncio.sleep(0)

            if file_bytes_sent != actual_size:
                raise RuntimeError(
                    "Artifact file changed while streaming: "
                    f"{artifact_file.relative_path}"
                )

            await transfer_client.send_file_complete(
                transfer_id,
                {
                    "artifact_id": artifact.id,
                    "file_id": artifact_file.id,
                    "file_index": file_index,
                    "relative_path": (
                        artifact_file.relative_path
                    ),
                    "bytes_sent": file_bytes_sent,
                    "chunks_sent": sequence,
                    "sha256": artifact_file.sha256,
                },
            )

            completed_file_ids.append(
                artifact_file.id
            )

            logger.info(
                "Completed artifact file stream "
                "transfer_id=%s artifact_id=%s "
                "file_id=%s file=%s bytes=%s",
                transfer_id,
                artifact.id,
                artifact_file.id,
                artifact_file.relative_path,
                file_bytes_sent,
            )

        await transfer_client.send_complete(
            transfer_id,
            {
                "artifact_id": artifact.id,
                "source_id": artifact.source_id,
                "operation_id": artifact.operation_id,
                "file_count": artifact_file_count,
                "total_size": artifact_total_size,
                "bytes_sent": total_bytes_sent,
                "chunks_sent": total_chunks_sent,
                "completed_file_ids": completed_file_ids,
            },
        )

        logger.info(
            "Completed artifact stream "
            "transfer_id=%s artifact_id=%s "
            "files=%s bytes=%s",
            transfer_id,
            artifact.id,
            artifact_file_count,
            total_bytes_sent,
        )

    except Exception as exc:
        logger.error(
            "Artifact stream failed "
            "transfer_id=%s artifact_id=%s: %s",
            transfer_id,
            artifact_id,
            exc,
        )

        try:
            await transfer_client.send_error(
                transfer_id,
                str(exc),
            )
        except Exception:
            pass


async def refresh_status(
    component: object, 
    requester_uid: str,
    requester_type: str,
) -> None:
    """
    Immediately sends a GPS update to the HIPRFISR.

    Parameters
    ----------
    requester_uid : str
        TAK UID.
    requester_type : str
        dashboard, tak, or broadcast 
    """
    component.logger.info("Refreshing status and sending a GPS update to the HIPRFISR")

    gps_manager = getattr(component, "gps_manager", None)
    if not gps_manager:
        component.logger.warning("No gps_manager available; cannot refresh status.")
        return

    gps_source = component.gps_source

    # Determine the correct meshtastic argument
    meshtastic_arg = None

    if gps_source == "Meshtastic":
        if component.network_type == "Meshtastic":
            meshtastic_arg = component.hiprfisr_socket
        else:
            meshtastic_arg = component.meshtastic_serial_port

    await gps_manager.send_gps_update_now(gps_source, meshtastic_arg)


async def sendPluginActionParametersTak(
    component: object,
    requester_uid: str,
    requester_type: str,
    plugin_name: str,
    action_name: str,
    node_uid: str,
    tak_context: str
) -> None:
    """
    Node handler for hub->node request: "sendPluginActionParameters"

    Returns the action schema back to HIPRFISR.
    """

    try:
        component.logger.info(
            f"Fetching schema for {plugin_name}.{action_name} (node_uid={node_uid})"
        )

        # Validate plugin directory exists
        plugin_path = os.path.join(fissure.utils.PLUGIN_DIR, plugin_name)
        if not os.path.exists(plugin_path):
            component.logger.error(f"Plugin path does not exist: {plugin_path}")
            return

        # Use existing utility function (importlib.util based)
        schema = plugin.get_action_schema(plugin_name, action_name, component.logger)

        # Normalize schema shape
        if not isinstance(schema, dict):
            schema = {"params": []}
        if "params" not in schema or not isinstance(schema.get("params"), list):
            schema["params"] = []

        PARAMETERS = {
            "requester_uid": requester_uid,
            "requester_type": requester_type,
            "plugin_name": plugin_name,
            "action_name": action_name,
            "node_uid": node_uid,
            "schema": schema,
            "tak_context": tak_context
        }

        msg = {
            fissure.comms.MessageFields.IDENTIFIER: component.identifier,
            fissure.comms.MessageFields.MESSAGE_NAME: "sendPluginActionParametersResultsTak",
            fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
        }

        component.logger.debug(
            f"Sending schema for {plugin_name}.{action_name} "
            f"with {len(schema.get('params', []))} params"
        )

        # Node -> Hub
        await component.hiprfisr_socket.send_msg(
            fissure.comms.MessageTypes.COMMANDS,
            msg
        )

    except Exception as e:
        component.logger.error(
            f"Error sending schema for {plugin_name}.{action_name}: {e}"
        )
        component.logger.debug(traceback.format_exc())


async def sendPluginTargetActionsTak(
    component: object,
    requester_uid: str,
    requester_type: str,
    plugin_name: str,
    node_uid: str,
    target_id: str,
    classification_candidates: List[str],
) -> None:
    """
    Node handler for hub->node request: get plugin action names filtered by target classification.
    """
    try:
        component.logger.info(
            f"Fetching target actions for plugin={plugin_name}, "
            f"target_id={target_id}, classifications={classification_candidates}"
        )

        plugin_path = os.path.join(fissure.utils.PLUGIN_DIR, plugin_name)
        if not os.path.exists(plugin_path):
            component.logger.error(f"Plugin path does not exist: {plugin_path}")
            return

        action_names = plugin.get_actions_for_classifications(
            plugin_name,
            classification_candidates,
            component.logger
        )

        PARAMETERS = {
            "requester_uid": requester_uid,
            "requester_type": requester_type,
            "node_uid": node_uid,
            "plugin_name": plugin_name,
            "action_names": action_names,
            "tak_context": "node",
        }

        msg = {
            fissure.comms.MessageFields.IDENTIFIER: component.identifier,
            fissure.comms.MessageFields.MESSAGE_NAME: "sendPluginActionNamesTakResults",
            fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
        }
        component.logger.debug(f"Sending action names for plugin {plugin_name} and TAK UID {requester_uid}: {action_names}")
        await component.hiprfisr_socket.send_msg(
            fissure.comms.MessageTypes.COMMANDS,
            msg
        )

    except Exception as e:
        component.logger.error(
            f"Error sending target actions for plugin={plugin_name}, target_id={target_id}: {e}"
        )
        component.logger.debug(traceback.format_exc())


async def queryPluginActionSchema(
    component: object,
    requester_uid: str,
    requester_type: str,
    plugin_name: str,
    action_name: str,
    node_uid: str,
    context: str = "",
) -> None:
    """
    Node handler for Dashboard-only plugin action schema queries.

    This returns the action schema back to HIPRFISR as a normal command
    message, not as TAK/CoT.
    """
    try:
        component.logger.info(
            f"Fetching dashboard schema for {plugin_name}.{action_name} "
            f"(node_uid={node_uid}, context={context})"
        )

        plugin_path = os.path.join(fissure.utils.PLUGIN_DIR, plugin_name)
        if not os.path.exists(plugin_path):
            component.logger.error(f"Plugin path does not exist: {plugin_path}")
            return

        schema = plugin.get_action_schema(
            plugin_name,
            action_name,
            component.logger,
        )

        if not isinstance(schema, dict):
            schema = {"params": []}

        if "params" not in schema or not isinstance(schema.get("params"), list):
            schema["params"] = []

        PARAMETERS = {
            "requester_uid": requester_uid,
            "requester_type": requester_type,
            "plugin_name": plugin_name,
            "action_name": action_name,
            "node_uid": node_uid,
            "schema": schema,
            "context": context,
        }

        msg = {
            fissure.comms.MessageFields.IDENTIFIER: component.identifier,
            fissure.comms.MessageFields.MESSAGE_NAME: "queryPluginActionSchemaResults",
            fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
        }

        component.logger.debug(
            f"Sending dashboard schema for {plugin_name}.{action_name} "
            f"with {len(schema.get('params', []))} params "
            f"(context={context})"
        )

        await component.hiprfisr_socket.send_msg(
            fissure.comms.MessageTypes.COMMANDS,
            msg,
        )

    except Exception as e:
        component.logger.error(
            f"Error sending dashboard schema for {plugin_name}.{action_name}: {e}"
        )
        component.logger.debug(traceback.format_exc())


