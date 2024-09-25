import binascii
import fissure.comms
import fissure.utils
import fissure.utils.hardware
import os
import shutil
import subprocess
import threading
import time
import yaml
from concurrent.futures import ThreadPoolExecutor
import asyncio
import zmq


async def updateLoggingLevels(component: object, new_console_level="", new_file_level=""):
    """ 
    Update the logging levels on the Sensor Node.
    """
    # Update New Levels for Sensor Node
    component.updateLoggingLevels(new_console_level, new_file_level)


async def hiprfisrDisconnecting(component: object):
    """
    Stop trying to send data and heartbeats to the HIPRFISSR on an intentional disconnect.
    """
    # Stop Outgoing Messages
    component.hiprfisr_connected = False


async def transferSensorNodeFile(
    component: object, sensor_node_id=0, local_file_data="", remote_filepath="", refresh_file_list=False
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
            await refreshSensorNodeFiles(component, sensor_node_id, os.path.dirname(remote_filepath))


async def deleteArchiveReplayFiles(component: object, sensor_node_id=0):
    """
    Deletes all the files in the Archive_Replay folder on the sensor node ahead of file transfer for replay.
    """
    # Delete Files
    folder_location = os.path.join(fissure.utils.SENSOR_NODE_DIR, "Archive_Replay")
    for filename in os.listdir(folder_location):
        if os.path.isfile(os.path.join(folder_location, filename)):
            if filename != ".gitkeep":
                os.remove(os.path.join(folder_location, filename))


async def overwriteDefaultAutorunPlaylist(component: object, sensor_node_id=0, playlist_dict={}):
    """
    Overwrites the default autorun playlist yaml file with a dictionary configured in the Dashboard.
    """
    # Overwrite default.yaml
    # playlist_dict = eval(
    #     binascii.a2b_hex(eval(playlist_dict)).decode()
    # )  # fissureclass.py does not like dictionaries in commands
    component.logger.info("OVERWRITE!")
    filename = os.path.join(fissure.utils.SENSOR_NODE_DIR, "Autorun_Playlists", "default.yaml")
    with open(filename, "w") as stream:
        yaml.dump(playlist_dict, stream, default_flow_style=False, indent=5)


async def downloadSensorNodeFile(component: object, sensor_node_id=0, sensor_node_file="", download_folder=""):
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
                "sensor_node_id": sensor_node_id,
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
                "sensor_node_id": sensor_node_id,
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


async def deleteSensorNodeFile(component: object, sensor_node_id=0, sensor_node_file=""):
    """
    Deletes a file or folder local to the sensor node.
    """
    # Delete the File
    if os.path.exists(sensor_node_file):
        os.system('rm -Rf "' + sensor_node_file + '"')


async def refreshSensorNodeFiles(component: object, sensor_node_id=0, sensor_node_folder=""):
    """
    Returns file details for a specified folder.
    """
    # Update the Tree Widget
    if (sensor_node_id > -1) and (len(sensor_node_folder) > 0):
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
            "sensor_node_id": sensor_node_id,
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


async def autorunPlaylistStart(component: object, sensor_node_id=0, playlist_dict={}, trigger_values=[]):
    """
    Starts a new thread for cycling through the autorun playlist.
    """
    # Run Event and Do Not Block
    loop = asyncio.get_event_loop()
    loop.run_in_executor(None, component.autorunPlaylistStart, sensor_node_id, playlist_dict, trigger_values)
    # component.autorunPlaylistStart(sensor_node_id, playlist_dict, trigger_values)


async def autorunPlaylistStop(component: object, sensor_node_id=0):
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
    sensor_node_id=0,
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
        sensor_node_id,
        fuzzing_variables,
        fuzzing_type,
        fuzzing_min,
        fuzzing_max,
        fuzzing_update_period,
        fuzzing_seed_step,
    )


async def physicalFuzzingStop(component: object, sensor_node_id=0):
    """
    Stop physical fuzzing on the currently running attack flow graph.
    """
    # Stop the Thread
    component.physical_fuzzing_stop_event = True


async def multiStageAttackStart(
    component: object,
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
    Starts a new thread for running two flow graphs.
    A new thread is created to allow the Sensor Node to still perform normal
    functionality while waiting for an attack to finish.
    """
    # Use the Function that is Called Frequently in SensorNode.py
    if len(trigger_values) == 0:
        # Run Event and Do Not Block
        loop = asyncio.get_event_loop()
        loop.run_in_executor(None, component.multiStageAttackStart, sensor_node_id, filenames, variable_names, variable_values, durations, repeat, file_types, autorun_index)
    else:
        # Make a new Trigger Thread
        fissure_event_values = [sensor_node_id, filenames, variable_names, variable_values, durations, repeat, file_types, autorun_index]
        loop = asyncio.get_event_loop()
        loop.run_in_executor(None, component.triggerStart, trigger_values, "Multi-Stage Attack", fissure_event_values, autorun_index)
    await asyncio.sleep(0.1)


async def multiStageAttackStop(component: object, sensor_node_id=0, autorun_index=0):
    """Stops a multi-stage attack already in progress"""
    # Use the Function that is Called Frequently in SensorNode.py
    loop = asyncio.get_event_loop()
    loop.run_in_executor(None, component.multiStageAttackStop, sensor_node_id, autorun_index)


async def archivePlaylistStart(
    component: object,
    sensor_node_id=0,
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
        loop.run_in_executor(None, component.archivePlaylistThreadStart, sensor_node_id, flow_graph, filenames, frequencies, sample_rates, formats, channels, gains, durations, repeat, ip_address, serial)
    else:
        # Run Event and Do Not Block
        fissure_event_values = [sensor_node_id, flow_graph, filenames, frequencies, sample_rates, formats, channels, gains, durations, repeat, ip_address, serial]
        loop = asyncio.get_event_loop()
        loop.run_in_executor(None, component.triggerStart, trigger_values, "Archive Replay", fissure_event_values, -1)
    await asyncio.sleep(0.1)


async def archivePlaylistStop(component: object, sensor_node_id=0):
    """
    Stops a multi-stage attack already in progress
    """
    # Use the Function that is Called Frequently in SensorNode.py
    loop = asyncio.get_event_loop()
    loop.run_in_executor(None, component.archivePlaylistStop, sensor_node_id)
    # component.archivePlaylistStop(sensor_node_id)
    await asyncio.sleep(0.1)


async def attackFlowGraphStart(
    component: object,
    sensor_node_id=0,
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
        loop.run_in_executor(None, component.attackFlowGraphStart, sensor_node_id, flow_graph_filepath, variable_names, variable_values, file_type, run_with_sudo, autorun_index)
    else:
        # Run Event and Do Not Block
        fissure_event_values = [sensor_node_id, flow_graph_filepath, variable_names, variable_values, file_type, run_with_sudo, autorun_index]
        loop = asyncio.get_event_loop()
        loop.run_in_executor(None, component.triggerStart, trigger_values, "Single-Stage Attack", fissure_event_values, autorun_index)
    await asyncio.sleep(0.1)


async def attackFlowGraphStop(component: object, sensor_node_id=0, parameter="", autorun_index=0):
    """
    Stop the currently running attack flow graph.
    """
    # Use the Function that is Called Frequently in SensorNode.py
    component.attackFlowGraphStop(sensor_node_id, parameter, autorun_index)
    # loop = asyncio.get_event_loop()
    # loop.run_in_executor(None, component.attackFlowGraphStop, sensor_node_id, parameter, autorun_index)


async def iqFlowGraphStart(
    component: object, sensor_node_id=0, flow_graph_filepath="", variable_names=[], variable_values=[], file_type=""
):
    """
    Runs the IQ flow graph with the specified file path.
    """
    # Local or Remote Directories
    if component.settings_dict["Sensor Node"]["local_remote"] == "remote":
        for n in range(0, len(variable_names)):
            if variable_names[n] == "filepath":
                # Playback
                if flow_graph_filepath.startswith('iq_playback'):
                    return_filepath = ""
                    variable_values[n] = os.path.join(fissure.utils.SENSOR_NODE_DIR, "IQ_Data_Playback", "playback.iq")
                    read_filepath = ""
                    
                # Record
                else:
                    return_filepath = variable_values[n]  # For record message, HIPRFISR computer
                    variable_values[n] = component.replaceUsername(variable_values[n], os.getenv('USER'))
                    read_filepath = variable_values[n]  # For record message, Sensor Node computer
    else:
        read_filepath = ""
        return_filepath = ""

    # Run Event and Do Not Block
    loop = asyncio.get_event_loop()
    loop.run_in_executor(
        None, 
        component.iqFlowGraphThread, 
        sensor_node_id,
        flow_graph_filepath,
        variable_names,
        variable_values,
        read_filepath,
        return_filepath,
    )

    # # Make a new Thread
    # stop_event = threading.Event()
    # if file_type == "Flow Graph":
    #     c_thread = threading.Thread(
    #         target=component.iqFlowGraphThread,
    #         args=(
    #             stop_event,
    #             sensor_node_id,
    #             flow_graph_filepath,
    #             variable_names,
    #             variable_values,
    #             read_filepath,
    #             return_filepath,
    #         ),
    #     )
    # c_thread.daemon = True
    # c_thread.start()


async def iqFlowGraphStop(component: object, parameter=""):
    """
    Stop the currently running IQ flow graph.
    """
    # Use the Function that is Called Frequently in SensorNode.py
    component.iqFlowGraphStop(parameter)


async def inspectionFlowGraphStart(
    component: object, sensor_node_id=0, flow_graph_filepath="", variable_names=[], variable_values=[], file_type=""
):
    """Runs the flow graph with the specified file path."""
    # Only Supports Flow Graphs with GUIs
    if file_type == "Flow Graph - GUI":

        # Run Event and Do Not Block
        loop = asyncio.get_event_loop()
        loop.run_in_executor(
            None, 
            component.inspectionFlowGraphGUI_Thread, 
            sensor_node_id,
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
    component: object, sensor_node_id=0, flow_graph_filepath="", variable_names=[], variable_values=[]
):
    """
    Runs the flow graph with the specified file path.
    """
    # Run Event and Do Not Block
    class_name = flow_graph_filepath.replace(".py", "")
    loop = asyncio.get_event_loop()
    loop.run_in_executor(None, component.snifferFlowGraphThread, sensor_node_id, class_name, variable_names, variable_values)


async def snifferFlowGraphStop(component: object, sensor_node_id=0, parameter=""):
    """
    Stop the currently running flow graph.
    """
    # Stop Sniffer Flow Graph (Wireshark Keeps Going)
    component.snifferflowtoexec.stop()
    component.snifferflowtoexec.wait()
    del component.snifferflowtoexec  # Free up the ports

    if parameter == "Stream":
        await component.flowGraphFinished(sensor_node_id, "Sniffer - Stream")
    elif parameter == "TaggedStream":
        await component.flowGraphFinished(sensor_node_id, "Sniffer - Tagged Stream")
    elif parameter == "Message/PDU":
        await component.flowGraphFinished(sensor_node_id, "Sniffer - Message/PDU")


async def startScapy(component: object, sensor_node_id=0, interface="", interval=0, loop=False, operating_system=""):
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


async def stopScapy(component: object, sensor_node_id=0):
    """
    Stop the currently running Scapy operation.
    """
    # Stop the Thread
    os.system('sudo pkill -f "python2 scapy"')


async def setVariable(component: object, sensor_node_id=0, flow_graph="", variable="", value=""):
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
        elif flow_graph == "Wideband":
            getattr(component.wideband_flowtoexec, formatted_name)(float(value))
    else:
        if flow_graph == "Protocol Discovery":
            getattr(component.pdflowtoexec, formatted_name)(value)
        elif flow_graph == "Attack":
            getattr(component.attackflowtoexec, formatted_name)(value)
        elif flow_graph == "Sniffer":
            getattr(component.snifferflowtoexec, formatted_name)(value)
        elif flow_graph == "Wideband":
            getattr(component.wideband_flowtoexec, formatted_name)(value)


async def protocolDiscoveryFG_Start(
    component: object, sensor_node_id=0, flow_graph_filepath="", variable_names=[], variable_values=[]
):
    """
    Runs the flow graph with the specified file path.
    """
    # Run Event and Do Not Block
    class_name = flow_graph_filepath.replace(".py", "")
    loop = asyncio.get_event_loop()
    loop.run_in_executor(None, component.protocolDiscoveryFG_ThreadStart, sensor_node_id, class_name, variable_names, variable_values)


async def protocolDiscoveryFG_Stop(component: object, sensor_node_id=0):
    """
    Stop the currently running flow graph.
    """
    component.pdflowtoexec.stop()
    component.pdflowtoexec.wait()
    del component.pdflowtoexec  # Free up the ports


async def updateConfiguration(
    component: object, sensor_node_id=0, start_frequency=0, end_frequency=0, step_size=0, dwell_time=0, detector_port=0
):
    """
    Updates the TSI Configuration with the specified values.
    """
    # Stop the Current Sweep
    # if component.running_TSI_wideband == True:
    # component.stopWidebandThread()

    # Update the Sweep Variables
    component.wideband_start_freq = []
    component.wideband_stop_freq = []
    component.wideband_step_size = []
    component.wideband_dwell = []
    for n in range(0, len(start_frequency)):
        component.wideband_start_freq.append(float(start_frequency[n]))
        component.wideband_stop_freq.append(float(end_frequency[n]))
        component.wideband_step_size.append(float(step_size[n]))
        component.wideband_dwell.append(float(dwell_time[n]))
    component.wideband_band = 0
    component.configuration_updated = True

    # Start a New Sweep
    if not component.running_TSI_wideband:
        # Run Event and Do Not Block
        loop = asyncio.get_event_loop()
        loop.run_in_executor(None, component.startWidebandThread, sensor_node_id, detector_port)


async def startTSI_Detector(component: object, sensor_node_id=0, detector="", variable_names=[], variable_values=[], detector_port=0):
    """
    Begins TSI processing of signals after receiving the command from the HIPRFISR.
    """
    component.logger.info("TSI: Starting TSI Detector...")
    component.running_TSI = True

    # Make a New Wideband Thread
    if len(detector) > 0:
        if detector == "wideband_x3x0.py":
            flow_graph_filename = "wideband_x3x0.py"
        elif detector == "wideband_b2x0.py":
            flow_graph_filename = "wideband_b2x0.py"
        elif detector == "wideband_hackrf.py":
            flow_graph_filename = "wideband_hackrf.py"
        elif detector == "wideband_b20xmini.py":
            flow_graph_filename = "wideband_b20xmini.py"
        elif detector == "wideband_rtl2832u.py":
            flow_graph_filename = "wideband_rtl2832u.py"
        elif detector == "wideband_limesdr.py":
            flow_graph_filename = "wideband_limesdr.py"
        elif detector == "wideband_bladerf.py":
            flow_graph_filename = "wideband_bladerf.py"
        elif detector == "wideband_plutosdr.py":
            flow_graph_filename = "wideband_plutosdr.py"
        elif detector == "wideband_usrp2.py":
            flow_graph_filename = "wideband_usrp2.py"
        elif detector == "wideband_usrp_n2xx.py":
            flow_graph_filename = "wideband_usrp_n2xx.py"
        elif detector == "wideband_bladerf2.py":
            flow_graph_filename = "wideband_bladerf2.py"
        elif detector == "wideband_usrp_x410.py":
            flow_graph_filename = "wideband_usrp_x410.py"
        elif detector == "wideband_rspduo.py":
            flow_graph_filename = "wideband_rspduo.py"
        elif detector == "wideband_rspdx.py":
            flow_graph_filename = "wideband_rspdx.py"                        
        elif detector == "wideband_rspdx_r2.py":
            flow_graph_filename = "wideband_rspdx_r2.py"                        
        elif detector == "IQ File":
            flow_graph_filename = "iq_file.py"
        elif "fixed_threshold" in detector:
            if detector == "fixed_threshold_x3x0.py":
                flow_graph_filename = "fixed_threshold_x3x0.py"
            elif detector == "fixed_threshold_b2x0.py":
                flow_graph_filename = "fixed_threshold_b2x0.py"
            elif detector == "fixed_threshold_hackrf.py":
                flow_graph_filename = "fixed_threshold_hackrf.py"
            elif detector == "fixed_threshold_b20xmini.py":
                flow_graph_filename = "fixed_threshold_b20xmini.py"
            elif detector == "fixed_threshold_rtl2832u.py":
                flow_graph_filename = "fixed_threshold_rtl2832u.py"
            elif detector == "fixed_threshold_limesdr.py":
                flow_graph_filename = "fixed_threshold_limesdr.py"
            elif detector == "fixed_threshold_bladerf.py":
                flow_graph_filename = "fixed_threshold_bladerf.py"
            elif detector == "fixed_threshold_plutosdr.py":
                flow_graph_filename = "fixed_threshold_plutosdr.py"
            elif detector == "fixed_threshold_usrp2.py":
                flow_graph_filename = "fixed_threshold_usrp2.py"
            elif detector == "fixed_threshold_usrp_n2xx.py":
                flow_graph_filename = "fixed_threshold_usrp_n2xx.py"
            elif detector == "fixed_threshold_bladerf2.py":
                flow_graph_filename = "fixed_threshold_bladerf2.py"
            elif detector == "fixed_threshold_usrp_x410.py":
                flow_graph_filename = "fixed_threshold_usrp_x410.py"
            elif detector == "fixed_threshold_rspduo.py":
                flow_graph_filename = "fixed_threshold_rspduo.py"
            elif detector == "fixed_threshold_rspdx.py":
                flow_graph_filename = "fixed_threshold_rspdx.py"                                
            elif detector == "fixed_threshold_rspdx_r2.py":
                flow_graph_filename = "fixed_threshold_rspdx_r2.py"                                
            elif detector == "fixed_threshold_simulator.py":
                flow_graph_filename = "fixed_threshold_simulator.py"

            # Run Event and Do Not Block
            loop = asyncio.get_event_loop()
            loop.run_in_executor(None, component.detectorFlowGraphGUI_Thread, sensor_node_id, flow_graph_filename, variable_names, variable_values, detector_port)
            return

        # Simulator Detector Thread
        if detector == "Simulator":
            # Run Event and Do Not Block
            loop = asyncio.get_event_loop()
            loop.run_in_executor(None, component.runDetectorSimulatorThread, variable_names, variable_values, detector_port)

            # Create a Temporary ZMQ SUB
            component.tsi_detector_context = zmq.Context()
            component.tsi_detector_socket = component.tsi_detector_context.socket(zmq.SUB)
            component.tsi_detector_socket.connect("tcp://127.0.0.1:" + str(detector_port))
            component.tsi_detector_socket.setsockopt_string(zmq.SUBSCRIBE, "")
            
        # Flow Graph Detector Thread
        else:
            # IQ File Detector/No Update Button
            if detector == "IQ File":
                # Create the Temporary ZMQ SUB
                component.tsi_detector_context = zmq.Context()
                component.tsi_detector_socket = component.tsi_detector_context.socket(zmq.SUB)
                component.tsi_detector_socket.connect("tcp://127.0.0.1:" + str(detector_port))
                component.tsi_detector_socket.setsockopt_string(zmq.SUBSCRIBE, "")

            # Run Event and Do Not Block, SUB Created on Update Click
            print("HEEEEEEEEEEEEEREDSAF")
            class_name = flow_graph_filename.replace(".py", "")
            print(flow_graph_filename)
            print(class_name)
            print(variable_names)
            print(variable_values)
            loop = asyncio.get_event_loop()
            loop.run_in_executor(None, component.runWidebandThread, sensor_node_id, class_name, variable_names, variable_values)


async def stopTSI_Detector(component: object, sensor_node_id=0):
    """
    Pauses TSI processing of signals after receiving the command from the HIPRFISR
    """
    # Call the Function used Multiple Times
    component.stopTSI_Detector(sensor_node_id)


async def startPD(component: object, sensor_node_id=0):
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


async def stopPD(component: object, sensor_node_id=0):
    """
    Closes the ZMQ SUB listening for bits.
    """
    # Call the Function used Multiple Times
    component.stopPD(sensor_node_id)


async def terminateSensorNode(component: object):
    """
    Stops sensor_node.py for local operations.
    """
    # Exit
    component.logger.info("sensor node shutdown")
    component.shutdown = True


async def recallSettings(component: object):
    """
    Recall default settings from a local yaml file and send to HIPRFISR.
    """
    # Recall Default Settings Saved Locally
    component.logger.info("Recall Settings")

    filename = os.path.join(fissure.utils.SENSOR_NODE_DIR, "Sensor_Node_Config", "default.yaml")
    with open(filename) as yaml_library_file:
        settings_dict = yaml.load(yaml_library_file, yaml.FullLoader)

    # Send the Message
    PARAMETERS = {"settings_dict": settings_dict}
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "recallSettingsReturn",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    await component.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def probeHardware(component: object, tab_index=0, table_row_text=[]):
    """
    Probe the selected hardware from the table and return the information.
    """
    get_hardware = str(table_row_text[0])
    output = ""
    height_width = ["", ""]

    if get_hardware == "USRP X3x0":
        # Get IP Address
        get_ip = str(table_row_text[5])

        # Probe
        try:
            proc = await asyncio.create_subprocess_shell(
                'uhd_usrp_probe --args="addr=' + get_ip + '" &',
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            output, _ = await proc.communicate()
            output = output.decode()
        except Exception as e:
            output = f"Error: {str(e)}"

    elif (get_hardware == "USRP B2x0") or (get_hardware == "USRP B20xmini"):
        # Probe
        try:
            proc = await asyncio.create_subprocess_shell(
                'uhd_usrp_probe --args="type=b200" &',
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            output, _ = await proc.communicate()
            output = output.decode()
        except Exception as e:
            output = f"Error: {str(e)}"

    elif get_hardware == "bladeRF":
        try:
            proc = await asyncio.create_subprocess_shell(
                "bladeRF-cli -p &",
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            output, _ = await proc.communicate()
            output = output.decode()
            height_width = [140, 400]
        except Exception as e:
            output = f"Error: {str(e)}"

    elif get_hardware == "LimeSDR":
        # Probe
        try:
            proc = await asyncio.create_subprocess_shell(
                "LimeUtil --find &",
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            output, _ = await proc.communicate()
            output = output.decode()
            height_width = [75, 700]
        except Exception as e:
            output = f"Error: {str(e)}"

    elif get_hardware == "HackRF":
        # Probe
        try:
            proc = await asyncio.create_subprocess_shell(
                "hackrf_info &",
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            output, _ = await proc.communicate()
            output = output.decode()
            height_width = [300, 500]
        except Exception as e:
            output = f"Error: {str(e)}"

    elif get_hardware == "PlutoSDR":
        # Probe
        try:
            proc = await asyncio.create_subprocess_shell(
                "iio_info -n pluto.local &",
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            output, _ = await proc.communicate()
            output = output.decode()
            height_width = [600, 900]
        except Exception as e:
            output = f"Error: {str(e)}"

    elif get_hardware == "USRP2":
        # Get IP Address
        get_ip = str(table_row_text[5])

        # Probe
        try:
            proc = await asyncio.create_subprocess_shell(
                'uhd_usrp_probe --args="addr=' + get_ip + '" &',
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            output, _ = await proc.communicate()
            output = output.decode()
        except Exception as e:
            output = f"Error: {str(e)}"

    elif get_hardware == "USRP N2xx":
        # Get IP Address
        get_ip = str(table_row_text[5])

        # Probe
        try:
            proc = await asyncio.create_subprocess_shell(
                'uhd_usrp_probe --args="addr=' + get_ip + '" &',
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            output, _ = await proc.communicate()
            output = output.decode()
        except Exception as e:
            output = f"Error: {str(e)}"

    elif get_hardware == "bladeRF 2.0":
        # Probe
        try:
            proc = await asyncio.create_subprocess_shell(
                "bladeRF-cli -p &",
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            output, _ = await proc.communicate()
            output = output.decode()
            height_width = [140, 400]
        except Exception as e:
            output = f"Error: {str(e)}"

    elif get_hardware == "USRP X410":
        # Get IP Address
        get_ip = str(table_row_text[5])

        # Probe
        try:
            proc = await asyncio.create_subprocess_shell(
                'uhd_usrp_probe --args="addr=' + get_ip + '" &',
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            output, _ = await proc.communicate()
            output = output.decode()
        except Exception as e:
            output = f"Error: {str(e)}"

    elif get_hardware == "RTL2832U":
        # Probe
        try:
            proc = await asyncio.create_subprocess_shell(
                "rtl_sdr -d -1 &", 
                shell=True, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE
            )  # Return text is in stderr
            _, output = await proc.communicate()
            output = output.decode()
            output = output.split("No matching devices found.")[0]

            height_width = [300, 500]
        except Exception as e:
            output = f"Error: {str(e)}"

    elif get_hardware == "RSPduo":
        # Probe
        try:
            proc = await asyncio.create_subprocess_shell(
                "lsusb &", 
                shell=True, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE
            )  # Return text is in stderr
            output, _ = await proc.communicate()
            output = output.decode()

            height_width = [300, 500]
        except Exception as e:
            output = f"Error: {str(e)}"

    elif get_hardware == "RSPdx":
        # Probe
        try:
            proc = await asyncio.create_subprocess_shell(
                "lsusb &", 
                shell=True, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE
            )  # Return text is in stderr
            output, _ = await proc.communicate()
            output = output.decode()

            height_width = [300, 500]
        except Exception as e:
            output = f"Error: {str(e)}"

    elif get_hardware == "RSPdx R2":
        # Probe
        try:
            proc = await asyncio.create_subprocess_shell(
                "lsusb &", 
                shell=True, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE
            )  # Return text is in stderr
            output, _ = await proc.communicate()
            output = output.decode()

            height_width = [300, 500]
        except Exception as e:
            output = f"Error: {str(e)}"

    # Return the Text
    PARAMETERS = {"tab_index": tab_index, "output": output, "height_width": height_width}
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "hardwareProbeResults",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    await component.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def scanHardware(component: object, tab_index=0, hardware_list=[]):
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

    # Return Scan Results
    PARAMETERS = {"tab_index": tab_index, "hardware_scan_results": all_scan_results}
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "hardwareScanResults",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    await component.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def guessHardware(component: object, tab_index=0, table_row=[], table_row_text=[], guess_index=0):
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

    # Return Guess Results
    PARAMETERS = {
        "tab_index": tab_index,
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
