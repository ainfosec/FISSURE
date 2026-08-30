import binascii
import fissure.comms
import fissure.utils
import fissure.utils.hardware
from fissure.utils import plugin
from fissure.utils.artifacts import ArtifactManager
from fissure.utils import scapy_compat
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


async def refreshSensorNodeActivity(component: object, log_limit=100):
    """Return one bounded read-only Activity snapshot to HIPRFISR."""
    def safe_text(value, max_chars=2048):
        try:
            text = str(value)
        except Exception:
            text = repr(value)

        if len(text) > max_chars:
            text = text[:max_chars] + "…"

        return text

    operations = []
    for operation_id, operation in list((getattr(component, "operations", {}) or {}).items()):
        if not isinstance(operation, dict):
            continue

        parameters = []
        raw_parameters = operation.get("user_parameters") or {}
        if isinstance(raw_parameters, dict):
            for name, value in raw_parameters.items():
                parameters.append({
                    "name": safe_text(name, 256),
                    "value": safe_text(value, 2048),
                })

        resources = []
        raw_resources = operation.get("resources") or {}
        if isinstance(raw_resources, dict):
            for resource_key, resource in raw_resources.items():
                resource = resource if isinstance(resource, dict) else {}
                resources.append({
                    "type": safe_text(resource.get("type") or "", 256),
                    "name": safe_text(
                        resource.get("description")
                        or resource.get("model")
                        or resource_key,
                        512,
                    ),
                    "identifier": safe_text(resource.get("serial") or "", 512),
                })

        owner = "Autorun" if str(operation.get("owner") or "").strip() else ""

        operations.append({
            "plugin": safe_text(operation.get("plugin") or "", 256),
            "activity": safe_text(operation.get("operation") or "", 512),
            "operation_id": safe_text(operation_id, 128),
            "start_time": operation.get("start_time") or 0,
            "owner": owner,
            "parameters": parameters,
            "resources": resources,
        })

    operations.sort(
        key=lambda operation: float(operation.get("start_time") or 0),
        reverse=True,
    )

    try:
        log_limit = max(0, min(int(log_limit), 100))
    except (TypeError, ValueError):
        log_limit = 100

    log_entries = []
    log_path = os.path.join(fissure.utils.LOG_DIR, "event.log")
    logger_token = f"fissure.sensor node {component.uuid[:8]}".lower()
    max_scan_bytes = 2 * 1024 * 1024

    if log_limit > 0 and os.path.isfile(log_path):
        def process_log_line(raw_line):
            line = raw_line.decode("utf-8", errors="replace").strip()
            lower_line = line.lower()

            if logger_token not in lower_line:
                return

            level_match = re.search(
                r"\[(INFO|WARNING|ERROR|CRITICAL)\]",
                line,
                re.IGNORECASE,
            )
            if level_match is None:
                return

            level = level_match.group(1).upper()
            if level == "CRITICAL":
                level = "ERROR"

            # FISSURE event.log format:
            # 08/28/2026 07:59:37 PM - fissure.sensor node d2674c57: [INFO] ...
            timestamp_match = re.match(
                r"^\d{2}/\d{2}/\d{4}\s+(\d{2}:\d{2}:\d{2}\s+[AP]M)\s+-\s+",
                line,
                re.IGNORECASE,
            )

            display_time = ""
            if timestamp_match is not None:
                raw_time = timestamp_match.group(1)
                try:
                    display_time = time.strftime(
                        "%H:%M:%S",
                        time.strptime(raw_time, "%I:%M:%S %p"),
                    )
                except ValueError:
                    display_time = raw_time

            logger_index = lower_line.find(logger_token)
            message = line[logger_index + len(logger_token):]
            message = re.sub(r"^[\s:\-\u2013\u2014]+", "", message).strip()

            # The level already has its own table column. Remove one or more
            # leading log-level tags from the message, while leaving tags that
            # occur later in the actual payload untouched.
            message = re.sub(
                r"^(?:\[(?:INFO|WARNING|ERROR|CRITICAL)\]\s*)+",
                "",
                message,
                flags=re.IGNORECASE,
            ).strip()

            log_entries.append({
                "time": display_time,
                "level": level,
                "message": safe_text(message, 2048),
            })

        try:
            with open(log_path, "rb") as log_file:
                log_file.seek(0, os.SEEK_END)
                position = log_file.tell()
                remainder = b""
                scanned = 0

                while position > 0 and len(log_entries) < log_limit and scanned < max_scan_bytes:
                    read_size = min(8192, position, max_scan_bytes - scanned)
                    position -= read_size
                    log_file.seek(position)
                    block = log_file.read(read_size)
                    scanned += read_size

                    combined = block + remainder
                    lines = combined.split(b"\n")
                    remainder = lines[0]

                    for raw_line in reversed(lines[1:]):
                        process_log_line(raw_line)
                        if len(log_entries) >= log_limit:
                            break

                if (
                    position == 0
                    and remainder
                    and len(log_entries) < log_limit
                    and scanned <= max_scan_bytes
                ):
                    process_log_line(remainder)

        except Exception:
            component.logger.debug(
                "Could not read Sensor Node Activity log snapshot.",
                exc_info=True,
            )

    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "refreshSensorNodeActivityResults",
        fissure.comms.MessageFields.PARAMETERS: {
            "node_uid": component.uuid,
            "operations": operations,
            "log_entries": log_entries,
        },
    }
    await component.hiprfisr_socket.send_msg(
        fissure.comms.MessageTypes.COMMANDS,
        msg,
    )


async def autorunPlaylistQuery(component: object):
    """Return stored Autorun playlist filenames to HIPRFISR."""
    playlists = component.get_autorun_playlist_names()
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "autorunPlaylistQueryResults",
        fissure.comms.MessageFields.PARAMETERS: {
            "node_uid": component.uuid,
            "playlists": playlists,
            "state": component.autorun_state,
            "source": component.autorun_source,
            "message": component.autorun_message,
        },
    }
    await component.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def autorunPlaylistLoad(component: object, playlist_filename=""):
    """Return one stored Autorun playlist to HIPRFISR."""
    success = True
    message = ""
    playlist_dict = {}
    try:
        playlist_dict = component.load_autorun_playlist_file(playlist_filename)
    except Exception as error:
        success = False
        message = str(error)

    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "autorunPlaylistLoadResults",
        fissure.comms.MessageFields.PARAMETERS: {
            "node_uid": component.uuid,
            "playlist_filename": playlist_filename,
            "playlist_dict": playlist_dict,
            "success": success,
            "message": message,
        },
    }
    await component.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def autorunPlaylistSave(component: object, playlist_filename="", playlist_dict=None):
    """Save one plugin-backed Autorun playlist and report completion."""
    success = True
    message = ""
    saved_filename = playlist_filename
    try:
        saved_filename = component.save_autorun_playlist_file(playlist_filename, playlist_dict or {})
    except Exception as error:
        success = False
        message = str(error)

    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "autorunPlaylistSaveResults",
        fissure.comms.MessageFields.PARAMETERS: {
            "node_uid": component.uuid,
            "playlist_filename": saved_filename,
            "success": success,
            "message": message,
        },
    }
    await component.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def autorunPlaylistStart(component: object, playlist_dict=None):
    """Start the in-memory plugin-backed Autorun playlist sent by the Dashboard."""
    await component.start_autorun_playlist(playlist_dict or {}, source="Dashboard Playlist")


async def autorunPlaylistExecute(component: object, playlist_filename=""):
    """Start one plugin-backed Autorun playlist already stored on the Sensor Node."""
    await component.start_autorun_playlist_file(playlist_filename, source=playlist_filename)


async def autorunPlaylistStop(component: object):
    """Stop the active plugin-backed Autorun run."""
    await component.stop_autorun_playlist()


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


async def refreshScapyInterfaces(component: object):
    """Return the Sensor Node's Scapy-visible network interfaces to HIPRFISR."""
    interfaces = scapy_compat.get_interfaces()

    parameters = {
        "node_uid": str(getattr(component, "uuid", "") or ""),
        "interfaces": interfaces,
    }

    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "refreshScapyInterfacesResults",
        fissure.comms.MessageFields.PARAMETERS: parameters,
    }

    await component.hiprfisr_socket.send_msg(
        fissure.comms.MessageTypes.COMMANDS,
        msg,
    )


async def startScapyTransmission(
    component: object,
    operation_id="",
    interface="",
    method="",
    interval=0.1,
    count=1,
    loop=False,
    packet_hex="",
    root_layer="Ether",
):
    """Start a Scapy transmission operation on this Sensor Node."""
    operation_id = str(operation_id or "").strip()

    async def progress_callback(
            operation_id="",
            state="",
            message="",
            packets_sent=0,
            set_rate="",
            started="",
        ):
            msg = {
                fissure.comms.MessageFields.IDENTIFIER: component.identifier,
                fissure.comms.MessageFields.MESSAGE_NAME: "scapyTransmissionStatus",
                fissure.comms.MessageFields.PARAMETERS: {
                    "node_uid": str(getattr(component, "uuid", "") or ""),
                    "operation_id": str(operation_id or ""),
                    "state": str(state or ""),
                    "message": str(message or ""),
                    "packets_sent": int(packets_sent or 0),
                    "set_rate": str(set_rate or ""),
                    "started": str(started or ""),
                },
            }

            await component.hiprfisr_socket.send_msg(
                fissure.comms.MessageTypes.COMMANDS,
                msg,
            )

    if not operation_id:
        await progress_callback(
            operation_id="",
            state="error",
            message="Missing operation ID.",
        )
        return

    parameters = {
        "operation_id": operation_id,
        "requester": "scapy_tab",
        "packet_hex": str(packet_hex or ""),
        "root_layer": str(root_layer or "Ether"),
        "interface": str(interface or ""),
        "method": str(method or ""),
        "interval": float(interval),
        "count": int(count),
        "loop": bool(loop),
        "description": "Scapy packet transmission",
        "progress_callback": progress_callback,
    }

    launched_operation_id = await component.run_plugin_operation(
        component,
        "Base",
        "scapy_transmit.py",
        parameters,
        str(getattr(component, "uuid", "") or ""),
    )

    if launched_operation_id is None:
        await progress_callback(
            operation_id=operation_id,
            state="error",
            message="Could not start the Scapy transmit operation.",
        )


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
        elif flow_graph == "Sniffer":
            getattr(component.snifferflowtoexec, formatted_name)(float(value))
    else:
        if flow_graph == "Protocol Discovery":
            getattr(component.pdflowtoexec, formatted_name)(value)
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


async def _get_plugin_inventory_with_setup_checks(component: object):
    """Build local plugin inventory and evaluate deployed setup hooks."""
    inventory = plugin.get_local_plugin_inventory()

    for plugin_name, entry in inventory.items():
        if not isinstance(entry, dict):
            continue

        if not entry.get("setup_present"):
            entry["setup_status"] = "Ready"
            entry["setup_message"] = "No external setup required."
            entry["setup_output"] = ""
            entry["setup_returncode"] = 0
            continue

        check_result = await plugin.run_plugin_setup(
            plugin_name,
            "check",
            timeout=20.0,
        )

        entry["setup_status"] = str(
            check_result.get("status")
            or "Setup Failed"
        )
        entry["setup_message"] = str(
            check_result.get("message")
            or ""
        )
        entry["setup_output"] = str(
            check_result.get("output")
            or ""
        )
        entry["setup_returncode"] = check_result.get("returncode")

    return inventory


def _plugin_has_active_operations(component: object, plugin_name: str):
    """Return active operation IDs currently owned by one plugin."""
    plugin_name = str(plugin_name or "").strip()
    active_operations = []

    for operation_id, operation in list(
        (getattr(component, "operations", {}) or {}).items()
    ):
        if not isinstance(operation, dict):
            continue

        if str(operation.get("plugin") or "").strip() == plugin_name:
            active_operations.append(str(operation_id))

    return active_operations


def _get_plugin_deployment_reservations(
    component: object,
):
    """Return/create the node-local plugin deployment reservation map."""
    reservations = getattr(
        component,
        "plugin_deployment_reservations",
        None,
    )

    if not isinstance(
        reservations,
        dict,
    ):
        reservations = {}
        component.plugin_deployment_reservations = (
            reservations
        )

    return reservations


def _clear_plugin_deployment_reservation(
    component: object,
    plugin_name: str,
    transfer_id: str,
):
    """Clear one reservation only when its transfer ID still matches."""
    reservations = (
        _get_plugin_deployment_reservations(
            component
        )
    )

    if reservations.get(
        plugin_name
    ) == transfer_id:
        reservations.pop(
            plugin_name,
            None,
        )


async def refreshPluginInventory(component: object):
    """Return plugin directories/manifests/setup health on this Sensor Node."""
    PARAMETERS = {
        "node_uid": component.uuid,
        "node_inventory": await _get_plugin_inventory_with_setup_checks(component),
    }
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "refreshPluginInventoryResults",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    await component.hiprfisr_socket.send_msg(
        fissure.comms.MessageTypes.COMMANDS,
        msg,
    )


async def repairPluginSetup(component: object, plugin_name=""):
    """Run one plugin's setup install hook and verify it on the Sensor Node."""
    plugin_name = str(plugin_name or "").strip()

    active_operations = _plugin_has_active_operations(
        component,
        plugin_name,
    )

    if active_operations:
        success = False
        status = "Blocked"
        message = (
            f"{plugin_name} has active operation"
            f"{'s' if len(active_operations) != 1 else ''}: "
            + ", ".join(active_operations)
        )
        output = ""
    else:
        install_result = await plugin.run_plugin_setup(
            plugin_name,
            "install",
            timeout=900.0,
        )

        install_output = str(
            install_result.get("output")
            or ""
        ).strip()

        if not install_result.get("ok"):
            success = False
            status = "Setup Failed"
            message = str(
                install_result.get("message")
                or "Setup install failed."
            )
            output = install_output
        else:
            check_result = await plugin.run_plugin_setup(
                plugin_name,
                "check",
                timeout=20.0,
            )

            check_output = str(
                check_result.get("output")
                or ""
            ).strip()

            output_parts = []
            if install_output:
                output_parts.append(
                    "INSTALL\n"
                    + install_output
                )
            if check_output:
                output_parts.append(
                    "CHECK\n"
                    + check_output
                )
            output = "\n\n".join(output_parts)

            if check_result.get("status") == "Ready":
                success = True
                status = "Ready"
                message = "Setup completed and verification passed."
            else:
                success = False
                status = str(
                    check_result.get("status")
                    or "Setup Failed"
                )
                message = (
                    "Setup install completed, but verification did not pass. "
                    + str(check_result.get("message") or "")
                ).strip()

    node_inventory = await _get_plugin_inventory_with_setup_checks(component)

    PARAMETERS = {
        "node_uid": component.uuid,
        "plugin_name": plugin_name,
        "success": success,
        "status": status,
        "message": message,
        "output": output,
        "node_inventory": node_inventory,
    }
    msg = {
        fissure.comms.MessageFields.IDENTIFIER: component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME: "repairPluginSetupResults",
        fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    }
    await component.hiprfisr_socket.send_msg(
        fissure.comms.MessageTypes.COMMANDS,
        msg,
    )


async def preparePluginDeployment(
    component: object,
    plugin_name="",
    transfer_id="",
    required_plugins=None,
):
    """
    Approve/reject one remote plugin deployment before HIPRFISR sends bytes.

    Required FISSURE plugins must already be physically deployed on this node.
    """
    plugin_name = str(
        plugin_name
        or ""
    ).strip()

    transfer_id = str(
        transfer_id
        or ""
    ).strip()

    required_plugins = [
        str(required_plugin).strip()
        for required_plugin in (
            required_plugins
            or []
        )
        if str(required_plugin).strip()
    ]

    success = False
    message = ""

    if component.local_remote != "remote":
        message = (
            "Plugin package deployment is only available "
            "for remote Sensor Nodes."
        )

    elif component.network_type != "IP":
        message = (
            "Plugin package deployment requires "
            "an IP Sensor Node."
        )

    else:
        node_inventory = (
            plugin.get_local_plugin_inventory()
        )

        missing_required_plugins = [
            required_plugin
            for required_plugin in required_plugins
            if required_plugin not in node_inventory
        ]

        if missing_required_plugins:
            message = (
                f"{plugin_name} requires plugin"
                f"{'s' if len(missing_required_plugins) != 1 else ''} "
                "that are not deployed on this Sensor Node: "
                + ", ".join(
                    missing_required_plugins
                )
            )

        else:
            active_operations = (
                _plugin_has_active_operations(
                    component,
                    plugin_name,
                )
            )

            if active_operations:
                message = (
                    f"{plugin_name} has active operation"
                    f"{'s' if len(active_operations) != 1 else ''}: "
                    + ", ".join(
                        active_operations
                    )
                )

            else:
                reservations = (
                    _get_plugin_deployment_reservations(
                        component
                    )
                )

                existing_transfer = reservations.get(
                    plugin_name
                )

                if (
                    existing_transfer
                    and existing_transfer != transfer_id
                ):
                    message = (
                        f"{plugin_name} already has "
                        "a deployment in progress."
                    )

                else:
                    try:
                        package_path = (
                            plugin.get_plugin_package_staging_path(
                                plugin_name,
                                transfer_id,
                                create_folder=True,
                            )
                        )

                        if os.path.isfile(
                            package_path
                        ):
                            os.remove(
                                package_path
                            )

                        reservations[
                            plugin_name
                        ] = transfer_id

                        success = True
                        message = (
                            "Sensor Node is ready to receive "
                            f"{plugin_name}."
                        )

                    except Exception as exc:
                        message = str(
                            exc
                        )

    PARAMETERS = {
        "node_uid": component.uuid,
        "plugin_name": plugin_name,
        "transfer_id": transfer_id,
        "success": success,
        "message": message,
    }

    msg = {
        fissure.comms.MessageFields.IDENTIFIER:
            component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME:
            "preparePluginDeploymentResults",
        fissure.comms.MessageFields.PARAMETERS:
            PARAMETERS,
    }

    await component.hiprfisr_socket.send_msg(
        fissure.comms.MessageTypes.COMMANDS,
        msg,
    )


async def cancelPluginDeployment(
    component: object,
    plugin_name="",
    transfer_id="",
):
    """Release one deployment reservation and delete its staged ZIP."""
    plugin_name = str(
        plugin_name
        or ""
    ).strip()
    transfer_id = str(
        transfer_id
        or ""
    ).strip()

    _clear_plugin_deployment_reservation(
        component,
        plugin_name,
        transfer_id,
    )

    try:
        package_path = (
            plugin.get_plugin_package_staging_path(
                plugin_name,
                transfer_id,
                create_folder=False,
            )
        )

        if os.path.isfile(
            package_path
        ):
            os.remove(
                package_path
            )

    except Exception:
        pass


async def finalizePluginDeployment(
    component: object,
    plugin_name="",
    transfer_id="",
):
    """
    Replace one remote Sensor Node plugin and verify/setup its environment.
    """
    plugin_name = str(
        plugin_name
        or ""
    ).strip()
    transfer_id = str(
        transfer_id
        or ""
    ).strip()

    success = False
    status = "Failed"
    message = ""
    output_parts = []

    reservations = (
        _get_plugin_deployment_reservations(
            component
        )
    )

    try:
        if component.local_remote != "remote":
            raise RuntimeError(
                "Plugin package deployment is only available "
                "for remote Sensor Nodes."
            )

        if component.network_type != "IP":
            raise RuntimeError(
                "Plugin package deployment requires "
                "an IP Sensor Node."
            )

        if reservations.get(
            plugin_name
        ) != transfer_id:
            raise RuntimeError(
                "Plugin deployment reservation is no longer valid."
            )

        active_operations = (
            _plugin_has_active_operations(
                component,
                plugin_name,
            )
        )

        if active_operations:
            raise RuntimeError(
                (
                    f"{plugin_name} has active operation"
                    f"{'s' if len(active_operations) != 1 else ''}: "
                    + ", ".join(
                        active_operations
                    )
                )
            )

        deployed = (
            plugin.deploy_staged_plugin_package(
                plugin_name,
                transfer_id,
            )
        )

        deployed_version = str(
            deployed.get(
                "version",
                "",
            )
            or ""
        ).strip()

        setup_present = bool(
            deployed.get(
                "setup_present",
                False,
            )
        )

        if not setup_present:
            success = True
            status = "Ready"
            message = (
                f"{plugin_name}"
                + (
                    f" {deployed_version}"
                    if deployed_version
                    else ""
                )
                + " deployed successfully. "
                "No external setup is required."
            )

        else:
            initial_check = (
                await plugin.run_plugin_setup(
                    plugin_name,
                    "check",
                    timeout=20.0,
                )
            )

            initial_output = str(
                initial_check.get(
                    "output",
                    "",
                )
                or ""
            ).strip()

            if initial_output:
                output_parts.append(
                    "CHECK BEFORE SETUP\n"
                    + initial_output
                )

            if (
                initial_check.get(
                    "status"
                )
                == "Ready"
            ):
                success = True
                status = "Ready"
                message = (
                    f"{plugin_name}"
                    + (
                        f" {deployed_version}"
                        if deployed_version
                        else ""
                    )
                    + " deployed successfully. "
                    "Existing setup is already ready."
                )

            else:
                install_result = (
                    await plugin.run_plugin_setup(
                        plugin_name,
                        "install",
                        timeout=900.0,
                    )
                )

                install_output = str(
                    install_result.get(
                        "output",
                        "",
                    )
                    or ""
                ).strip()

                if install_output:
                    output_parts.append(
                        "INSTALL\n"
                        + install_output
                    )

                if not install_result.get(
                    "ok"
                ):
                    success = False
                    status = "Setup Failed"
                    message = (
                        f"{plugin_name}"
                        + (
                            f" {deployed_version}"
                            if deployed_version
                            else ""
                        )
                        + " files were deployed, but setup failed. "
                        + str(
                            install_result.get(
                                "message",
                                "",
                            )
                            or ""
                        )
                    ).strip()

                else:
                    final_check = (
                        await plugin.run_plugin_setup(
                            plugin_name,
                            "check",
                            timeout=20.0,
                        )
                    )

                    final_output = str(
                        final_check.get(
                            "output",
                            "",
                        )
                        or ""
                    ).strip()

                    if final_output:
                        output_parts.append(
                            "CHECK AFTER SETUP\n"
                            + final_output
                        )

                    if (
                        final_check.get(
                            "status"
                        )
                        == "Ready"
                    ):
                        success = True
                        status = "Ready"
                        message = (
                            f"{plugin_name}"
                            + (
                                f" {deployed_version}"
                                if deployed_version
                                else ""
                            )
                            + " deployed and setup verified."
                        )

                    else:
                        success = False
                        status = str(
                            final_check.get(
                                "status",
                                "Setup Failed",
                            )
                            or "Setup Failed"
                        )
                        message = (
                            f"{plugin_name}"
                            + (
                                f" {deployed_version}"
                                if deployed_version
                                else ""
                            )
                            + " files were deployed, but setup verification failed. "
                            + str(
                                final_check.get(
                                    "message",
                                    "",
                                )
                                or ""
                            )
                        ).strip()

    except Exception as exc:
        success = False
        status = "Failed"
        message = str(
            exc
        )

    finally:
        _clear_plugin_deployment_reservation(
            component,
            plugin_name,
            transfer_id,
        )

        try:
            package_path = (
                plugin.get_plugin_package_staging_path(
                    plugin_name,
                    transfer_id,
                    create_folder=False,
                )
            )

            if os.path.isfile(
                package_path
            ):
                os.remove(
                    package_path
                )

        except Exception:
            pass

    node_inventory = (
        await _get_plugin_inventory_with_setup_checks(
            component
        )
    )

    PARAMETERS = {
        "node_uid": component.uuid,
        "plugin_name": plugin_name,
        "transfer_id": transfer_id,
        "success": success,
        "status": status,
        "message": message,
        "output": "\n\n".join(
            output_parts
        ),
        "node_inventory": node_inventory,
    }
    msg = {
        fissure.comms.MessageFields.IDENTIFIER:
            component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME:
            "finalizePluginDeploymentResults",
        fissure.comms.MessageFields.PARAMETERS:
            PARAMETERS,
    }
    await component.hiprfisr_socket.send_msg(
        fissure.comms.MessageTypes.COMMANDS,
        msg,
    )


async def removeManagedPlugin(
    component: object,
    plugin_name="",
):
    """
    Remove one plugin from this Sensor Node using the managed plugin lifecycle.
    """
    plugin_name = str(
        plugin_name
        or ""
    ).strip()

    success = False
    status = "Failed"
    message = ""
    output = ""

    try:
        if not plugin_name:
            raise RuntimeError(
                "No plugin was selected."
            )

        if plugin_name.casefold() == "base":
            raise RuntimeError(
                "The Base plugin cannot be removed."
            )

        active_operations = (
            _plugin_has_active_operations(
                component,
                plugin_name,
            )
        )

        if active_operations:
            status = "Blocked"

            raise RuntimeError(
                (
                    f"{plugin_name} has active operation"
                    f"{'s' if len(active_operations) != 1 else ''}: "
                    + ", ".join(
                        active_operations
                    )
                )
            )

        inventory = (
            plugin.get_local_plugin_inventory()
        )

        plugin_entry = inventory.get(
            plugin_name
        )

        if not isinstance(
            plugin_entry,
            dict,
        ):
            raise RuntimeError(
                f"Plugin is not deployed: {plugin_name}"
            )

        dependent_plugins = []

        for (
            deployed_plugin_name,
            deployed_plugin_entry,
        ) in inventory.items():
            if (
                deployed_plugin_name == plugin_name
                or not isinstance(
                    deployed_plugin_entry,
                    dict,
                )
            ):
                continue

            required_plugins = [
                str(required_plugin).strip()
                for required_plugin in (
                    deployed_plugin_entry.get(
                        "required_plugins",
                        [],
                    )
                    or []
                )
                if str(required_plugin).strip()
            ]

            if plugin_name in required_plugins:
                dependent_plugins.append(
                    deployed_plugin_name
                )

        if dependent_plugins:
            dependent_plugins.sort(
                key=str.casefold
            )

            status = "Blocked"

            raise RuntimeError(
                (
                    f"{plugin_name} is required by deployed plugin"
                    f"{'s' if len(dependent_plugins) != 1 else ''}: "
                    + ", ".join(
                        dependent_plugins
                    )
                )
            )

        cleanup_supported = bool(
            plugin_entry.get(
                "cleanup_supported",
                False,
            )
        )

        setup_present = bool(
            plugin_entry.get(
                "setup_present",
                False,
            )
        )

        if cleanup_supported:
            if not setup_present:
                raise RuntimeError(
                    (
                        f"{plugin_name} declares cleanup support "
                        "but does not provide setup.py."
                    )
                )

            cleanup_result = (
                await plugin.run_plugin_setup(
                    plugin_name,
                    "cleanup",
                    timeout=300.0,
                )
            )

            output = str(
                cleanup_result.get(
                    "output",
                    "",
                )
                or ""
            ).strip()

            if not cleanup_result.get(
                "ok"
            ):
                status = "Cleanup Failed"

                raise RuntimeError(
                    (
                        f"{plugin_name} cleanup failed. "
                        + str(
                            cleanup_result.get(
                                "message",
                                "",
                            )
                            or ""
                        )
                    ).strip()
                )

        plugin.remove_local_plugin_directory(
            plugin_name
        )

        success = True
        status = "Removed"

        if cleanup_supported:
            message = (
                f"{plugin_name} cleanup completed and "
                "the plugin was removed."
            )
        else:
            message = (
                f"{plugin_name} was removed. "
                "No cleanup was declared."
            )

    except Exception as exc:
        if not message:
            message = str(
                exc
            )

    node_inventory = (
        await _get_plugin_inventory_with_setup_checks(
            component
        )
    )

    PARAMETERS = {
        "node_uid": component.uuid,
        "plugin_name": plugin_name,
        "success": success,
        "status": status,
        "message": message,
        "output": output,
        "node_inventory": node_inventory,
    }

    msg = {
        fissure.comms.MessageFields.IDENTIFIER:
            component.identifier,
        fissure.comms.MessageFields.MESSAGE_NAME:
            "removeManagedPluginResults",
        fissure.comms.MessageFields.PARAMETERS:
            PARAMETERS,
    }

    await component.hiprfisr_socket.send_msg(
        fissure.comms.MessageTypes.COMMANDS,
        msg,
    )
    

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
    tak_context: str,
):
    """Send context-appropriate Plugin Action Names for TAK/Tactical."""
    try:
        action_names = (
            plugin.get_plugin_actions(
                plugin_name,
                component.settings_dict,
                component.logger,
                requester_type=(
                    requester_type
                ),
                node_location=(
                    getattr(
                        component,
                        "local_remote",
                        "",
                    )
                ),
            )
        )

        PARAMETERS = {
            "requester_uid": requester_uid,
            "requester_type": requester_type,
            "node_uid": node_uid,
            "plugin_name": plugin_name,
            "action_names": action_names,
            "tak_context": tak_context,
        }

        msg = {
            fissure.comms.MessageFields.IDENTIFIER:
                component.identifier,
            fissure.comms.MessageFields.MESSAGE_NAME:
                "sendPluginActionNamesTakResults",
            fissure.comms.MessageFields.PARAMETERS:
                PARAMETERS,
        }

        component.logger.debug(
            "Sending action names for "
            f"plugin={plugin_name}, "
            f"requester_type={requester_type}, "
            f"node_location={getattr(component, 'local_remote', '')}: "
            f"{action_names}"
        )

        await component.hiprfisr_socket.send_msg(
            fissure.comms.MessageTypes.COMMANDS,
            msg,
        )

    except Exception as exc:
        component.logger.error(
            "Error sending action names for "
            f"plugin={plugin_name}, requester_uid={requester_uid}: {exc}"
        )

        component.logger.debug(
            traceback.format_exc()
        )


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
    Return plugin/action records matching generic tag and hardware filters.

    Autorun is node-owned execution, so its catalog ignores client.dashboard /
    client.tak restrictions while still honoring node.local / node.remote and
    configured hardware compatibility.
    """
    try:
        include_tags = include_tags or []
        exclude_tags = exclude_tags or []
        action_requester_type = "autorun" if context.startswith("sensor_nodes.autorun") else requester_type

        if scope == "plugin" and plugin_name:
            plugin_names = [plugin_name]
        else:
            plugin_names = plugin.get_local_plugin_names()

        matches = []

        for candidate_plugin in plugin_names:
            plugin_path = os.path.join(fissure.utils.PLUGIN_DIR, candidate_plugin)
            if not os.path.isdir(plugin_path):
                continue

            actions_module = _load_plugin_actions_module(candidate_plugin, component.logger)
            if actions_module is None:
                continue

            action_tags = getattr(actions_module, "ACTION_TAGS", {}) or {}
            action_hardware = getattr(actions_module, "ACTION_HARDWARE", {}) or {}

            available_actions = plugin.get_plugin_actions(
                candidate_plugin,
                component.settings_dict,
                component.logger,
                requester_type=action_requester_type,
                node_location=getattr(component, "local_remote", ""),
            )

            for action_name in available_actions:
                tags = list(action_tags.get(action_name, []) or [])
                if not _action_tags_match(tags, include_tags, exclude_tags):
                    continue

                compatible_hardware = list(action_hardware.get(action_name, []) or [])
                if not _action_hardware_matches(hardware, compatible_hardware):
                    continue

                matches.append(
                    {
                        "plugin": candidate_plugin,
                        "action": action_name,
                        "tags": tags,
                        "hardware": compatible_hardware,
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
            f"queryPluginActions context={context}, scope={scope}, plugin={plugin_name}, "
            f"include_tags={include_tags}, hardware={hardware}, matches={matches}"
        )

        await component.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)

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
    tak_context: str,
) -> None:
    """
    Return an action schema only when the action is allowed for this client/node
    context.
    """
    try:
        component.logger.info(
            f"Fetching schema for {plugin_name}.{action_name} "
            f"(node_uid={node_uid})"
        )

        plugin_path = os.path.join(
            fissure.utils.PLUGIN_DIR,
            plugin_name,
        )

        if not os.path.exists(
            plugin_path
        ):
            component.logger.error(
                f"Plugin path does not exist: {plugin_path}"
            )
            return

        if not plugin.action_is_allowed(
            plugin_name,
            action_name,
            requester_type=(
                requester_type
            ),
            node_location=(
                getattr(
                    component,
                    "local_remote",
                    "",
                )
            ),
            logger=component.logger,
        ):
            component.logger.warning(
                "Rejected action schema request for "
                f"{plugin_name}.{action_name}: "
                f"requester_type={requester_type}, "
                f"node_location={getattr(component, 'local_remote', '')}"
            )
            return

        schema = plugin.get_action_schema(
            plugin_name,
            action_name,
            component.logger,
        )

        if not isinstance(
            schema,
            dict,
        ):
            schema = {
                "params": []
            }

        if (
            "params" not in schema
            or not isinstance(
                schema.get(
                    "params"
                ),
                list,
            )
        ):
            schema["params"] = []

        PARAMETERS = {
            "requester_uid": requester_uid,
            "requester_type": requester_type,
            "plugin_name": plugin_name,
            "action_name": action_name,
            "node_uid": node_uid,
            "schema": schema,
            "tak_context": tak_context,
        }

        msg = {
            fissure.comms.MessageFields.IDENTIFIER:
                component.identifier,
            fissure.comms.MessageFields.MESSAGE_NAME:
                "sendPluginActionParametersResultsTak",
            fissure.comms.MessageFields.PARAMETERS:
                PARAMETERS,
        }

        component.logger.debug(
            f"Sending schema for {plugin_name}.{action_name} "
            f"with {len(schema.get('params', []))} params"
        )

        await component.hiprfisr_socket.send_msg(
            fissure.comms.MessageTypes.COMMANDS,
            msg,
        )

    except Exception as exc:
        component.logger.error(
            f"Error sending schema for {plugin_name}.{action_name}: {exc}"
        )

        component.logger.debug(
            traceback.format_exc()
        )


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
    Return target-classification actions that are also valid for the requesting
    client and current node location.
    """
    try:
        component.logger.info(
            f"Fetching target actions for plugin={plugin_name}, "
            f"target_id={target_id}, "
            f"classifications={classification_candidates}"
        )

        plugin_path = os.path.join(
            fissure.utils.PLUGIN_DIR,
            plugin_name,
        )

        if not os.path.exists(
            plugin_path
        ):
            component.logger.error(
                f"Plugin path does not exist: {plugin_path}"
            )
            return

        action_names = (
            plugin.get_actions_for_classifications(
                plugin_name,
                classification_candidates,
                component.logger,
                requester_type=(
                    requester_type
                ),
                node_location=(
                    getattr(
                        component,
                        "local_remote",
                        "",
                    )
                ),
            )
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
            fissure.comms.MessageFields.IDENTIFIER:
                component.identifier,
            fissure.comms.MessageFields.MESSAGE_NAME:
                "sendPluginActionNamesTakResults",
            fissure.comms.MessageFields.PARAMETERS:
                PARAMETERS,
        }

        component.logger.debug(
            "Sending target action names for "
            f"plugin={plugin_name}, "
            f"requester_type={requester_type}, "
            f"node_location={getattr(component, 'local_remote', '')}: "
            f"{action_names}"
        )

        await component.hiprfisr_socket.send_msg(
            fissure.comms.MessageTypes.COMMANDS,
            msg,
        )

    except Exception as exc:
        component.logger.error(
            "Error sending target actions for "
            f"plugin={plugin_name}, target_id={target_id}: {exc}"
        )

        component.logger.debug(
            traceback.format_exc()
        )


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
    Return a Dashboard action schema only when the action is valid for the
    requesting client and current node location.
    """
    try:
        component.logger.info(
            f"Fetching dashboard schema for {plugin_name}.{action_name} "
            f"(node_uid={node_uid}, context={context})"
        )

        plugin_path = os.path.join(
            fissure.utils.PLUGIN_DIR,
            plugin_name,
        )

        if not os.path.exists(
            plugin_path
        ):
            component.logger.error(
                f"Plugin path does not exist: {plugin_path}"
            )
            return

        if not plugin.action_is_allowed(
            plugin_name,
            action_name,
            requester_type=(
                requester_type
            ),
            node_location=(
                getattr(
                    component,
                    "local_remote",
                    "",
                )
            ),
            logger=component.logger,
        ):
            component.logger.warning(
                "Rejected Dashboard action schema request for "
                f"{plugin_name}.{action_name}: "
                f"requester_type={requester_type}, "
                f"node_location={getattr(component, 'local_remote', '')}"
            )
            return

        schema = plugin.get_action_schema(
            plugin_name,
            action_name,
            component.logger,
        )

        if not isinstance(
            schema,
            dict,
        ):
            schema = {
                "params": []
            }

        if (
            "params" not in schema
            or not isinstance(
                schema.get(
                    "params"
                ),
                list,
            )
        ):
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
            fissure.comms.MessageFields.IDENTIFIER:
                component.identifier,
            fissure.comms.MessageFields.MESSAGE_NAME:
                "queryPluginActionSchemaResults",
            fissure.comms.MessageFields.PARAMETERS:
                PARAMETERS,
        }

        await component.hiprfisr_socket.send_msg(
            fissure.comms.MessageTypes.COMMANDS,
            msg,
        )

    except Exception as exc:
        component.logger.error(
            "Error sending Dashboard schema for "
            f"{plugin_name}.{action_name}: {exc}"
        )

        component.logger.debug(
            traceback.format_exc()
        )


