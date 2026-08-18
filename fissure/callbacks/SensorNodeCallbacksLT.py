import binascii
# import fissure.comms
import fissure.utils
import fissure.utils.hardware
from fissure.utils import plugin
import os
import shutil
import subprocess
import threading
import time
import yaml
from concurrent.futures import ThreadPoolExecutor
import asyncio
import zmq
from typing import List
import json
from fissure.comms import MessageFields, MessageTypes, Identifiers
import re


async def recallInfoMeshtasticLT(component: object, tab_index="", source_id=None):
    """
    Recall default settings from a local yaml file and send only essential fields to HIPRFISR.
    Handles low-throughput mode by sending 'nickname', 'location', and 'notes' together if under a certain size.
    If the total payload exceeds 200 bytes when including 'notes', 'notes' is excluded.
    """
    # Recall Default Settings Saved Locally
    # component.logger.info("Recall Info LT")

    filename = os.path.join(fissure.utils.SENSOR_NODE_DIR, "Sensor_Node_Config", "default.yaml")
    with open(filename) as yaml_library_file:
        settings_dict = yaml.load(yaml_library_file, yaml.FullLoader)

    # print(settings_dict)
    
    # Extract only the essential fields for low-throughput messaging
    essential_fields = {
        'tab_index': tab_index,
        'nickname': settings_dict.get('Sensor Node', {}).get('nickname', ''),
        'location': settings_dict.get('Sensor Node', {}).get('location', ''),
        'notes': settings_dict.get('Sensor Node', {}).get('notes', '')
    }

    # Prepare the payload including the 'notes' field initially
    PARAMETERS = {
        'tab_index': essential_fields['tab_index'],
        'nickname': essential_fields['nickname'],
        'location': essential_fields['location'],
        'notes': essential_fields['notes']
    }

    # Estimate the size of the payload with 'notes' and avoid pre-encoding
    payload_size = len(str(PARAMETERS).encode('utf-8'))

    if payload_size > 200:
        component.logger.warning(f"Payload size exceeds 200 bytes ({payload_size} bytes). Excluding 'notes' field.")
        PARAMETERS.pop('notes', None)
    else:
        pass
        # component.logger.info(f"Payload size within limits: {payload_size} bytes.")

    # Send the payload directly as a dictionary
    response_message = {
        MessageFields.SOURCE: component.assigned_id,
        MessageFields.DESTINATION: source_id,
        MessageFields.MESSAGE_NAME: "recallInfoMeshtasticReturnLT",
        MessageFields.PARAMETERS: PARAMETERS,
    }

    await component.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, response_message)
    # component.logger.info(f"Sent recallInfoMeshtasticReturnLT with payload: {payload}")


async def recallHardwareMeshtasticLT(component: object, source_id=None):
    """
    Recall default settings from a local yaml file and send only essential fields to HIPRFISR.
    Handles low-throughput mode by sending 'nickname', 'location', and 'notes' together if under a certain size.
    If the total payload exceeds 200 bytes when including 'notes', 'notes' is excluded.
    """
    # Recall Default Settings Saved Locally
    component.logger.info("Recall Settings LT")

    filename = os.path.join(fissure.utils.SENSOR_NODE_DIR, "Sensor_Node_Config", "default.yaml")
    with open(filename) as yaml_library_file:
        settings_dict = yaml.load(yaml_library_file, yaml.FullLoader)

    print(settings_dict)
    
    # Prepare the payload
    PARAMETERS = {
        'tsi': settings_dict.get('Sensor Node', {}).get('tsi', ''),
        # 'pd': settings_dict.get('Sensor Node', {}).get('pd', ''),
        # 'attack': settings_dict.get('Sensor Node', {}).get('attack', ''),
        # 'iq': settings_dict.get('Sensor Node', {}).get('iq', ''),
        # 'archive': settings_dict.get('Sensor Node', {}).get('archive', '')
    }

    # Estimate the size of the payload with 'notes' and avoid pre-encoding
    payload_size = len(str(PARAMETERS).encode('utf-8'))

    if payload_size > 200:
        component.logger.warning(f"Payload size exceeds 200 bytes ({payload_size} bytes).")
        # payload.pop('notes', None)
    else:
        component.logger.info(f"Payload size within limits: {payload_size} bytes.")

    # Send the payload directly as a dictionary
    response_message = {
        MessageFields.SOURCE: component.assigned_id,
        MessageFields.DESTINATION: source_id,
        MessageFields.MESSAGE_NAME: "recallHardwareMeshtasticReturnLT",
        MessageFields.PARAMETERS: PARAMETERS,
    }

    await component.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, response_message)
    component.logger.info(f"Sent recallHardwareMeshtasticReturnLT with payload: {PARAMETERS}")


async def recallStatusMeshtasticLT(component: object, tab_index="", source_id=None):
    """
    Recalls sensor node status.
    """
    # Recall Default Settings Saved Locally
    component.logger.info("Recall Status LT")
    
    # Prepare the payload
    PARAMETERS = {
        'tab_index': tab_index,
        'status': "Sensor node online"
    }

    # Send the payload directly as a dictionary
    response_message = {
        MessageFields.SOURCE: component.assigned_id,
        MessageFields.DESTINATION: source_id,
        MessageFields.MESSAGE_NAME: "recallStatusMeshtasticReturnLT",
        MessageFields.PARAMETERS: PARAMETERS,
    }

    await component.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, response_message)
    component.logger.info(f"Sent recallStatusMeshtasticReturnLT with payload: {PARAMETERS}")


async def findGPS_CoordinatesLT(component: object, tab_index=0, gps_source="", format="", source_id=None):
    """
    Find the sensor node GPS coordinates using gpsd and return the information.
    """
    # Retrieve Coordinates
    if gps_source == "gpsd":
        get_coordinates = fissure.utils.hardware.probe_gpsd(component.logger, format, component.gpsd_serial_port, False)
    elif gps_source == "Meshtastic":
        # Use Existing Serial Connection
        if component.local_remote == "remote":
            gps_data = await component.hiprfisr_socket.get_gps_position()

        # Establish Serial Connection
        else:
            gps_data = await fissure.utils.hardware.probeMeshtasticGPS(component.meshtastic_serial_port, 10)

        # Format Data
        if gps_data:
            get_coordinates = fissure.utils.format_coordinates(
                gps_data['latitude'], 
                gps_data['longitude'],
                format
            )
        else:
            component.logger.warning("GPS data unavailable — skipping coordinate formatting.")
            get_coordinates = "GPS unavailable"

    elif gps_source == "Saved":
        get_coordinates = fissure.utils.format_coordinates(
            component.gps_position['latitude'], 
            component.gps_position['longitude'], 
            format
        )
    else:
        get_coordinates = "Invalid GPS Source"

    # Return the Text
    if get_coordinates:
        PARAMETERS = {"tab_index": tab_index, "coordinates": get_coordinates}
        response_message = {
            MessageFields.SOURCE: component.assigned_id,
            MessageFields.DESTINATION: source_id,
            MessageFields.MESSAGE_NAME: "findGPS_CoordinatesResultsLT",
            MessageFields.PARAMETERS: PARAMETERS,
        }

        await component.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, response_message)


async def probeHardwareLT(component: object, tab_index=0, table_row_text=[], source_id=None):
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

    elif get_hardware == "CaribouLite":
        output = await fissure.utils.hardware.probeCaribouLite()
        if not output.startswith("Error:"):
            height_width = [300, 500]

    # Return Text up to a Limit
    print(output)
    if output and len(output) > 10:
        output = output[:10]
        print(output)

    # Return the Text
    PARAMETERS = {"tab_index": tab_index, "output": output, "height_width": height_width}
    msg = {
        MessageFields.SOURCE: component.assigned_id,
        MessageFields.DESTINATION: source_id,
        MessageFields.MESSAGE_NAME: "hardwareProbeResultsLT",
        MessageFields.PARAMETERS: PARAMETERS,
    }
    await component.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def scanHardwareLT(component: object, tab_index=0, hardware_list=[], source_id=None):
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
    PARAMETERS = {"tab_index": tab_index, "hardware_scan_results": all_scan_results}
    msg = {
        MessageFields.SOURCE: component.assigned_id,
        MessageFields.DESTINATION: source_id,
        MessageFields.MESSAGE_NAME: "hardwareScanResultsLT",
        MessageFields.PARAMETERS: PARAMETERS,
    }
    await component.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def guessHardwareLT(component: object, tab_index=0, table_row=[], table_row_text=[], guess_index=0, source_id=None):
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
        scan_results, new_guess_index = fissure.utils.hardware.findCaribouLite()        

    # Return Guess Results
    PARAMETERS = {"results": [tab_index, table_row, get_hardware, scan_results, new_guess_index]}
    msg = {
        MessageFields.SOURCE: component.assigned_id,
        MessageFields.DESTINATION: source_id,
        MessageFields.MESSAGE_NAME: "hardwareGuessResultsLT",
        MessageFields.PARAMETERS: PARAMETERS,
    }
    await component.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)


async def autorunPlaylistExecuteLT(component: object, playlist_filename=""):
    """Start a stored plugin-backed Autorun playlist from a low-bandwidth command."""
    component.logger.info(f"Start Autorun playlist command received: {playlist_filename}")
    await component.start_autorun_playlist_file(
        playlist_filename,
        source=playlist_filename,
    )


async def autorunPlaylistStopLT(component: object):
    """Stop the active plugin-backed Autorun playlist from a low-bandwidth command."""
    component.logger.info("Stop Autorun playlist command received")
    await component.stop_autorun_playlist()


async def gpsBeaconEnableMeshtasticLT(component: object):
    """
    Enables the GPS TAK beacon.
    """
    # Enable
    component.logger.info("Enabling the GPS TAK beacon")
    component.gps_tak_beacon = True


async def gpsBeaconDisableMeshtasticLT(component: object):
    """
    Disables the GPS TAK beacon.
    """
    # Disable
    component.logger.info("Disabling the GPS TAK beacon")
    component.gps_tak_beacon = False


async def rebootMeshtasticLT(component: object):
    """
    Reboots the sensor node computer.
    """
    component.logger.info("Rebooting")
    
    # Reboot
    os.system("sudo reboot")


async def uptimeMeshtasticLT(component: object, source_id=None):
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

    # Return the Text
    PARAMETERS = {
        "uptime": uptime_string
    }
    response_message = {
        MessageFields.SOURCE: component.assigned_id,
        MessageFields.DESTINATION: source_id,
        MessageFields.MESSAGE_NAME: "uptimeMeshtasticReturnLT",
        MessageFields.PARAMETERS: PARAMETERS,
    }

    await component.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, response_message)


async def memoryMeshtasticLT(component: object, source_id=None):
    """
    Retrieves the memory usage of the sensor node computer.
    """
    # Run the command
    output = subprocess.check_output("free -h", shell=True, text=True).splitlines()

    # Parse lines
    # headers = output[0].split()
    memory_list = output[1].split()[1:]  # Skip "Mem:"

    # Return the Text
    PARAMETERS = {
        "memory": memory_list
    }
    response_message = {
        MessageFields.SOURCE: component.assigned_id,
        MessageFields.DESTINATION: source_id,
        MessageFields.MESSAGE_NAME: "memoryMeshtasticReturnLT",
        MessageFields.PARAMETERS: PARAMETERS,
    }

    await component.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, response_message)


async def diskMeshtasticLT(component: object, source_id=None):
    """
    Retrieves the disk usage of the sensor node computer.
    """
    # Get disk usage for root
    result = subprocess.check_output("df -h /", shell=True, text=True)
    lines = result.strip().split('\n')
    headers = lines[0].split()
    values = lines[1].split()

    # Create dictionary
    disk_dict = dict(zip(headers, values))

    # # Make it more readable
    # for key, value in disk_dict.items():
    #     print(f"{key}: {value}")

    # Return the Text
    PARAMETERS = {
        "disk": disk_dict
    }
    response_message = {
        MessageFields.SOURCE: component.assigned_id,
        MessageFields.DESTINATION: source_id,
        MessageFields.MESSAGE_NAME: "diskMeshtasticReturnLT",
        MessageFields.PARAMETERS: PARAMETERS,
    }

    await component.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, response_message)


async def cpuMeshtasticLT(component: object, source_id=None):
    """
    Retrieves the CPU percentage of the sensor node computer.
    """
    # Get CPU Percentage
    cpu_result = subprocess.check_output("top -bn1 | grep 'Cpu(s)' | awk '{print $2 + $4}'", shell=True, text=True).strip()
    cpu_result = f"{cpu_result}%"

    # Return the Text
    PARAMETERS = {
        "cpu": cpu_result
    }
    response_message = {
        MessageFields.SOURCE: component.assigned_id,
        MessageFields.DESTINATION: source_id,
        MessageFields.MESSAGE_NAME: "cpuMeshtasticReturnLT",
        MessageFields.PARAMETERS: PARAMETERS,
    }

    await component.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, response_message)


async def processesMeshtasticLT(component: object, source_id=None):
    """
    Retrieves the processes on the sensor node computer.
    """
    # Get Processes
    processes_result = subprocess.check_output(
        "ps -eo pid,args | grep -i fissure | grep -v grep | awk '{pid=$1; $1=\"\"; split($NF,f,\"/\"); print pid, f[length(f)]}'",
        shell=True,
        text=True
    ).strip()

    # Return the Text
    PARAMETERS = {
        "processes": processes_result
    }
    response_message = {
        MessageFields.SOURCE: component.assigned_id,
        MessageFields.DESTINATION: source_id,
        MessageFields.MESSAGE_NAME: "processesMeshtasticReturnLT",
        MessageFields.PARAMETERS: PARAMETERS,
    }

    await component.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, response_message)


async def ifconfigMeshtasticLT(component: object, source_id=None):
    """
    Retrieves an abbreviated ifconfig output: only physical Ethernet/Wi-Fi interfaces with their IPv4 address or '-'.
    """
    cmd = r"""
    ifconfig | awk '
    /^[a-z]/ {
        iface=$1
        sub(":", "", iface)
        ip="-"
        if (iface ~ /^(br|docker|veth|lo)/) {
            skip=1
        } else if (iface ~ /^(en|eth|wl)/) {
            skip=0
            interfaces[iface] = "-"
        } else {
            skip=1
        }
    }
    /inet / && $2 != "127.0.0.1" && !skip {
        interfaces[iface] = $2
    }
    END {
        for (i in interfaces) print i, interfaces[i]
    }'
    """

    try:
        ifconfig_result = subprocess.check_output(cmd, shell=True, text=True).strip()
    except subprocess.CalledProcessError as e:
        ifconfig_result = f"Error: {e}"

    # Return the Text
    PARAMETERS = {
        "ifconfig": ifconfig_result
    }
    response_message = {
        MessageFields.SOURCE: component.assigned_id,
        MessageFields.DESTINATION: source_id,
        MessageFields.MESSAGE_NAME: "ifconfigMeshtasticReturnLT",
        MessageFields.PARAMETERS: PARAMETERS,
    }

    await component.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, response_message)


async def iwconfigMeshtasticLT(component: object, source_id=None):
    """
    Retrieves the wireless interface name and mode (Managed or Monitor) on the sensor node computer.
    """
    cmd = r"""
    iwconfig 2>/dev/null | awk '
    /^[a-z]/ {iface=$1}
    /Mode:/ {
      for (i = 1; i <= NF; i++) {
        if ($i ~ /^Mode:/) {
          split($i, a, ":")
          print iface, a[2]
        }
      }
    }'
    """

    try:
        iwconfig_result = subprocess.check_output(cmd, shell=True, text=True).strip()
    except subprocess.CalledProcessError as e:
        iwconfig_result = f"Error: {e}"

    # Return the Text
    PARAMETERS = {
        "iwconfig": iwconfig_result
    }
    response_message = {
        MessageFields.SOURCE: component.assigned_id,
        MessageFields.DESTINATION: source_id,
        MessageFields.MESSAGE_NAME: "iwconfigMeshtasticReturnLT",
        MessageFields.PARAMETERS: PARAMETERS,
    }

    await component.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, response_message)


async def completeMeshtasticHandshakeLT(component: object, assigned_id:int, source_id=None, destination_id=None):
    """
    
    """
    # Get Processes
    if destination_id and destination_id == component.uuid:
        component.assigned_id = assigned_id
        component.hiprfisr_socket.assigned_id = assigned_id

        # Increase the heartbeat interval
        component.heartbeat_interval = component.heartbeat_interval_connected


async def nodeSelectLT(component: object, dashboard_node_index, source_id=None):
    """
    Recall default settings from a local yaml file and send to HIPRFISR.
    """
    # # Recall Default Settings Saved Locally
    # component.logger.info("nodeSelectIP/Recall Settings")
    # filename = os.path.join(fissure.utils.SENSOR_NODE_DIR, "Sensor_Node_Config", "default.yaml")
    # with open(filename) as yaml_library_file:
    #     settings_dict = yaml.load(yaml_library_file, yaml.FullLoader)

    # # Send the Message
    # PARAMETERS = {
    #     "dashboard_node_index": dashboard_node_index,
    #     "settings_dict": settings_dict
    # }
    # msg = {
    #     fissure.comms.MessageFields.IDENTIFIER: component.identifier,
    #     fissure.comms.MessageFields.MESSAGE_NAME: "recallSettingsReturnLT",
    #     fissure.comms.MessageFields.PARAMETERS: PARAMETERS,
    # }
    # await component.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, msg)

        # Recall Default Settings Saved Locally
    # component.logger.info("Recall Info LT")

    print("AT node select")
    filename = os.path.join(fissure.utils.SENSOR_NODE_DIR, "Sensor_Node_Config", "default.yaml")
    with open(filename) as yaml_library_file:
        settings_dict = yaml.load(yaml_library_file, yaml.FullLoader)

    # print(settings_dict)
    
    # Extract only the essential fields for low-throughput messaging
    essential_fields = {
        'tab_index': dashboard_node_index,
        'nickname': settings_dict.get('Sensor Node', {}).get('nickname', ''),
        'location': settings_dict.get('Sensor Node', {}).get('location', ''),
        'notes': settings_dict.get('Sensor Node', {}).get('notes', '')
    }

    # Prepare the payload including the 'notes' field initially
    PARAMETERS = {
        'tab_index': essential_fields['tab_index'],
        'nickname': essential_fields['nickname'],
        'location': essential_fields['location'],
        'notes': essential_fields['notes']
    }

    # Estimate the size of the payload with 'notes' and avoid pre-encoding
    payload_size = len(str(PARAMETERS).encode('utf-8'))

    if payload_size > 200:
        component.logger.warning(f"Payload size exceeds 200 bytes ({payload_size} bytes). Excluding 'notes' field.")
        PARAMETERS.pop('notes', None)
    else:
        pass
        # component.logger.info(f"Payload size within limits: {payload_size} bytes.")

    # Send the payload directly as a dictionary
    response_message = {
        MessageFields.SOURCE: component.assigned_id,
        MessageFields.DESTINATION: source_id,
        MessageFields.MESSAGE_NAME: "recallInfoMeshtasticReturnLT",
        MessageFields.PARAMETERS: PARAMETERS,
    }

    await component.hiprfisr_socket.send_msg(fissure.comms.MessageTypes.COMMANDS, response_message)
    # component.logger.info(f"Sent recallInfoMeshtasticReturnLT with payload: {payload}")
