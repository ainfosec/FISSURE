import subprocess
import time
import logging
from gps import gps, WATCH_ENABLE, WATCH_DEVICE, WATCH_JSON
from fissure.utils import format_coordinates, get_library_version
import asyncio
import meshtastic
from meshtastic.serial_interface import SerialInterface
from typing import Optional, Dict
import socket
import os
import select
import json
import re
import aiohttp


SUPPORTED_HARDWARE = [
    "Computer",
    "USRP X3x0",
    "USRP B2x0",
    "HackRF",
    "RTL2832U",
    "802.11x Adapter",
    "USRP B20xmini",
    "LimeSDR",
    "bladeRF",
    "Open Sniffer",
    "PlutoSDR",
    "USRP2",
    "USRP N2xx",
    "bladeRF 2.0",
    "USRP X410",
    "RSPduo",
    "RSPdx",
    "RSPdx R2",
    "CaribouLite"
]
    

def hardwareID_Column(hardware_type):
    """
    Returns the column in the Sensor Node Configuration Scan Results table that is used as the hardware ID.
        0: Type
        1: UID
        2: Radio Name
        3: Serial
        4: Network Interface
        5: IP Address
        6: Daughterboard
    """
    # Return ID Column Based on Hardware Type
    if hardware_type == "Computer":
        hardware_id = None
    elif hardware_type == "USRP X3x0":
        hardware_id = 5
    elif hardware_type == "USRP B2x0":
        hardware_id = 3
    elif hardware_type == "HackRF":
        hardware_id = 3
    elif hardware_type == "RTL2832U":
        hardware_id = 3
    elif hardware_type == "802.11x Adapter":
        hardware_id = 4
    elif hardware_type == "USRP B20xmini":
        hardware_id = 3
    elif hardware_type == "LimeSDR":
        hardware_id = 3
    elif hardware_type == "bladeRF":
        hardware_id = 3
    elif hardware_type == "Open Sniffer":
        hardware_id = None
    elif hardware_type == "PlutoSDR":
        hardware_id = 5
    elif hardware_type == "USRP2":
        hardware_id = 5
    elif hardware_type == "USRP N2xx":
        hardware_id = 5
    elif hardware_type == "bladeRF 2.0":
        hardware_id = 3
    elif hardware_type == "USRP X410":
        hardware_id = 5
    elif hardware_type == "RSPduo":
        hardware_id = 3
    elif hardware_type == "RSPdx":
        hardware_id = 3
    elif hardware_type == "RSPdx R2":
        hardware_id = 3
    elif hardware_type == "CaribouLite":
        hardware_id = 1
    else:
        hardware_id = None

    return hardware_id


def hardwareDisplayName(dashboard, hardware_type, sensor_node, component, index):
    """Returns a display name for comboboxes based on provided sensor node hardware information."""
    # Return Display Name Based on Type
    get_hardware_name = ""
    get_column = hardwareID_Column(hardware_type)

    if hardware_type == "Computer":
        get_hardware_name = hardware_type
    elif hardware_type == "USRP X3x0":
        get_hardware_name = hardware_type + " - " + dashboard.backend.settings[sensor_node][component][index][get_column]
    elif hardware_type == "USRP B2x0":
        get_hardware_name = hardware_type + " - " + dashboard.backend.settings[sensor_node][component][index][get_column]
    elif hardware_type == "HackRF":
        get_hardware_name = hardware_type + " - " + dashboard.backend.settings[sensor_node][component][index][get_column]
    elif hardware_type == "RTL2832U":
        get_hardware_name = hardware_type + " - " + dashboard.backend.settings[sensor_node][component][index][get_column]
    elif hardware_type == "802.11x Adapter":
        get_hardware_name = hardware_type + " - " + dashboard.backend.settings[sensor_node][component][index][get_column]
    elif hardware_type == "USRP B20xmini":
        get_hardware_name = hardware_type + " - " + dashboard.backend.settings[sensor_node][component][index][get_column]
    elif hardware_type == "LimeSDR":
        get_hardware_name = hardware_type + " - " + dashboard.backend.settings[sensor_node][component][index][get_column]
    elif hardware_type == "bladeRF":
        get_hardware_name = hardware_type + " - " + dashboard.backend.settings[sensor_node][component][index][get_column]
    elif hardware_type == "Open Sniffer":
        get_hardware_name = hardware_type
    elif hardware_type == "PlutoSDR":
        get_hardware_name = hardware_type + " - " + dashboard.backend.settings[sensor_node][component][index][get_column]
    elif hardware_type == "USRP2":
        get_hardware_name = hardware_type + " - " + dashboard.backend.settings[sensor_node][component][index][get_column]
    elif hardware_type == "USRP N2xx":
        get_hardware_name = hardware_type + " - " + dashboard.backend.settings[sensor_node][component][index][get_column]
    elif hardware_type == "bladeRF 2.0":
        get_hardware_name = hardware_type + " - " + dashboard.backend.settings[sensor_node][component][index][get_column]
    elif hardware_type == "USRP X410":
        get_hardware_name = hardware_type + " - " + dashboard.backend.settings[sensor_node][component][index][get_column]
    elif hardware_type == "RSPduo":
        get_hardware_name = hardware_type + " - " + dashboard.backend.settings[sensor_node][component][index][get_column]
    elif hardware_type == "RSPdx":
        get_hardware_name = hardware_type + " - " + dashboard.backend.settings[sensor_node][component][index][get_column]        
    elif hardware_type == "RSPdx R2":
        get_hardware_name = hardware_type + " - " + dashboard.backend.settings[sensor_node][component][index][get_column]
    elif hardware_type == "CaribouLite":
        get_hardware_name = hardware_type + " - " + dashboard.backend.settings[sensor_node][component][index][get_column]        
    else:
        get_hardware_name = "UNKNOWN HARDWARE"

    return get_hardware_name


def hardwareDisplayNameLookup(dashboard, display_name, component):
    """
    Takes in a hardware display name and returns all the selected sensor node
    hardware information.

    Returns:
        [type, uid, radio_name, serial, interface, ip, daughterboard]
    """
    blank = ["", "", "", "", "", "", ""]

    if not display_name:
        return blank

    display_name = str(display_name).strip()

    if display_name == "Computer":
        return ["Computer", "", "", "", "", "", ""]

    if display_name == "Open Sniffer":
        return ["Open Sniffer", "", "", "", "", "", ""]

    parts = display_name.split(" - ", 1)
    hardware_type = parts[0].strip()

    try:
        second_value = parts[1].strip()
    except Exception:
        second_value = ""

    if not hardware_type:
        return blank

    hardware_settings = _get_selected_node_hardware_settings(dashboard)
    sections = _get_hardware_sections_for_component(component)

    for section in sections:
        entries = hardware_settings.get(section, {}) or {}

        if not isinstance(entries, dict):
            continue

        for uid, entry in entries.items():
            values = _hardware_entry_to_values(uid, entry, section)

            ret_type = values[0]
            ret_uid = values[1]
            ret_radio_name = values[2]
            ret_serial = values[3]
            ret_interface = values[4]
            ret_ip = values[5]
            ret_daughterboard = values[6]

            if ret_type != hardware_type:
                continue

            # Exact display-name match is the safest check.
            if hardwareDisplayNameFromValues(values) == display_name:
                return values

            # Fallback for legacy/odd display strings.
            candidate_values = [
                ret_uid,
                f"UID {ret_uid}" if ret_uid else "",
                ret_radio_name,
                ret_serial,
                ret_interface,
                ret_ip,
                ret_daughterboard,
            ]

            if second_value and second_value in candidate_values:
                return values

    return blank
        

def checkFrequencyBounds(get_frequency, get_hardware, get_daughterboard):
    """ Returns True or False if the frequency is within the bounds of the hardware. Move to utils?
    """
    if get_hardware == "Computer":
        # Frequency Limits
        if (get_frequency >= 1) and (get_frequency <= 6000):
            return True

    elif get_hardware == "USRP X3x0":
        # Frequency Limits
        if get_daughterboard == "CBX-120":
            if (get_frequency >= 1200) and (get_frequency <= 6000):
                return True
        elif get_daughterboard == "SBX-120":
            if (get_frequency >= 400) and (get_frequency <= 4400):
                return True
        elif get_daughterboard == "UBX-160":
            if (get_frequency >= 10) and (get_frequency <= 6000):
                return True
        elif get_daughterboard == "WBX-120":
            if (get_frequency >= 25) and (get_frequency <= 2200):
                return True
        elif get_daughterboard == "TwinRX":
            if (get_frequency >= 10) and (get_frequency <= 6000):
                return True

    elif get_hardware == "USRP B2x0":
        # Frequency Limits
        if (get_frequency >= 70) and (get_frequency <= 6000):
            return True

    elif get_hardware == "HackRF":
        # Frequency Limits
        if (get_frequency >= 1) and (get_frequency <= 6000):
            return True

    elif get_hardware == "RTL2832U":
        # Frequency Limits
        if (get_frequency >= 64) and (get_frequency <= 1700):
            return True

    elif get_hardware == "802.11x Adapter":
        # Frequency Limits
        if (get_frequency >= 1) and (get_frequency <= 6000):
            return True

    elif get_hardware == "USRP B20xmini":
        # Frequency Limits
        if (get_frequency >= 70) and (get_frequency <= 6000):
            return True

    elif get_hardware == "LimeSDR":
        # Frequency Limits
        if (get_frequency >= 1) and (get_frequency <= 3800):
            return True

    elif get_hardware == "bladeRF":
        # Frequency Limits
        if (get_frequency >= 280) and (get_frequency <= 3800):
            return True

    elif get_hardware == "Open Sniffer":
        # Frequency Limits
        if (get_frequency >= 1) and (get_frequency <= 6000):
            return True

    elif get_hardware == "PlutoSDR":
        # Frequency Limits
        if (get_frequency >= 325) and (get_frequency <= 3800):
            return True

    elif get_hardware == "USRP2":
        # Frequency Limits
        if get_daughterboard == "XCVR2450":
            if (get_frequency >= 2400) and (get_frequency <= 6000):
                return True
        elif get_daughterboard == "DBSRX":
            if (get_frequency >= 800) and (get_frequency <= 2300):
                return True
        elif get_daughterboard == "SBX-40":
            if (get_frequency >= 400) and (get_frequency <= 4400):
                return True
        elif get_daughterboard == "UBX-40":
            if (get_frequency >= 10) and (get_frequency <= 6000):
                return True
        elif get_daughterboard == "WBX-40":
            if (get_frequency >= 50) and (get_frequency <= 2200):
                return True
        elif get_daughterboard == "CBX-40":
            if (get_frequency >= 1200) and (get_frequency <= 6000):
                return True
        elif get_daughterboard == "LFRX":
            if (get_frequency >= 0) and (get_frequency <= 30):
                return True
        elif get_daughterboard == "LFTX":
            if (get_frequency >= 0) and (get_frequency <= 30):
                return True
        elif get_daughterboard == "BasicRX":
            if (get_frequency >= 1) and (get_frequency <= 250):
                return True
        elif get_daughterboard == "BasicTX":
            if (get_frequency >= 1) and (get_frequency <= 250):
                return True
        elif get_daughterboard == "TVRX2":
            if (get_frequency >= 50) and (get_frequency <= 860):
                return True
        elif get_daughterboard == "RFX400":
            if (get_frequency >= 400) and (get_frequency <= 500):
                return True
        elif get_daughterboard == "RFX900":
            if (get_frequency >= 750) and (get_frequency <= 1050):
                return True
        elif get_daughterboard == "RFX1200":
            if (get_frequency >= 1150) and (get_frequency <= 1450):
                return True
        elif get_daughterboard == "RFX1800":
            if (get_frequency >= 1500) and (get_frequency <= 2100):
                return True
        elif get_daughterboard == "RFX2400":
            if (get_frequency >= 2300) and (get_frequency <= 2900):
                return True

    elif get_hardware == "USRP N2xx":
        # Frequency Limits
        if get_daughterboard == "XCVR2450":
            if (get_frequency >= 2400) and (get_frequency <= 6000):
                return True
        elif get_daughterboard == "DBSRX":
            if (get_frequency >= 800) and (get_frequency <= 2300):
                return True
        elif get_daughterboard == "SBX-40":
            if (get_frequency >= 400) and (get_frequency <= 4400):
                return True
        elif get_daughterboard == "UBX-40":
            if (get_frequency >= 10) and (get_frequency <= 6000):
                return True
        elif get_daughterboard == "WBX-40":
            if (get_frequency >= 50) and (get_frequency <= 2200):
                return True
        elif get_daughterboard == "CBX-40":
            if (get_frequency >= 1200) and (get_frequency <= 6000):
                return True
        elif get_daughterboard == "LFRX":
            if (get_frequency >= 0) and (get_frequency <= 30):
                return True
        elif get_daughterboard == "LFTX":
            if (get_frequency >= 0) and (get_frequency <= 30):
                return True
        elif get_daughterboard == "BasicRX":
            if (get_frequency >= 1) and (get_frequency <= 250):
                return True
        elif get_daughterboard == "BasicTX":
            if (get_frequency >= 1) and (get_frequency <= 250):
                return True
        elif get_daughterboard == "TVRX2":
            if (get_frequency >= 50) and (get_frequency <= 860):
                return True
        elif get_daughterboard == "RFX400":
            if (get_frequency >= 400) and (get_frequency <= 500):
                return True
        elif get_daughterboard == "RFX900":
            if (get_frequency >= 750) and (get_frequency <= 1050):
                return True
        elif get_daughterboard == "RFX1200":
            if (get_frequency >= 1150) and (get_frequency <= 1450):
                return True
        elif get_daughterboard == "RFX1800":
            if (get_frequency >= 1500) and (get_frequency <= 2100):
                return True
        elif get_daughterboard == "RFX2400":
            if (get_frequency >= 2300) and (get_frequency <= 2900):
                return True

    elif get_hardware == "bladeRF 2.0":
        # Frequency Limits
        if (get_frequency >= 70) and (get_frequency <= 6000):  # Soapy blocks don't work below 70 MHz
            return True

    elif get_hardware == "USRP X410":
        # Frequency Limits
        if get_daughterboard == "ZBX":
            if (get_frequency >= 1) and (get_frequency <= 7200):
                return True

    elif get_hardware == "RSPduo":
        # Frequency Limits
        if (get_frequency >= 0.001) and (get_frequency <= 2000):
            return True
        
    elif get_hardware == "RSPdx":
        # Frequency Limits
        if (get_frequency >= 0.001) and (get_frequency <= 2000):
            return True
        
    elif get_hardware == "RSPdx R2":
        # Frequency Limits
        if (get_frequency >= 0.001) and (get_frequency <= 2000):
            return True
        
    elif get_hardware == "CaribouLite":
        # Frequency Limits
        if (get_frequency >= 30) and (get_frequency <= 6000):
            return True

    # Not in Bounds
    return False


def find80211x(guess_network_interface="", guess_index=0):
    """ 
    Parses the results of 'iwconfig' and sets the 802.11x Adapter interface for an edit box.
    """
        # Scan Results
    scan_results = ['802.11x Adapter','','','','','','']  # Type, UID, Radio Name, Serial, Net. Interface, IP Address, Daughterboard
    
    # Get the Text
    proc = subprocess.Popen("iwconfig", shell=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    output = proc.communicate()[0].decode()

    # Reset Interface Index
    if not guess_network_interface:
        guess_index = 0
    else:
        guess_index += 1

    # Pull the Interfaces
    lines = output.split('\n')
    wifi_interfaces = []
    
    current_iface = None
    for line in lines:
        if line.strip() == "":  # Ignore empty lines
            continue
        
        # Look for interface names (they are the first word in a line)
        if not line.startswith(" "):
            current_iface = line.split()[0]  # Extract interface name
        
        # Add to list if it's a Wi-Fi interface
        if current_iface and ('ESSID' in line or 'Mode:Monitor' in line):
            wifi_interfaces.append(current_iface)
            current_iface = None  # Avoid duplicate entries

    # Found an Interface
    if wifi_interfaces:
        # Check Interface Index
        if guess_index >= len(wifi_interfaces):
            guess_index = 0

        # Update the Edit Box
        scan_results[4] = wifi_interfaces[guess_index]
        
    return scan_results, guess_index


def findB205mini(guess_serial=""):
    """ 
    Parses the results of 'uhd_find_devices' and sets the B205mini serial for an edit box.
    """
    # Scan Results
    scan_results = ['USRP B20xmini','','','','','','']  # Type, UID, Radio Name, Serial, Net. Interface, IP Address, Daughterboard
    
    # Get the Text
    proc = subprocess.Popen("uhd_find_devices &", shell=True, stdout=subprocess.PIPE, )
    output = proc.communicate()[0].decode()

    # Get the Variables and Values
    device_index = -1
    device_dict = {}
    record_values = False
    for line in output.splitlines():
        if len(line.strip()) == 0:
            record_values = False
        if record_values == True:
            get_var = line.split(':')[0].strip(' ')
            get_val = line.split(':')[1].strip(' ')
            device_dict[device_index].append((get_var,get_val))
        if "Device Address" in line:
            device_index = device_index + 1
            device_dict.update({device_index:[]})
            record_values = True

    # Find B205i
    for n in range(0,len(device_dict)):
        for nn in device_dict[n]:
            if ('B205i' in nn) or ('B200i' in nn):
                # Update Dashboard
                for m in device_dict[n]:
                    if m[0] == 'serial':
                        scan_results[3] = m[1]
                        
    return scan_results


def findB2x0(guess_serial=""):
    """ 
    Parses the results of 'uhd_find_devices' for hardware information.
    """
    # Scan Results
    scan_results = ['USRP B2x0','','','','','','']  # Type, UID, Radio Name, Serial, Net. Interface, IP Address, Daughterboard
    
    # Get the Text
    proc = subprocess.Popen("uhd_find_devices &", shell=True, stdout=subprocess.PIPE, )
    output = proc.communicate()[0].decode()

    # Get the Variables and Values
    device_index = -1
    device_dict = {}
    record_values = False
    for line in output.splitlines():
        if len(line.strip()) == 0:
            record_values = False
        if record_values == True:
            get_var = line.split(':')[0].strip(' ')
            get_val = line.split(':')[1].strip(' ')
            device_dict[device_index].append((get_var,get_val))
        if "Device Address" in line:
            device_index = device_index + 1
            device_dict.update({device_index:[]})
            record_values = True

    # Find B210
    for n in range(0,len(device_dict)):
        for nn in device_dict[n]:
            if ('B210' in nn) or ('B200' in nn):
                # Update Dashboard
                for m in device_dict[n]:
                    if m[0] == 'serial':
                        scan_results[3] = m[1]
    
    return scan_results


def findHackRF(guess_serial="", guess_index=0):
    """ 
    Parses the results of 'hackrf_info' and sets the HackRF serial for an edit box.
    """
    # Scan Results
    scan_results = ['HackRF','','','','','','']  # Type, UID, Radio Name, Serial, Net. Interface, IP Address, Daughterboard
    
    # Get the Text
    proc = subprocess.Popen("hackrf_info &", shell=True, stdout=subprocess.PIPE, )
    output = proc.communicate()[0].decode()

    # Reset Guess Index
    get_text = guess_serial  #str(widget_serial.toPlainText())
    if len(get_text) == 0:
        guess_index = 0
    else:
        guess_index = guess_index + 1

    # Get the Variables and Values
    device_index = -1
    device_dict = {}
    for line in output.splitlines():
        if "Serial number" in line:
            device_index = device_index + 1
            device_dict.update({device_index:[]})
            get_var = line.split(':')[0].strip(' ')
            get_val = line.split(':')[1].strip(' ').lstrip('0')
            device_dict[device_index].append((get_var,get_val))

    # Check Interface Index
    if guess_index > (len(device_dict)-1):
        guess_index = 0

    # Update GUI
    try:
        m = device_dict[guess_index][0]
        if m[0] == 'Serial number':
            scan_results[3] = m[1]
    except:
        pass
        
    return scan_results, guess_index


def findLimeSDR():
    """  
    Parses the results of 'LimeUtil --find' and sets the serial number for an edit box.
    """
    # Scan Results
    scan_results = ['LimeSDR','','','','','','']  # Type, UID, Radio Name, Serial, Net. Interface, IP Address, Daughterboard
    
    # Get the Text
    proc = subprocess.Popen("LimeUtil --find &", shell=True, stdout=subprocess.PIPE, )
    output = proc.communicate()[0].decode()

    # Extract the Serial
    get_serial = output[output.find('serial=')+7:output.rfind(']')]

    # Update the Edit Box
    scan_results[3] = get_serial
    
    return scan_results


def findPlutoSDR(guess_index=0):
    """ 
    Parses the results of 'avahi-browse' and copies an IP address for the PlutoSDR into an edit box.
    """
    # Scan Results
    scan_results = ['PlutoSDR','','','','','','']  # Type, UID, Radio Name, Serial, Net. Interface, IP Address, Daughterboard
    
    # Get the Text
    proc = subprocess.Popen("avahi-browse -d local _ssh._tcp --resolve -t &", shell=True, stdout=subprocess.PIPE, )
    output = proc.communicate()[0].decode()

    # Reset Guess Index
    get_text = ""  #str(widget_ip.toPlainText())
    if len(get_text) == 0:
        guess_index = 0
    else:
        guess_index = guess_index + 1

    # Get the Variables and Values
    device_index = -1
    device_dict = {}
    device_found = False
    for line in output.splitlines():

        # address = [192.168.#.#] Line
        if device_found == True:
            device_index = device_index + 1
            device_dict.update({device_index:[]})
            get_var = line.split('=')[0].strip(' ')
            get_val = line.split('=')[1].strip(' []')
            device_dict[device_index].append((get_var,get_val))
            device_found = False

        # hostname = [pluto.local] Line
        if "hostname = [pluto" in line:
            device_found = True

    # Check Interface Index
    if guess_index > (len(device_dict)-1):
        guess_index = 0

    # Update GUI
    try:
        m = device_dict[guess_index][0]
        if m[0] == 'address':
            scan_results[5] = m[1]
    except:
        pass
        
    return scan_results, guess_index


def findUSRP2(guess_ip=""):
    """ 
    Parses the results of 'uhd_find_devices' and sets the USRP2 IP and serial for two edit boxes.
    """
    # Scan Results
    scan_results = ['USRP2','','','','','','']  # Type, UID, Radio Name, Serial, Net. Interface, IP Address, Daughterboard
    
    # Get the Text
    proc = subprocess.Popen("uhd_find_devices &", shell=True, stdout=subprocess.PIPE, )
    output = proc.communicate()[0].decode()

    # Get the Variables and Values
    device_index = -1
    device_dict = {}
    record_values = False
    for line in output.splitlines():
        if len(line.strip()) == 0:
            record_values = False
        if record_values == True:
            get_var = line.split(':')[0].strip(' ')
            get_val = line.split(':')[1].strip(' ')
            device_dict[device_index].append((get_var,get_val))
        if "Device Address" in line:
            device_index = device_index + 1
            device_dict.update({device_index:[]})
            record_values = True

    # Find USRP2
    for n in range(0,len(device_dict)):
        for nn in device_dict[n]:
            if 'usrp2' in nn:
                # Update Dashboard
                for m in device_dict[n]:
                    if m[0] == 'addr':
                        scan_results[5] = m[1]
                    if m[0] == 'serial':
                        scan_results[3] = m[1]

    # Find Daughterboard
    try:
        # Probe
        get_ip = scan_results[5]
        #widget_probing_label.setVisible(True)
        #QtWidgets.QApplication.processEvents()
        proc = subprocess.Popen('uhd_usrp_probe --args="addr=' + get_ip + '" &', shell=True, stdout=subprocess.PIPE, )
        output = str(proc.communicate()[0].decode())
        #widget_probing_label.setVisible(False)

        if "XCVR2450" in output:
            scan_results[6] = "XCVR2450"
        elif "DBSRX" in output:
            scan_results[6] = "DBSRX"
        elif "SBX-40" in output:
            scan_results[6] = "SBX-40"
        elif "UBX-40" in output:
            scan_results[6] = "UBX-40"
        elif "WBX-40" in output:
            scan_results[6] = "WBX-40"
        elif "CBX-40" in output:
            scan_results[6] = "CBX-40"
        elif "LFRX" in output:
            scan_results[6] = "LFRX"
        elif "LFTX" in output:
            scan_results[6] = "LFTX"
        elif "BasicRX" in output:
            scan_results[6] = "BasicRX"
        elif "BasicTX" in output:
            scan_results[6] = "BasicTX"
        elif "TVRX2" in output:
            scan_results[6] = "TVRX2"
        elif "RFX400" in output:
            scan_results[6] = "RFX400"
        elif "RFX900" in output:
            scan_results[6] = "RFX900"
        elif "RFX1200" in output:
            scan_results[6] = "RFX1200"
        elif "RFX1800" in output:
            scan_results[6] = "RFX1800"
        elif "RFX2400" in output:
            scan_results[6] = "RFX2400"
    except:
        pass
        #widget_probing_label.setVisible(False)
        
    return scan_results


def findUSRP_N2xx(guess_ip=""):
    """ 
    Parses the results of 'uhd_find_devices' and sets the USRP N2xx IP and serial for two edit boxes.
    """
    # Scan Results
    scan_results = ['USRP N2xx','','','','','','']  # Type, UID, Radio Name, Serial, Net. Interface, IP Address, Daughterboard
    
    # Get the Text
    proc = subprocess.Popen("uhd_find_devices &", shell=True, stdout=subprocess.PIPE, )
    output = proc.communicate()[0].decode()

    # Get the Variables and Values
    device_index = -1
    device_dict = {}
    record_values = False
    for line in output.splitlines():
        if len(line.strip()) == 0:
            record_values = False
        if record_values == True:
            get_var = line.split(':')[0].strip(' ')
            get_val = line.split(':')[1].strip(' ')
            device_dict[device_index].append((get_var,get_val))
        if "Device Address" in line:
            device_index = device_index + 1
            device_dict.update({device_index:[]})
            record_values = True

    # Find USRP N2xx
    for n in range(0,len(device_dict)):
        for nn in device_dict[n]:
            if 'usrp2' in nn:  # Confirm this string
                # Update Dashboard
                for m in device_dict[n]:
                    if m[0] == 'addr':
                        scan_results[5] = m[1]
                    if m[0] == 'serial':
                        scan_results[3] = m[1]

    # Find Daughterboard
    try:
        # Probe
        get_ip = scan_results[5]  # str(widget_ip.toPlainText())
        #widget_probing_label.setVisible(True)
        #QtWidgets.QApplication.processEvents()
        proc = subprocess.Popen('uhd_usrp_probe --args="addr=' + get_ip + '" &', shell=True, stdout=subprocess.PIPE, )
        output = str(proc.communicate()[0].decode())
        #widget_probing_label.setVisible(False)

        if "XCVR2450" in output:
            scan_results[6] = "XCVR2450"
        elif "DBSRX" in output:
            scan_results[6] = "DBSRX"
        elif "SBX-40" in output:
            scan_results[6] = "SBX-40"
        elif "UBX-40" in output:
            scan_results[6] = "UBX-40"
        elif "WBX-40" in output:
            scan_results[6] = "WBX-40"
        elif "CBX-40" in output:
            scan_results[6] = "CBX-40"
        elif "LFRX" in output:
            scan_results[6] = "LFRX"
        elif "LFTX" in output:
            scan_results[6] = "LFTX"
        elif "BasicRX" in output:
            scan_results[6] = "BasicRX"
        elif "BasicTX" in output:
            scan_results[6] = "BasicTX"
        elif "TVRX2" in output:
            scan_results[6] = "TVRX2"
        elif "RFX400" in output:
            scan_results[6] = "RFX400"
        elif "RFX900" in output:
            scan_results[6] = "RFX900"
        elif "RFX1200" in output:
            scan_results[6] = "RFX1200"
        elif "RFX1800" in output:
            scan_results[6] = "RFX1800"
        elif "RFX2400" in output:
            scan_results[6] = "RFX2400"
    except:
        pass
        #widget_probing_label.setVisible(False)
        
    return scan_results


def findX310(guess_index=0):
    """ 
    Parses the results of 'uhd_find_devices' and sets the X310 IP and serial for two edit boxes.
    """
    # Scan Results
    scan_results = ['USRP X3x0','','','','','','']  # Type, UID, Radio Name, Serial, Net. Interface, IP Address, Daughterboard
    
    # Get the Text
    proc = subprocess.Popen("uhd_find_devices &", shell=True, stdout=subprocess.PIPE, )
    output = proc.communicate()[0].decode()

    # Get the Variables and Values
    device_index = -1
    device_dict = {}
    record_values = False
    for line in output.splitlines():
        if len(line.strip()) == 0:
            record_values = False
        if record_values == True:
            get_var = line.split(':')[0].strip(' ')
            get_val = line.split(':')[1].strip(' ')
            device_dict[device_index].append((get_var,get_val))
        if "Device Address" in line:
            device_index = device_index + 1
            device_dict.update({device_index:[]})
            record_values = True

    # Find X310
    for n in range(0,len(device_dict)):
        for nn in device_dict[n]:
            if 'X310' or 'X300' in nn:
                # Update Dashboard
                for m in device_dict[n]:
                    if m[0] == 'addr':
                        scan_results[5] = m[1]
                    if m[0] == 'serial':
                        scan_results[3] = m[1]

    # Find Daughterboard
    try:
        # Probe
        #get_ip = str(widget_ip.toPlainText())
        # widget_probing_label.setVisible(True)
        # QtWidgets.QApplication.processEvents()
        proc = subprocess.Popen('uhd_usrp_probe --args="addr=' + scan_results[5] + '" &', shell=True, stdout=subprocess.PIPE, )
        output = str(proc.communicate()[0].decode())

        if ("CBX-120" in output) and (guess_index != 0):
            scan_results[6] = "CBX-120"
            guess_index = 0
        elif ("SBX-120" in output) and (guess_index != 1):
            scan_results[6] = "SBX-120"
            guess_index = 1
        elif ("UBX-160" in output) and (guess_index != 2):
            scan_results[6] = "UBX-160"
            guess_index = 2
        elif ("WBX-120" in output) and (guess_index != 3):
            scan_results[6] = "WBX-120"
            guess_index = 3
        elif ("TwinRX" in output) and (guess_index != 4):
            scan_results[6] = "TwinRX"
            guess_index = 4
    except:
        pass
        
    return scan_results, guess_index
    

def findX410(guess_ip=""):
    """ 
    Parses the results of 'uhd_find_devices' and sets the X410 IP and serial for two edit boxes.
    """
    # Scan Results
    scan_results = ['USRP X410','','','','','','']  # Type, UID, Radio Name, Serial, Net. Interface, IP Address, Daughterboard
    
    # Get the Text
    proc = subprocess.Popen("uhd_find_devices &", shell=True, stdout=subprocess.PIPE, )
    output = proc.communicate()[0].decode()

    # Get the Variables and Values
    device_index = -1
    device_dict = {}
    record_values = False
    for line in output.splitlines():
        if len(line.strip()) == 0:
            record_values = False
        if record_values == True:
            get_var = line.split(':')[0].strip(' ')
            get_val = line.split(':')[1].strip(' ')
            device_dict[device_index].append((get_var,get_val))
        if "Device Address" in line:
            device_index = device_index + 1
            device_dict.update({device_index:[]})
            record_values = True

    # Find X410
    for n in range(0,len(device_dict)):
        for nn in device_dict[n]:
            if 'X410' in nn:
                # Update Dashboard
                for m in device_dict[n]:
                    if m[0] == 'addr':
                        scan_results[5] = m[1]
                    if m[0] == 'serial':
                        scan_results[3] = m[1]

    # Find Daughterboard
    try:
        # Probe
        get_ip = scan_results[5]  # str(widget_ip.toPlainText())
        #widget_probing_label.setVisible(True)
        #QtWidgets.QApplication.processEvents()
        proc = subprocess.Popen('uhd_usrp_probe --args="addr=' + get_ip + '" &', shell=True, stdout=subprocess.PIPE, )
        output = str(proc.communicate()[0].decode())
        #widget_probing_label.setVisible(False)

        if "ZBX" in output:
            scan_results[6] = "ZBX"
    except:
        pass
        #widget_probing_label.setVisible(False)
        
    return scan_results


def find_bladeRF2(guess_serial="", guess_index=0):
    """ 
    Parses the results of 'bladeRF-cli' and copies the serial number for the bladeRF into an edit box.
    """
    # Scan Results
    scan_results = ['bladeRF 2.0','','','','','','']  # Type, UID, Radio Name, Serial, Net. Interface, IP Address, Daughterboard
    
    # Get the Text
    proc=subprocess.Popen('bladeRF-cli -p &', shell=True, stdout=subprocess.PIPE, )
    output = proc.communicate()[0].decode()

    # Reset Guess Index
    get_text = guess_serial  # str(widget_serial.toPlainText())
    if len(get_text) == 0:
        guess_index = 0
    else:
        guess_index = guess_index + 1

    # Get the Variables and Values
    device_index = -1
    device_dict = {}
    for line in output.splitlines():

        # "Serial:         5519595f67984cc3af24xxxxxxxxxxxx" Line
        if "Serial:" in line:
            device_index = device_index + 1
            device_dict.update({device_index:[]})
            get_var = line.split(':')[0].strip(' ')
            get_val = line.split(':')[1].strip(' ')
            device_dict[device_index].append((get_var,get_val))

    # Check Interface Index
    if guess_index > (len(device_dict)-1):
        guess_index = 0

    # Update GUI
    try:
        m = device_dict[guess_index][0]
        if m[0] == 'Serial':
            scan_results[3] = m[1]
    except:
        pass 
        
    return scan_results, guess_index
    

def findRTL2832U(guess_serial="", guess_index=0):
    """ 
    Parses the results of 'rtl_sdr' and returns the RTL serial number.
    """
    # Scan Results
    scan_results = ['RTL2832U','','','','','','']  # Type, UID, Radio Name, Serial, Net. Interface, IP Address, Daughterboard
    
    # Get the Text
    proc = subprocess.Popen("rtl_sdr -d -1 &", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)  # Return text is in stderr
    empty_output, output = proc.communicate()
    output = output.decode()

    # Reset Guess Index
    get_text = guess_serial
    if len(get_text) == 0:
        guess_index = 0
    else:
        guess_index = guess_index + 1

    # Get the Variables and Values
    device_index = -1
    device_dict = {}
    for line in output.splitlines():
        if "SN: " in line:
            device_index = device_index + 1
            device_dict.update({device_index:[]})
            get_var = line.split(', SN: ')[0].strip(' ')
            get_val = line.split(', SN: ')[1].strip(' ')
            device_dict[device_index].append((get_var,get_val))

    # Check Interface Index
    if guess_index > (len(device_dict)-1):
        guess_index = 0

    # Update GUI
    try:
        m = device_dict[guess_index][0]
        scan_results[3] = m[1]
    except:
        pass
        
    return scan_results, guess_index


def findRSPduo(guess_serial="", guess_index=0):
    """ 
    Parses the results of 'lsusb' and returns an integer based on the guess index and number of RSPduos.
    """
    # Scan Results
    scan_results = ['RSPduo','','','','','','']  # Type, UID, Radio Name, Serial, Net. Interface, IP Address, Daughterboard
    
    # Get the Text
    proc = subprocess.Popen("lsusb | grep RSPduo &", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, output_error = proc.communicate()
    output = output.decode()

    # Reset Guess Index
    get_text = guess_serial
    if len(get_text) == 0:
        guess_index = 0
    else:
        guess_index = guess_index + 1

    # Get the Variables and Values
    device_index = -1
    for line in output.splitlines():
        if "RSPduo" in line:
            device_index = device_index + 1

    # Check Interface Index
    if guess_index > device_index:
        guess_index = 0

    # Update GUI
    try:
        scan_results[3] = str(guess_index)
    except:
        pass
        
    return scan_results, guess_index


def findRSPdx(guess_serial="", guess_index=0):
    """ 
    Parses the results of 'lsusb' and returns an integer based on the guess index and number of RSPdxs.
    """
    # Scan Results
    scan_results = ['RSPdx','','','','','','']  # Type, UID, Radio Name, Serial, Net. Interface, IP Address, Daughterboard
    
    # Get the Text
    proc = subprocess.Popen("lsusb | grep -w RSPdx &", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, output_error = proc.communicate()
    output = output.decode()

    # Reset Guess Index
    get_text = guess_serial
    if len(get_text) == 0:
        guess_index = 0
    else:
        guess_index = guess_index + 1

    # Get the Variables and Values
    device_index = -1
    for line in output.splitlines():
        if "RSPdx" in line:
            device_index = device_index + 1

    # Check Interface Index
    if guess_index > device_index:
        guess_index = 0

    # Update GUI
    try:
        if device_index == -1:
            scan_results[3] = ""
        else:
            scan_results[3] = str(guess_index)
    except:
        pass
        
    return scan_results, guess_index
    
def findRSPdxR2(guess_serial="", guess_index=0):
    """ 
    Parses the results of 'lsusb' and returns an integer based on the guess index and number of RSPdx R2s.
    """
    # Scan Results
    scan_results = ['RSPdx R2','','','','','','']  # Type, UID, Radio Name, Serial, Net. Interface, IP Address, Daughterboard
    
    # Get the Text
    proc = subprocess.Popen("lsusb | grep RSPdxR2 &", shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, output_error = proc.communicate()
    output = output.decode()

    # Reset Guess Index
    get_text = guess_serial
    if len(get_text) == 0:
        guess_index = 0
    else:
        guess_index = guess_index + 1

    # Get the Variables and Values
    device_index = -1
    for line in output.splitlines():
        if "RSPdxR2" in line:
            device_index = device_index + 1

    # Check Interface Index
    if guess_index > device_index:
        guess_index = 0

    # Update GUI
    try:
        if device_index == -1:
            scan_results[3] = ""
        else:
            scan_results[3] = str(guess_index)
    except:
        pass
        
    return scan_results, guess_index


def findCaribouLite():
    """  
    Parses the results of 'SoapySDRUtil --find' and extracts the first CaribouLite device's UUID.
    """
    # Placeholder results
    scan_results = ['CaribouLite', '', '', '', '', '', '']  # Type, UID, Radio Name, Serial, Net. Interface, IP Address, Daughterboard

    # Run the command
    proc = subprocess.Popen("SoapySDRUtil --find &", shell=True, stdout=subprocess.PIPE)
    output = proc.communicate()[0].decode()

    # Find all CaribouLite device blocks
    blocks = output.split("Found device")
    for block in blocks:
        if "driver = Cariboulite" in block:
            # Extract UUID using regex
            match = re.search(r'uuid\s*=\s*([a-fA-F0-9\-]+)', block)
            if match:
                uuid = match.group(1)
                scan_results[1] = uuid
                break  # Stop after the first CaribouLite device

    return scan_results


def probe_gpsd(
        logger: logging.Logger,
        format="",
        serial_port="/dev/ttyACM1",
        return_altitude=False,
        timeout=5.0,
    ):
    from gps import gps, WATCH_ENABLE, WATCH_JSON

    """
    Probes GPS devices using gpsd and returns the coordinates without restarting gpsd.
    Assumes gpsd is already running and managing the serial device.
    """
    session = None
    try:
        if not os.path.exists(serial_port):
            logger.error(f"❌ GPS device not found at {serial_port}. Ensure the device is connected.")
            return None

        try:
            with socket.create_connection(("localhost", 2947), timeout=2):
                logger.debug("Connected to gpsd socket on port 2947.")
        except Exception as e:
            logger.error(f"❌ Could not connect to gpsd: {e}")
            return None

        session = gps(mode=WATCH_ENABLE | WATCH_JSON)
        logger.debug("GPS session initialized. Waiting for data...")

        start_time = time.time()
        timeout = max(1.0, float(timeout))

        while time.time() - start_time < timeout:
            try:
                report = session.next()
                if report.get("class") == "TPV":
                    lat = getattr(report, "lat", None)
                    lon = getattr(report, "lon", None)

                    if lat is not None and lon is not None:
                        if return_altitude:
                            alt = getattr(report, "alt", None)
                            return {
                                "latitude": lat,
                                "longitude": lon,
                                "altitude": alt,
                            }

                        coords = format_coordinates(lat, lon, format)
                        logger.debug(f"✅ GPS Data Received: {coords}")
                        return coords

            except KeyError:
                continue
            except StopIteration:
                logger.error("❌ GPSD has terminated")
                return None
            except Exception as e:
                logger.error(f"❌ Error while retrieving GPS data: {e}")
                return None

        logger.warning(
            f"GPS timeout: no valid position received within {timeout:.1f} seconds."
        )
        return None

    except Exception as e:
        logger.error(f"❌ Error in GPS probe: {e}")
        return None

    finally:
        if session:
            try:
                session.close()
                logger.debug("GPS session closed cleanly.")
            except Exception as e:
                logger.error(f"Error closing GPS session: {e}")
    

async def probeMeshtasticGPS(serial_port: str, timeout: int = 10) -> Optional[Dict[str, float]]:
    """
    Create a temporary Meshtastic serial connection, fetch GPS data, then close the connection.

    Args:
        serial_port (str): The serial port to connect to.
        timeout (int): Maximum time in seconds to wait for GPS data.

    Returns:
        dict: GPS coordinates if successful, None if failed.
    """
    try:
        interface = SerialInterface(serial_port)
        start_time = asyncio.get_running_loop().time()

        while asyncio.get_running_loop().time() - start_time < timeout:
            node_info = interface.getMyNodeInfo()

            if node_info and "position" in node_info:
                position = node_info["position"]

                if "latitudeI" in position and "longitudeI" in position:
                    latitude = round(position["latitudeI"] / 1e7, 6)
                    longitude = round(position["longitudeI"] / 1e7, 6)
                elif "latitude" in position and "longitude" in position:
                    latitude = round(position["latitude"], 6)
                    longitude = round(position["longitude"], 6)
                else:
                    latitude = None
                    longitude = None

                altitude = position.get("altitude", 0.0)  # Altitude is optional

                if latitude is not None and longitude is not None and latitude != 0 and longitude != 0:
                    interface.close()
                    return {
                        "latitude": latitude,
                        "longitude": longitude,
                        "altitude": altitude
                    }

            await asyncio.sleep(1)  # Retry if GPS is unavailable

        # Close the connection if no GPS lock is found
        interface.close()
        return None  # Instead of "GPS not acquired", return None

    except Exception as e:
        print(f"Error creating temporary connection to {serial_port}: {e}")
        return None


async def probeInternetGPS(logger):
    """
    Fetch approximate GPS data from the internet using IP-based geolocation.

    Returns:
        dict: {'latitude': float, 'longitude': float, 'altitude': float}
        or None if the lookup failed.
    """
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get("https://ipinfo.io/loc", timeout=5) as response:
                if response.status == 200:
                    text = (await response.text()).strip()
                    lat_str, lon_str = text.split(",")
                    lat = float(lat_str)
                    lon = float(lon_str)
                    alt = 0.0  # IP geolocation has no altitude info
                    logger.info(f"Fetched internet GPS location: {lat}, {lon}")
                    return {'latitude': lat, 'longitude': lon, 'altitude': alt}
                else:
                    logger.warning(f"ipinfo.io returned status {response.status}")
                    return None
    except Exception as e:
        logger.error(f"Error fetching GPS from internet: {e}")
        return None


def getHardwareGain(hardware_type: str, tx_rx: str):
    """ 
    Returns (min, max, default) hardware gain values for transmit or receive.
    """
    # Transmit
    gain_values = None
    if tx_rx == "TX":
        if hardware_type == "Computer":
            gain_values = None
        elif hardware_type == "USRP X3x0":
            gain_values = [0, 34, 30]
        elif hardware_type == "USRP B2x0":
            gain_values = [0, 90, 70]
        elif hardware_type == "HackRF":
            gain_values = [0, 47, 40]
        elif hardware_type == "RTL2832U":
            gain_values = None
        elif hardware_type == "802.11x Adapter":
            gain_values = None
        elif hardware_type == "USRP B20xmini":
            gain_values = [0, 90, 70]
        elif hardware_type == "LimeSDR":
            gain_values = [0, 70, 50]
        elif hardware_type == "bladeRF":
            gain_values = [0, 47, 40]
        elif hardware_type == "Open Sniffer":
            gain_values = None
        elif hardware_type == "PlutoSDR":
            gain_values = [0, 71, 64]
        elif hardware_type == "USRP2":
            gain_values = [0, 34, 30]
        elif hardware_type == "USRP N2xx":
            gain_values = [0, 34, 30]
        elif hardware_type == "bladeRF 2.0":
            if get_library_version() == "maint-3.8":
                gain_values = [0, 47, 40]
            else:
                gain_values = [17, 73, 60]
        elif hardware_type == "USRP X410":
            gain_values = [0, 60, 50]
        elif hardware_type == "RSPduo":
            gain_values = [0, 59, 0]  # attenuation, not gain
        elif hardware_type == "RSPdx":
            gain_values = [0, 59, 0]  # attenuation, not gain
        elif hardware_type == "RSPdx R2":
            gain_values = [0, 59, 0]  # attenuation, not gain
        elif hardware_type == "CaribouLite":
            gain_values = [0, 31, 20]  # Does CaribouLite use TX gain or is it fixed?
        else:
            gain_values = None

    # Receive
    elif tx_rx == "RX":
        if hardware_type == "Computer":
            gain_values = None
        elif hardware_type == "USRP X3x0":
            gain_values = [0, 34, 30]
        elif hardware_type == "USRP B2x0":
            gain_values = [0, 90, 70]
        elif hardware_type == "HackRF":
            gain_values = [0, 47, 40]
        elif hardware_type == "RTL2832U":
            gain_values = [0, 47, 40]
        elif hardware_type == "802.11x Adapter":
            gain_values = None
        elif hardware_type == "USRP B20xmini":
            gain_values = [0, 90, 70]
        elif hardware_type == "LimeSDR":
            gain_values = [0, 70, 50]
        elif hardware_type == "bladeRF":
            gain_values = [0, 47, 40]
        elif hardware_type == "Open Sniffer":
            gain_values = None
        elif hardware_type == "PlutoSDR":
            gain_values = [0, 71, 64]
        elif hardware_type == "USRP2":
            gain_values = [0, 34, 30]
        elif hardware_type == "USRP N2xx":
            gain_values = [0, 34, 30]
        elif hardware_type == "bladeRF 2.0":
            if get_library_version() == "maint-3.8":
                gain_values = [0, 47, 40]
            else:
                gain_values = [-1, 60, 50]
        elif hardware_type == "USRP X410":
            gain_values = [0, 60, 50]
        elif hardware_type == "RSPduo":
            gain_values = [0, 59, 0]  # attenuation, not gain
        elif hardware_type == "RSPdx":
            gain_values = [0, 59, 0]  # attenuation, not gain
        elif hardware_type == "RSPdx R2":
            gain_values = [0, 59, 0]  # attenuation, not gain
        elif hardware_type == "CaribouLite":
            gain_values = [0, 31, 20]            
        else:
            gain_values = None

    return gain_values


def getHardwareAntennas(hardware_type: str, tx_rx: str):
    """ 
    Returns a list of hardware antenna options for transmit or receive.
    """
    # Transmit
    antenna_values = None
    if tx_rx == "TX":
        if hardware_type == "Computer":
            antenna_values = None
        elif hardware_type == "USRP X3x0":
            antenna_values = ["TX/RX"]
        elif hardware_type == "USRP B2x0":
            antenna_values = ["TX/RX"]
        elif hardware_type == "HackRF":
            antenna_values = [""]
        elif hardware_type == "RTL2832U":
            antenna_values = None
        elif hardware_type == "802.11x Adapter":
            antenna_values = None
        elif hardware_type == "USRP B20xmini":
            antenna_values = ["TX/RX"]
        elif hardware_type == "LimeSDR":
            antenna_values = ["TX1", "TX2"]
        elif hardware_type == "bladeRF":
            antenna_values = ["", ""]
        elif hardware_type == "Open Sniffer":
            antenna_values = None
        elif hardware_type == "PlutoSDR":
            antenna_values = [""]
        elif hardware_type == "USRP2":
            antenna_values = ["J1", "J2"]
        elif hardware_type == "USRP N2xx":
            antenna_values = ["J1", "J2"]
        elif hardware_type == "bladeRF 2.0":
            if get_library_version() == "maint-3.8":
                antenna_values = ["", ""]
            else:
                antenna_values = ["", ""]  # Will this be different?
        elif hardware_type == "USRP X410":
            antenna_values = ["TX/RX"]
        elif hardware_type == "RSPduo":
            antenna_values = None
        elif hardware_type == "RSPdx":
            antenna_values = None
        elif hardware_type == "RSPdx R2":
            antenna_values = None
        elif hardware_type == "CaribouLite":
            antenna_values = None            
        else:
            antenna_values = None

    # Receive
    elif tx_rx == "RX":
        if hardware_type == "Computer":
            antenna_values = None
        elif hardware_type == "USRP X3x0":
            antenna_values = ["TX/RX", "RX1", "RX2"]
        elif hardware_type == "USRP B2x0":
            antenna_values = ["TX/RX", "RX2"]
        elif hardware_type == "HackRF":
            antenna_values = [""]
        elif hardware_type == "RTL2832U":
            antenna_values = [""]
        elif hardware_type == "802.11x Adapter":
            antenna_values = None
        elif hardware_type == "USRP B20xmini":
            antenna_values = ["TX/RX", "RX2"]
        elif hardware_type == "LimeSDR":
            antenna_values = ["RX1", "RX2"]
        elif hardware_type == "bladeRF":
            antenna_values = ["", ""]
        elif hardware_type == "Open Sniffer":
            antenna_values = None
        elif hardware_type == "PlutoSDR":
            antenna_values = [""]
        elif hardware_type == "USRP2":
            antenna_values = ["J1", "J2"]
        elif hardware_type == "USRP N2xx":
            antenna_values = ["J1", "J2"]
        elif hardware_type == "bladeRF 2.0":
            if get_library_version() == "maint-3.8":
                antenna_values = ["", ""]
            else:
                antenna_values = ["", ""]
        elif hardware_type == "USRP X410":
            antenna_values = ["TX/RX", "RX1", "RX2"]
        elif hardware_type == "RSPduo":
            antenna_values = ["1", "2"]
        elif hardware_type == "RSPdx":
            antenna_values = ["A", "B", "C"]
        elif hardware_type == "RSPdx R2":
            antenna_values = ["A", "B", "C"]
        elif hardware_type == "CaribouLite":
            antenna_values = None            
        else:
            antenna_values = None

    return antenna_values


def getHardwareChannels(hardware_type: str, tx_rx: str):
    """ 
    Returns a list of hardware channels options for transmit or receive.
    """
    # Transmit
    channel_values = None
    if tx_rx == "TX":
        if hardware_type == "Computer":
            channel_values = None
        elif hardware_type == "USRP X3x0":
            channel_values = ["A:0", "B:0"]
        elif hardware_type == "USRP B2x0":
            channel_values = ["A:A", "A:B"]
        elif hardware_type == "HackRF":
            channel_values = [""]
        elif hardware_type == "RTL2832U":
            channel_values = None
        elif hardware_type == "802.11x Adapter":
            channel_values = None
        elif hardware_type == "USRP B20xmini":
            channel_values = ["A:A", "A:B"]
        elif hardware_type == "LimeSDR":
            channel_values = ["A", "B"]
        elif hardware_type == "bladeRF":
            channel_values = ["", ""]
        elif hardware_type == "Open Sniffer":
            channel_values = None
        elif hardware_type == "PlutoSDR":
            channel_values = [""]
        elif hardware_type == "USRP2":
            channel_values = ["A:0", "B:0", "A:AB", "A:BA", "A:A", "A:B", "B:AB", "B:BA", "B:A", "B:B"]
        elif hardware_type == "USRP N2xx":
            channel_values = ["A:0", "B:0", "A:AB", "A:BA", "A:A", "A:B", "B:AB", "B:BA", "B:A", "B:B"]
        elif hardware_type == "bladeRF 2.0":
            if get_library_version() == "maint-3.8":
                channel_values = ["", ""]
            else:
                channel_values = ["", ""]  # Will this be different?
        elif hardware_type == "USRP X410":
            channel_values = ["A:0", "B:0"]
        elif hardware_type == "RSPduo":
            channel_values = None
        elif hardware_type == "RSPdx":
            channel_values = None
        elif hardware_type == "RSPdx R2":
            channel_values = None
        elif hardware_type == "CaribouLite":
            channel_values = ["HiF", "S1G"]
        else:
            channel_values = None

    # Receive
    elif tx_rx == "RX":
        if hardware_type == "Computer":
            channel_values = None
        elif hardware_type == "USRP X3x0":
            channel_values = ["A:0", "B:0"]
        elif hardware_type == "USRP B2x0":
            channel_values = ["A:A", "A:B"]
        elif hardware_type == "HackRF":
            channel_values = [""]
        elif hardware_type == "RTL2832U":
            channel_values = [""]
        elif hardware_type == "802.11x Adapter":
            channel_values = None
        elif hardware_type == "USRP B20xmini":
            channel_values = ["A:A", "A:B"]
        elif hardware_type == "LimeSDR":
            channel_values = ["A", "B"]
        elif hardware_type == "bladeRF":
            channel_values = ["", ""]
        elif hardware_type == "Open Sniffer":
            channel_values = None
        elif hardware_type == "PlutoSDR":
            channel_values = [""]
        elif hardware_type == "USRP2":
            channel_values = ["A:0", "B:0", "A:AB", "A:BA", "A:A", "A:B", "B:AB", "B:BA", "B:A", "B:B"]
        elif hardware_type == "USRP N2xx":
            channel_values = ["A:0", "B:0", "A:AB", "A:BA", "A:A", "A:B", "B:AB", "B:BA", "B:A", "B:B"]
        elif hardware_type == "bladeRF 2.0":
            if get_library_version() == "maint-3.8":
                channel_values = ["", ""]
            else:
                channel_values = ["", ""]  # Will this be different?
        elif hardware_type == "USRP X410":
            channel_values = ["A:0", "B:0"]
        elif hardware_type == "RSPduo":
            channel_values = [""]
        elif hardware_type == "RSPdx":
            channel_values = [""]
        elif hardware_type == "RSPdx R2":
            channel_values = [""]
        elif hardware_type == "CaribouLite":
            channel_values = ["HiF", "S1G"]
        else:
            channel_values = None

    return channel_values


async def probeUSRP_X3x0(ip_address=""):
    """
    Asynchronously probes a USRP X3x0 device.
    """
    try:
        proc = await asyncio.create_subprocess_shell(
            f'uhd_usrp_probe --args="addr={ip_address}"',
            shell=True,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        output, _ = await proc.communicate()
        output = output.decode()
    except Exception as e:
        output = f"Error: {str(e)}"
    
    return output


async def probeUSRP_B2x0():
    """
    Asynchronously probes a USRP B200/B210 device.
    """
    try:
        proc = await asyncio.create_subprocess_shell(
            'uhd_usrp_probe --args="type=b200"',
            shell=True,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        output, _ = await proc.communicate()
        output = output.decode()

    except Exception as e:
        output = f"Error: {str(e)}"

    return output


async def probe_bladeRF():
    """
    Asynchronously probes a bladeRF device.
    """
    try:
        proc = await asyncio.create_subprocess_shell(
            "bladeRF-cli -p",
            shell=True,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        output, _ = await proc.communicate()
        output = output.decode()
    except Exception as e:
        output = f"Error: {str(e)}"
    
    return output


async def probeLimeSDR():
    """
    Asynchronously probes a LimeSDR device.
    """
    try:
        proc = await asyncio.create_subprocess_shell(
            "LimeUtil --find",
            shell=True,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        output, _ = await proc.communicate()
        output = output.decode()
    except Exception as e:
        output = f"Error: {str(e)}"

    return output


async def probeHackRF():
    """
    Asynchronously probes a HackRF device.
    """
    try:
        proc = await asyncio.create_subprocess_shell(
            "hackrf_info",
            shell=True,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        output, _ = await proc.communicate()
        output = output.decode()
    except Exception as e:
        output = f"Error: {str(e)}"

    return output


async def probePlutoSDR():
    """
    Asynchronously probes a PlutoSDR device.
    """
    try:
        proc = await asyncio.create_subprocess_shell(
            "iio_info -n pluto.local",
            shell=True,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        output, _ = await proc.communicate()
        output = output.decode()
    except Exception as e:
        output = f"Error: {str(e)}"

    return output


async def probeUSRP2(ip_address=""):
    """
    Asynchronously probes a USRP2 device.
    """
    try:
        proc = await asyncio.create_subprocess_shell(
            f'uhd_usrp_probe --args="addr={ip_address}"',
            shell=True,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        output, _ = await proc.communicate()
        output = output.decode()
    except Exception as e:
        output = f"Error: {str(e)}"

    return output


async def probeUSRP2_N2xx(ip_address=""):
    """
    Asynchronously probes a USRP2 N2xx device.
    """
    try:
        proc = await asyncio.create_subprocess_shell(
            f'uhd_usrp_probe --args="addr={ip_address}"',
            shell=True,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        output, _ = await proc.communicate()
        output = output.decode()
    except Exception as e:
        output = f"Error: {str(e)}"

    return output

async def probe_bladeRF2():
    """
    Asynchronously probes a bladeRF 2.0 device.
    """
    try:
        proc = await asyncio.create_subprocess_shell(
            "bladeRF-cli -p",
            shell=True,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        output, _ = await proc.communicate()
        output = output.decode()
    except Exception as e:
        output = f"Error: {str(e)}"
    
    return output


async def probeUSRP_X410(ip_address=""):
    """
    Asynchronously probes a USRP X410 device.
    """
    try:
        proc = await asyncio.create_subprocess_shell(
            f'uhd_usrp_probe --args="addr={ip_address}"',
            shell=True,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        output, _ = await proc.communicate()
        output = output.decode()
    except Exception as e:
        output = f"Error: {str(e)}"

    return output


async def probeRTL2832U():
    """
    Asynchronously probes an RTL2832U device.
    """
    try:
        proc = await asyncio.create_subprocess_shell(
            "rtl_sdr -d -1",
            shell=True, 
            stdout=asyncio.subprocess.PIPE, 
            stderr=asyncio.subprocess.PIPE
        )  # Return text is in stderr
        _, output = await proc.communicate()
        output = output.decode()
        output = output.split("No matching devices found.")[0]
    except Exception as e:
        output = f"Error: {str(e)}"

    return output


async def probeRSPduo():
    """
    Asynchronously probes an RSPduo device.
    """
    try:
        proc = await asyncio.create_subprocess_shell(
            "lsusb",
            shell=True, 
            stdout=asyncio.subprocess.PIPE, 
            stderr=asyncio.subprocess.PIPE
        )
        output, _ = await proc.communicate()
        output = output.decode()
    except Exception as e:
        output = f"Error: {str(e)}"
    
    return output


async def probeRSPdx():
    """
    Asynchronously probes an RSPdx device.
    """
    try:
        proc = await asyncio.create_subprocess_shell(
            "lsusb",
            shell=True, 
            stdout=asyncio.subprocess.PIPE, 
            stderr=asyncio.subprocess.PIPE
        )
        output, _ = await proc.communicate()
        output = output.decode()

    except Exception as e:
        output = f"Error: {str(e)}"

    return output


async def probeRSPdxR2():
    """
    Asynchronously probes an RSPdx R2 device.
    """
    try:
        proc = await asyncio.create_subprocess_shell(
            "lsusb",
            shell=True, 
            stdout=asyncio.subprocess.PIPE, 
            stderr=asyncio.subprocess.PIPE
        )
        output, _ = await proc.communicate()
        output = output.decode()

    except Exception as e:
        output = f"Error: {str(e)}"

    return output


async def probe80211x():
    """
    Asynchronously probes an 802.11x device.
    """
    try:
        proc = await asyncio.create_subprocess_shell(
            "iwconfig",
            shell=True, 
            stdout=asyncio.subprocess.PIPE, 
            stderr=asyncio.subprocess.PIPE
        )
        output, _ = await proc.communicate()
        output = output.decode()

    except Exception as e:
        output = f"Error: {str(e)}"

    return output


async def probeCaribouLite():
    """
    Asynchronously probes a CaribouLite SDR device using SoapySDRUtil.
    """
    try:
        proc = await asyncio.create_subprocess_shell(
            "SoapySDRUtil --find",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        output, _ = await proc.communicate()
        output = output.decode()
    except Exception as e:
        output = f"Error: {str(e)}"

    return output


def get_default_sdr(settings):
    """Return the default SDR config dict."""
    hw = settings.get("Sensor Node", {}).get("hardware", {})
    defaults = hw.get("defaults", {})
    sdr_key = defaults.get("sdr")

    sdrs = hw.get("sdrs", {})
    return sdrs.get(sdr_key)


def get_default_wifi(settings):
    """Return the default Wi-Fi adapter config dict."""
    hw = settings.get("Sensor Node", {}).get("hardware", {})
    defaults = hw.get("defaults", {})
    wifi_key = defaults.get("wifi_adapter")

    wifi = hw.get("wifi_adapters", {})
    return wifi.get(wifi_key)


def get_default_wifi_interface(settings):
    wifi = get_default_wifi(settings)
    if not wifi:
        return None
    return wifi.get("interface")


def _get_selected_node_hardware_settings(dashboard):
    """
    Returns the selected node hardware settings dictionary.

    Expected format:
        dashboard.selected_node_settings["Sensor Node"]["hardware"]
    """
    selected_settings = getattr(dashboard, "selected_node_settings", {}) or {}

    if not isinstance(selected_settings, dict):
        return {}

    sensor_node_settings = selected_settings.get("Sensor Node", {}) or {}

    if not isinstance(sensor_node_settings, dict):
        return {}

    hardware_settings = sensor_node_settings.get("hardware", {}) or {}

    if not isinstance(hardware_settings, dict):
        return {}

    return hardware_settings


def _get_hardware_sections_for_component(component):
    """
    Maps old component/category names to the new selected-node hardware sections.
    """
    component_key = str(component or "").strip().lower()

    if component_key in ["sdr", "sdrs"]:
        return ["sdrs"]

    if component_key in [
        "wifi",
        "wi-fi",
        "wifi_adapter",
        "wifi_adapters",
        "802.11x adapter",
    ]:
        return ["wifi_adapters"]

    # Legacy callers may pass "tsi", "pd", "attack", or "archive".
    # The new node config does not store hardware by tab anymore, so return all.
    return ["sdrs", "wifi_adapters"]


def _hardware_entry_to_values(uid, entry, section):
    """
    Converts a new selected-node hardware entry into the legacy return format:

        [type, uid, radio_name, serial, interface, ip, daughterboard]
    """
    if not isinstance(entry, dict):
        return ["", "", "", "", "", "", ""]

    ret_uid = str(uid)

    if section == "wifi_adapters":
        ret_type = str(entry.get("type") or "802.11x Adapter")
    else:
        ret_type = str(entry.get("type") or "")

    ret_radio_name = str(entry.get("radio_name", "") or "")
    ret_serial = str(entry.get("serial", "") or "")

    ret_interface = str(
        entry.get("network_interface")
        or entry.get("interface")
        or ""
    )

    ret_ip = str(entry.get("ip_address", "") or "")
    ret_daughterboard = str(entry.get("daughterboard", "") or "")

    return [
        ret_type,
        ret_uid,
        ret_radio_name,
        ret_serial,
        ret_interface,
        ret_ip,
        ret_daughterboard,
    ]


def hardwareDisplayNameFromValues(values):
    """
    Returns a combobox display name from legacy hardware values:

        [type, uid, radio_name, serial, interface, ip, daughterboard]
    """
    if not values or len(values) < 7:
        return ""

    hardware_type = str(values[0] or "").strip()
    uid = str(values[1] or "").strip()
    radio_name = str(values[2] or "").strip()
    serial = str(values[3] or "").strip()
    interface = str(values[4] or "").strip()
    ip_address = str(values[5] or "").strip()
    daughterboard = str(values[6] or "").strip()

    if not hardware_type:
        return ""

    if hardware_type in ["Computer", "Open Sniffer"]:
        return hardware_type

    hardware_id_column = hardwareID_Column(hardware_type)

    if hardware_id_column == 1:
        second_value = uid
    elif hardware_id_column == 2:
        second_value = radio_name
    elif hardware_id_column == 3:
        second_value = serial
    elif hardware_id_column == 4:
        second_value = interface
    elif hardware_id_column == 5:
        second_value = ip_address
    elif hardware_id_column == 6:
        second_value = daughterboard
    else:
        second_value = ""

    if second_value:
        return f"{hardware_type} - {second_value}"

    # Clearly labeled fallback when the real hardware ID is missing.
    if uid:
        return f"{hardware_type} - UID {uid}"

    if radio_name:
        return f"{hardware_type} - {radio_name}"

    return hardware_type


def selectedNodeHardwareDisplayNames(
    dashboard,
    component="",
    include_computer=False,
):
    """
    Returns hardware display names for the currently selected node.

    component may be:
        "sdrs", "wifi_adapters", "tsi", "pd", "attack", "archive", etc.

    Legacy tab component names return all selected-node hardware because the
    new YAML stores hardware globally under Sensor Node -> hardware.
    """
    display_names = []

    if include_computer:
        display_names.append("Computer")

    hardware_settings = _get_selected_node_hardware_settings(dashboard)
    sections = _get_hardware_sections_for_component(component)

    for section in sections:
        entries = hardware_settings.get(section, {}) or {}

        if not isinstance(entries, dict):
            continue

        for uid, entry in entries.items():
            values = _hardware_entry_to_values(uid, entry, section)
            display_name = hardwareDisplayNameFromValues(values)

            if display_name:
                display_names.append(display_name)

    return display_names


def get_compatible_sdr(settings, compatible_types):
    """
    Return (uid, sdr_entry) for the default compatible SDR, falling back to the
    first compatible SDR.

    compatible_types should be a list/set of hardware type strings, such as:
        ["USRP B20xmini", "USRP B2x0"]
    """
    compatible_types = set(compatible_types or [])

    hw = settings.get("Sensor Node", {}).get("hardware", {}) or {}
    defaults = hw.get("defaults", {}) or {}
    sdrs = hw.get("sdrs", {}) or {}

    if not isinstance(sdrs, dict) or not sdrs:
        return None, None

    default_sdr_uid = defaults.get("sdr", "")

    # Prefer the configured default SDR if compatible.
    for candidate_uid in (default_sdr_uid, str(default_sdr_uid)):
        if candidate_uid in sdrs and isinstance(sdrs[candidate_uid], dict):
            candidate = sdrs[candidate_uid]
            candidate_type = str(candidate.get("type", "") or "").strip()

            if candidate_type in compatible_types:
                return candidate_uid, candidate

    # Otherwise use the first compatible SDR.
    for candidate_uid, candidate in sdrs.items():
        if not isinstance(candidate, dict):
            continue

        candidate_type = str(candidate.get("type", "") or "").strip()

        if candidate_type in compatible_types:
            return candidate_uid, candidate

    return None, None


def sdr_entry_to_operation_parameters(uid, entry):
    """
    Convert a Sensor Node SDR config entry into normalized plugin operation
    hardware_* parameters.
    """
    if not isinstance(entry, dict):
        return {}

    radio_name = str(entry.get("radio_name", "") or "").strip()
    hardware_type = str(entry.get("type", "") or "").strip()
    serial = str(entry.get("serial", "") or "").strip()
    ip_address = str(entry.get("ip_address", "") or "").strip()

    if hardware_type in {"USRP B20xmini", "USRP B2x0"}:
        serial_argument = f"serial={serial}" if serial else "False"
    else:
        serial_argument = serial if serial else "False"

    return {
        "hardware_uuid": str(uid),
        "hardware_type": hardware_type,
        "hardware_display_name": radio_name,
        "hardware_radio_name": radio_name,
        "hardware_serial": serial,
        "hardware_interface": str(
            entry.get("network_interface")
            or entry.get("interface")
            or ""
        ).strip(),
        "hardware_ip": ip_address,
        "hardware_daughterboard": str(entry.get("daughterboard", "") or "").strip(),
        "hardware_serial_argument": serial_argument,
    }