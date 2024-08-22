import subprocess


def hardwareDisplayName(dashboard, hardware_type, sensor_node, component, index):
    """Returns a display name for comboboxes based on provided sensor node hardware information."""
    # Return Display Name Based on Type
    get_hardware_name = ""
    if hardware_type == "Computer":
        get_hardware_name = hardware_type
    elif hardware_type == "USRP X3x0":
        get_hardware_name = hardware_type + " - " + dashboard.backend.settings[sensor_node][component][index][5]
    elif hardware_type == "USRP B2x0":
        get_hardware_name = hardware_type + " - " + dashboard.backend.settings[sensor_node][component][index][3]
    elif hardware_type == "HackRF":
        get_hardware_name = hardware_type + " - " + dashboard.backend.settings[sensor_node][component][index][3]
    elif hardware_type == "RTL2832U":
        get_hardware_name = hardware_type + " - " + dashboard.backend.settings[sensor_node][component][index][3]
    elif hardware_type == "802.11x Adapter":
        get_hardware_name = hardware_type + " - " + dashboard.backend.settings[sensor_node][component][index][4]
    elif hardware_type == "USRP B20xmini":
        get_hardware_name = hardware_type + " - " + dashboard.backend.settings[sensor_node][component][index][3]
    elif hardware_type == "LimeSDR":
        get_hardware_name = hardware_type + " - " + dashboard.backend.settings[sensor_node][component][index][3]
    elif hardware_type == "bladeRF":
        get_hardware_name = hardware_type + " - " + dashboard.backend.settings[sensor_node][component][index][3]
    elif hardware_type == "Open Sniffer":
        get_hardware_name = hardware_type
    elif hardware_type == "PlutoSDR":
        get_hardware_name = hardware_type + " - " + dashboard.backend.settings[sensor_node][component][index][5]
    elif hardware_type == "USRP2":
        get_hardware_name = hardware_type + " - " + dashboard.backend.settings[sensor_node][component][index][5]
    elif hardware_type == "USRP N2xx":
        get_hardware_name = hardware_type + " - " + dashboard.backend.settings[sensor_node][component][index][5]
    elif hardware_type == "bladeRF 2.0":
        get_hardware_name = hardware_type + " - " + dashboard.backend.settings[sensor_node][component][index][3]
    elif hardware_type == "USRP X410":
        get_hardware_name = hardware_type + " - " + dashboard.backend.settings[sensor_node][component][index][5]
    else:
        get_hardware_name = "UNKNOWN HARDWARE"

    return get_hardware_name


def hardwareDisplayNameLookup(dashboard, display_name, component):
    """
    Takes in a hardware display name and returns all the sensor node hardware information.
    """
    # Return Saved Hardware Information
    hardware_type = display_name.split(" - ")[0]
    try:
        second_value = display_name.split(" - ")[1]
    except:
        second_value = ""

    if len(second_value) > 0:
        get_sensor_node = ["sensor_node1", "sensor_node2", "sensor_node3", "sensor_node4", "sensor_node5"]
        sensor_node = get_sensor_node[dashboard.active_sensor_node]
        get_index = 0
        for n in range(0, len(dashboard.backend.settings[sensor_node][component])):
            if hardware_type == "Computer":
                if second_value == "":  # todo
                    get_index = n
                    break
            elif hardware_type == "USRP X3x0":
                if second_value == dashboard.backend.settings[sensor_node][component][n][5]:
                    get_index = n
                    break
            elif hardware_type == "USRP B2x0":
                if second_value == dashboard.backend.settings[sensor_node][component][n][3]:
                    get_index = n
                    break
            elif hardware_type == "HackRF":
                if second_value == dashboard.backend.settings[sensor_node][component][n][3]:
                    get_index = n
                    break
            elif hardware_type == "RTL2832U":
                if second_value == dashboard.backend.settings[sensor_node][component][n][3]:
                    get_index = n
                    break
            elif hardware_type == "802.11x Adapter":
                if second_value == dashboard.backend.settings[sensor_node][component][n][4]:
                    get_index = n
                    break
            elif hardware_type == "USRP B20xmini":
                if second_value == dashboard.backend.settings[sensor_node][component][n][3]:
                    get_index = n
                    break
            elif hardware_type == "LimeSDR":
                if second_value == dashboard.backend.settings[sensor_node][component][n][3]:
                    get_index = n
                    break
            elif hardware_type == "bladeRF":
                if second_value == dashboard.backend.settings[sensor_node][component][n][3]:
                    get_index = n
                    break
            elif hardware_type == "Open Sniffer":
                if second_value == "":  # todo
                    get_index = n
                    break
            elif hardware_type == "PlutoSDR":
                if second_value == dashboard.backend.settings[sensor_node][component][n][5]:
                    get_index = n
                    break
            elif hardware_type == "USRP2":
                if second_value == dashboard.backend.settings[sensor_node][component][n][5]:
                    get_index = n
                    break
            elif hardware_type == "USRP N2xx":
                if second_value == dashboard.backend.settings[sensor_node][component][n][5]:
                    get_index = n
                    break
            elif hardware_type == "bladeRF 2.0":
                if second_value == dashboard.backend.settings[sensor_node][component][n][3]:
                    get_index = n
                    break
            elif hardware_type == "USRP X410":
                if second_value == dashboard.backend.settings[sensor_node][component][n][5]:
                    get_index = n
                    break
            else:
                pass

        # Return All Saved Values
        ret_type = dashboard.backend.settings[sensor_node][component][get_index][0]
        ret_uid = dashboard.backend.settings[sensor_node][component][get_index][1]
        ret_radio_name = dashboard.backend.settings[sensor_node][component][get_index][2]
        ret_serial = dashboard.backend.settings[sensor_node][component][get_index][3]
        ret_interface = dashboard.backend.settings[sensor_node][component][get_index][4]
        ret_ip = dashboard.backend.settings[sensor_node][component][get_index][5]
        ret_daughterboard = dashboard.backend.settings[sensor_node][component][get_index][6]

        return [ret_type, ret_uid, ret_radio_name, ret_serial, ret_interface, ret_ip, ret_daughterboard]

    else:
        return ["", "", "", "", "", "", ""]
        

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
        if (get_frequency >= 47) and (get_frequency <= 6000):
            return True

    elif get_hardware == "USRP X410":
        # Frequency Limits
        if get_daughterboard == "ZBX":
            if (get_frequency >= 1) and (get_frequency <= 7200):
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
    proc = subprocess.Popen("iwconfig &", shell=True, stdout=subprocess.PIPE, )
    output = proc.communicate()[0].decode()

    # Reset Interface Index
    get_text = guess_network_interface  # str(widget_interface.toPlainText())
    if len(get_text) == 0:
        guess_index = 0
    else:
        guess_index = guess_index + 1

    # Pull the Interfaces
    lines = output.split('\n')
    get_interface = ''
    wifi_interfaces = []
    for n in range(0,len(lines)):
        if 'ESSID' in lines[n]:
            wifi_interfaces.append(lines[n].split(' ',1)[0])

    # Found an Interface
    if len(wifi_interfaces) > 0:

        # Check Interface Index
        if guess_index > (len(wifi_interfaces)-1):
            guess_index = 0

        # Update the Edit Box
        get_interface = wifi_interfaces[guess_index]
        scan_results[4] = get_interface
        
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
