import sys
import time
import subprocess

def main():
    # Accept Command Line Arguments
    try:
        interface = str(sys.argv[1])
        ssid = str(sys.argv[2])
    except:
        print("Error accepting detect SSID arguments. Exiting trigger.")
        return -1
            
    # Check SSIDs Periodically
    while True:
        get_ssids = scan_wifi_ssids(interface)
        print(get_ssids)
        for n in range(0,len(get_ssids)):
            if ssid == get_ssids[n]:
                return 0
        
        time.sleep(10)

def scan_wifi_ssids(interface='wlan0'):
    """
    Scan for available SSIDs (wireless network names) using iwlist command.
    
    :param interface: Name of the wireless interface (default is wlan0).
    :return: List of SSIDs found during the scan.
    """
    try:
        # Run iwlist command to scan for wireless networks
        result = subprocess.run(['iwlist', interface, 'scan'], capture_output=True, text=True)
        output_lines = result.stdout.split('\n')
        
        # Extract SSIDs from the output
        ssids = []
        for line in output_lines:
            if 'ESSID' in line:
                ssid = line.split('"')[1]
                ssids.append(ssid)
        
        return ssids
    except Exception as e:
        print(f"Error: {e}")
        return None



if __name__ == "__main__":
    main()
