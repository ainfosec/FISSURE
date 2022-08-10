from scapy.all import Dot11,Dot11ProbeReq,Dot11Elt,RadioTap,sendp
import os, sys

#################################################
############ Default FISSURE Header #############
#################################################
def getArguments():
    client = 'FF:FF:FF:FF:FF:FF'        # Receiver/Dest. MAC address
    trans = 'EC:08:6B:46:FE:30'         # Transmitter/Source MAC address  
    bssid = 'FF:FF:FF:FF:FF:FF'         # BSSID MAC address         
    iface = 'wlan0'	                    # Wireless interface name 
    channel = '1'                       # Wireless channel
    interval = 0.01                     # Scapy interval
    notes = 'Transmits a Scapy probe request on repeat.'
    arg_names = ['client','trans','bssid','iface','channel','interval','notes']
    arg_values = [client, trans, bssid, iface, channel, interval, notes]

    return (arg_names,arg_values)


if __name__ == "__main__":

    # Default Values
    client = 'FF:FF:FF:FF:FF:FF'        # Receiver/Dest. MAC address
    trans = 'EC:08:6B:46:FE:30'         # Transmitter/Source MAC address  
    bssid = 'FF:FF:FF:FF:FF:FF'         # BSSID MAC address     
    iface = 'wlan0'                     # Wireless interface name 
    channel = '1'                       # Wireless channel
    interval = '0.01'                   # Scapy interval

    # Accept Command Line Arguments
    try:
        client = sys.argv[1]
        trans = sys.argv[2]
        bssid = sys.argv[3]
        iface = sys.argv[4]
        channel = sys.argv[5]
        interval = sys.argv[6]
    except:
        pass

#################################################
    
    # Create Frame
    ssid_parameters = Dot11Elt(ID="SSID", info="\x4f\x4f\x4f\x4f\x4f")
    supported_rates = '\x01\x08\x82\x84\x0b\x16\x0c\x12\x18\x24'
    extended_supported_rates = '\x32\x08\x0c\x12\x18\x24\x30\x48\x60\x6c' #'\x32\x04\x30\x48\x60\x6c'
    ht_capabilities = '\x2d\x1a\x2f\x01\x1f\xff\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    extended_capabilities = '\x7f\x09\x04\x00\x0a\x02\x01\x00\x00\x40\x80'
    packet = RadioTap()/Dot11(type=0, subtype=4, FCfield=0x00,addr1=client, addr2=trans, addr3=bssid)/Dot11ProbeReq()/ssid_parameters/supported_rates \
        /extended_supported_rates/ht_capabilities/extended_capabilities

    # Set Monitor Mode and Channel
    os.system("sudo ifconfig " + iface + " down") 
    os.system("sudo iwconfig " + iface + " mode monitor") 
    os.system("sudo ifconfig " + iface + " up") 
    os.system("sudo iwconfig " + iface + " channel " + channel) 
	
    # Send Frame  
    sendp(packet, iface=iface, inter=float(interval), loop=1)


