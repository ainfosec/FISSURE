import sys
import os
from scapy.all import Dot11,RadioTap,sendp,rdpcap

program_name = sys.argv[0]
get_interface = sys.argv[1]
get_interval = sys.argv[2]
get_loop = sys.argv[3]

get_packet = rdpcap(os.path.dirname(os.path.dirname(os.path.abspath(__file__))) + "/Crafted Packets/Scapy/temp.cap")
sendp(get_packet[0], iface=get_interface, inter=float(get_interval), loop=int(get_loop))





#for pkt in packet:
    #ls(pkt)
#print "DSFDSF"
#wrpcap("temp.cap",packet)



## Scapy Test

#from scapy.all import Dot11,RadioTap,sendp,ls
#import os

#client = 'ff:ff:ff:ff:ff:ff'        # Receiver/Dest. MAC address
#trans = 'ec:08:6b:46:fe:30'         # Transmitter/Source MAC address 
#bssid = 'ff:ff:ff:ff:ff:ff'         # BSSID MAC address  
#iface = 'wlan0'                     # Wireless interface name 

#category = '\x00'
#action = '\x00'
#element = '\x00'

#packet = RadioTap()/Dot11(type=0, subtype=13, addr1=client, addr2=trans, addr3=bssid)/category/action/element

#print packet[0].show()
#print ls(packet)

##os.system("sudo iwconfig " + iface + " channel 153") 
##sendp(packet, iface=iface, inter=1, loop=1)

 
