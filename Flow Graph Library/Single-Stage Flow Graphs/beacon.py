from scapy.all import Dot11,Dot11Beacon,Dot11Elt,RadioTap,sendp
import os, sys

#################################################
############ Default FISSURE Header #############
#################################################
def getArguments():
    dst_mac_addr = 'FF:FF:FF:FF:FF:FF'  # Destination MAC address
    src_mac_addr = 'AA:BB:CC:12:34:56'  # Source MAC address  
    netSSID = 'testSSID'                # Network name
    iface = 'wlan0'	                    # Wireless interface name 
    channel = '1'                       # Wireless channel
    interval = 0.01                     # Scapy interval
    notes = 'Generates the same Scapy beacon continuously.'

    arg_names = ['dst_mac_addr','src_mac_addr','netSSID','iface','channel','interval','notes']
    arg_values = [dst_mac_addr, src_mac_addr, netSSID, iface, channel, interval, notes]

    return (arg_names,arg_values)


if __name__ == "__main__":

    # Default Values
    dst_mac_addr = 'FF:FF:FF:FF:FF:FF'  # Destination MAC address
    src_mac_addr = 'AA:BB:CC:12:34:56'  # Source MAC address  
    netSSID = 'testSSID'                # Network name
    iface = 'wlx00c0ca956682'	                    # Wireless interface name 
    channel = '1'                       # Wireless channel
    interval = 0.01                     # Scapy interval

    # Accept Command Line Arguments
    try:
        dst_mac_addr = sys.argv[1]
        src_mac_addr = sys.argv[2]
        netSSID = sys.argv[3]
        iface = sys.argv[4]
        channel = sys.argv[5]
        interval = sys.argv[6]
    except:
        pass

#################################################
    
    # Construct Frame
    ap_mac_addr = src_mac_addr          # Access Point MAC address
    
    dot11 = Dot11(type=0, subtype=8, FCfield=0x00, addr1=dst_mac_addr, addr2=src_mac_addr, addr3=ap_mac_addr)
    beacon = Dot11Beacon(cap='ESS+privacy')
    essid = Dot11Elt(ID='SSID',info=netSSID, len=len(netSSID))
    rsn = Dot11Elt(ID='RSNinfo', info=(
    '\x01\x00'                          # RSN Version 1
    '\x00\x0f\xac\x02'                  # Group Cipher Suite : 00-0f-ac TKIP
    '\x02\x00'                          # 2 Pairwise Cipher Suites (next two lines)
    '\x00\x0f\xac\x04'                  # AES Cipher
    '\x00\x0f\xac\x02'                  # TKIP Cipher
    '\x01\x00'                          # 1 Authentication Key Managment Suite (line below)
    '\x00\x0f\xac\x02'                  # Pre-Shared Key
    '\x00\x00'))                        # RSN Capabilities (no extra capabilities)

    # Vendor Data
    vendor_tag_number = '\xdd'
    vendor_length = '\x08'              # Bytes after length field
    vendor_oui = '\x00\x02\x9a'
    vendor_oui_type = '\x01'
    vendor_subtype = '\x04'
    vendor_data = 3 * '\xfe'
    vendor = vendor_tag_number + vendor_length + vendor_oui + vendor_oui_type + vendor_subtype + vendor_data
    
    # Assemble Frame
    frame = RadioTap()/dot11/beacon/essid/rsn/vendor
    
    # Set Monitor Mode and Channel
    os.system("sudo ifconfig " + iface + " down") 
    os.system("sudo iwconfig " + iface + " mode monitor") 
    os.system("sudo ifconfig " + iface + " up") 
    os.system("sudo iwconfig " + iface + " channel " + channel) 
	
    # Send Frame  
    sendp(frame, iface=iface, inter=float(interval), loop=1)

