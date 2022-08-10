from scapy.all import Dot11Beacon,Dot11Elt,Dot11FCS
import socket
import time
import sys

#################################################
############ Default FISSURE Header #############
#################################################
def getArguments():
    ssid = "TEST"
    mac_address = "23:23:23:23:23:23"  
    interval = .1
    wifi_tx_udp_port = 52001
    wifi_tx_ip_address = "127.0.0.1"
    notes = 'Generates Beacon frames with a custom SSID and MAC address. Beacon data is sent to the wifi_tx.py UDP port which needs to be connected to the mac_in of the WiFi PHY Hier block.'
    arg_names = ['ssid','mac_address','interval','wifi_tx_udp_port','wifi_tx_ip_address','notes']
    arg_values = [ssid, mac_address, interval, wifi_tx_udp_port, wifi_tx_ip_address, notes]

    return (arg_names,arg_values)


if __name__ == "__main__":

    # Default Values
    get_ssid = "TEST"
    get_mac_address = "23:23:23:23:23:23"  
    get_interval = .1
    get_wifi_tx_udp_port = 52001
    get_wifi_tx_ip_address = "127.0.0.1"

    # Accept Command Line Arguments
    try:
        get_ssid = sys.argv[1]
        get_mac_address = sys.argv[2]
        get_interval = float(sys.argv[3])
        get_wifi_tx_udp_port = int(sys.argv[4])
        get_wifi_tx_ip_address = sys.argv[5]
    except:
        pass

#################################################

    # Beacon Data -> "wifi_tx.py" Port -> mac_in of WiFi PHY Hier block
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
    # Craft Beacon Frame
    frame = Dot11FCS(addr1='ff:ff:ff:ff:ff:ff', addr2=get_mac_address, addr3=get_mac_address)/Dot11Beacon()/Dot11Elt(ID='SSID', info=get_ssid)
    
    # Send
    while True:
        udp_socket.sendto(bytes(frame),(get_wifi_tx_ip_address, get_wifi_tx_udp_port))      
        time.sleep(get_interval)


