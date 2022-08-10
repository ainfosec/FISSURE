from scapy.all import IP,UDP,LLC,SNAP,repr_hex
import socket
import time
import sys

#################################################
############ Default FISSURE Header #############
#################################################
def getArguments():
    udp_source_ip = "192.168.1.200"
    udp_dest_ip = "192.168.1.5"
    udp_source_port = "14321"
    udp_dest_port = "55555"
    udp_data = '48657265277320796f757220747261666669632e'
    interval = .1
    wifi_tx_udp_port = 52001
    wifi_tx_ip_address = "127.0.0.1"
    notes = 'Generates UDP messages. Messages are placed in UDP data and sent to a wifi_tx.py UDP port.'
    arg_names = ['udp_source_ip','udp_dest_ip','udp_source_port','udp_dest_port','udp_data','interval','wifi_tx_udp_port','wifi_tx_ip_address','notes']
    arg_values = [udp_source_ip, udp_dest_ip, udp_source_port, udp_dest_port, udp_data, interval, wifi_tx_udp_port, wifi_tx_ip_address, notes]

    return (arg_names,arg_values)


if __name__ == "__main__":

    # Default Values
    get_udp_source_ip = "192.168.1.200"
    get_udp_dest_ip = "192.168.1.5"
    get_udp_source_port = "14321"
    get_udp_dest_port = "55555"
    get_udp_data = '48657265277320796f757220747261666669632e'
    get_interval = .1
    get_wifi_tx_udp_port = 52001
    get_wifi_tx_ip_address = "127.0.0.1"

    # Accept Command Line Arguments
    try:
        get_udp_source_ip = sys.argv[1]
        get_udp_dest_ip = sys.argv[2]
        get_udp_source_port = sys.argv[3]
        get_udp_dest_port = sys.argv[4]
        get_udp_data = sys.argv[5]
        get_interval = float(sys.argv[6])
        get_wifi_tx_udp_port = int(sys.argv[7])
        get_wifi_tx_ip_address = sys.argv[8]
    except:
        pass

#################################################

    # LLC/SNAP/IP/UDP Message in UDP Data -> "wifi_tx.py" Port
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # LLC/SNAP/IP/UDP
    pip_bytes = LLC()/SNAP()/IP()/UDP()
    pip_bytes[IP].src = get_udp_source_ip
    pip_bytes[IP].dst = get_udp_dest_ip
    pip_bytes[IP].id = 0x0000
    pip_bytes[IP].flags = 2
    pip_bytes[UDP].sport = int(get_udp_source_port)
    pip_bytes[UDP].dport = int(get_udp_dest_port)
    pip_udp_data = get_udp_data.replace(" ","").decode('hex')
    pip_bytes = str(pip_bytes/pip_udp_data)  

    while True:
        udp_socket.sendto(pip_bytes,(get_wifi_tx_ip_address, get_wifi_tx_udp_port))
        time.sleep(get_interval)
