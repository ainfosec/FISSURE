from scapy.all import ICMP,LLC,SNAP,IP
import socket
import time
import sys

#################################################
############ Default FISSURE Header #############
#################################################
def getArguments():
    source_ip = "192.168.1.1"
    dest_ip = "192.168.1.5"
    icmp_type = 8
    icmp_code = 0
    icmp_id = 0
    icmp_seq = 0   
    icmp_data = "8681000000000000101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F3031323334353637" 
    interval = .1
    wifi_tx_udp_port = 52001
    wifi_tx_ip_address = "127.0.0.1"
    notes = 'Generates ICMP messages. Messages are placed in UDP data and sent to a wifi_tx.py UDP port.'
    arg_names = ['source_ip','dest_ip','icmp_type','icmp_code','icmp_id','icmp_seq','icmp_data','interval','wifi_tx_udp_port','wifi_tx_ip_address','notes']
    arg_values = [source_ip, dest_ip, icmp_type, icmp_code, icmp_id, icmp_seq, icmp_data, interval, wifi_tx_udp_port, wifi_tx_ip_address, notes]

    return (arg_names,arg_values)


if __name__ == "__main__":

    # Default Values
    get_source_ip = "192.168.1.1"
    get_dest_ip = "192.168.1.5"
    get_icmp_type = 8
    get_icmp_code = 0
    get_icmp_id = 0
    get_icmp_seq = 0  
    get_icmp_data = "8681000000000000101112131415161718191A1B1C1D1E1F202122232425262728292A2B2C2D2E2F3031323334353637"   
    get_interval = .1
    get_wifi_tx_udp_port = 52001
    get_wifi_tx_ip_address = "127.0.0.1"

    # Accept Command Line Arguments
    try:
        get_source_ip = sys.argv[1]
        get_dest_ip = sys.argv[2]
        get_icmp_type = int(sys.argv[3])
        get_icmp_code = int(sys.argv[4])
        get_icmp_id = int(sys.argv[5])
        get_icmp_seq = int(sys.argv[6])
        get_icmp_data = sys.argv[7]
        get_interval = float(sys.argv[8])
        get_wifi_tx_udp_port = int(sys.argv[9])
        get_wifi_tx_ip_address = sys.argv[10]
    except:
        pass

#################################################

    # LLC/SNAP/ARP Message in UDP Data -> "wifi_tx.py" Port
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # LLC/SNAP/IP/ICMP
    pip_bytes = LLC()/SNAP()/IP()/ICMP()
    pip_bytes[IP].src = get_source_ip
    pip_bytes[IP].dst = get_dest_ip
    pip_bytes[ICMP].type = get_icmp_type
    pip_bytes[ICMP].code = get_icmp_code
    pip_bytes[ICMP].id = get_icmp_id
    pip_bytes[ICMP].seq = get_icmp_seq 
    
    if get_icmp_data == "-1":
        pip_bytes_formatted = str(pip_bytes)
    else:
        pip_bytes_formatted = str(pip_bytes/(get_icmp_data.decode('hex')))
    
    
    while True:
        udp_socket.sendto(pip_bytes_formatted,(get_wifi_tx_ip_address, get_wifi_tx_udp_port))      
        time.sleep(get_interval)


