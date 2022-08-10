from scapy.all import IP,UDP,LLC,SNAP,repr_hex
import socket
import time
import sys
import os

#################################################
############ Default FISSURE Header #############
#################################################
def getArguments():
    udp_source_ip = "192.168.1.200"
    udp_dest_ip = "192.168.1.5"
    udp_source_port = "14321"
    udp_dest_port = "55555"
    filepath = ''
    interval = .1
    mtu = 1000
    wifi_tx_udp_port = 52001
    wifi_tx_ip_address = "127.0.0.1"
    notes = 'Reads in bytes of data and puts it in a UDP payload. Messages are placed in UDP data and sent to a wifi_tx.py UDP port.'
    arg_names = ['udp_source_ip','udp_dest_ip','udp_source_port','udp_dest_port','filepath','interval','mtu','wifi_tx_udp_port','wifi_tx_ip_address','notes']
    arg_values = [udp_source_ip, udp_dest_ip, udp_source_port, udp_dest_port, filepath, interval, mtu, wifi_tx_udp_port, wifi_tx_ip_address, notes]

    return (arg_names,arg_values)


if __name__ == "__main__":

    # Default Values
    get_udp_source_ip = "192.168.1.200"
    get_udp_dest_ip = "192.168.1.5"
    get_udp_source_port = "14321"
    get_udp_dest_port = "55555"
    get_filepath = ''
    get_interval = .1
    get_mtu = 1000
    get_wifi_tx_udp_port = 52001
    get_wifi_tx_ip_address = "127.0.0.1"

    # Accept Command Line Arguments
    try:
        get_udp_source_ip = sys.argv[1]
        get_udp_dest_ip = sys.argv[2]
        get_udp_source_port = sys.argv[3]
        get_udp_dest_port = sys.argv[4]
        get_filepath = sys.argv[5]
        get_interval = float(sys.argv[6])
        get_mtu = int(sys.argv[7])
        get_wifi_tx_udp_port = int(sys.argv[8])
        get_wifi_tx_ip_address = sys.argv[9]
    except:
        pass

#################################################

    if len(get_filepath) > 0:
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
        
        number_of_bytes = os.path.getsize(get_filepath)
        file = open(get_filepath,"rb")                          # Open the file    
        
        # Send File Data
        for n in range(0, number_of_bytes, get_mtu):
            file.seek(n)
            transfer_data = file.read(get_mtu)  
            final_bytes = str(pip_bytes/transfer_data)  
            udp_socket.sendto(final_bytes,(get_wifi_tx_ip_address, get_wifi_tx_udp_port))
            time.sleep(get_interval)

        # Send Last File Read
        file_remainder = number_of_bytes % get_mtu
        transfer_data = file.read(file_remainder)
        final_bytes = str(pip_bytes/transfer_data)
        udp_socket.sendto(final_bytes,(get_wifi_tx_ip_address, get_wifi_tx_udp_port))
        file.close()
        print "File Relay Complete"
    
    else:
        print "Invalid File Selected"
