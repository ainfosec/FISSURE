from scapy.all import IP,UDP,LLC,SNAP,repr_hex
import socket
import time
import sys
import os

#################################################
############ Default FISSURE Header #############
#################################################
def getArguments():
    filepath = ''
    interval = .1
    wifi_tx_udp_port = 52001
    wifi_tx_ip_address = "127.0.0.1"
    notes = 'Sends raw binary data to wifi_tx UDP port.'
    arg_names = ['filepath','interval','wifi_tx_udp_port','wifi_tx_ip_address','notes']
    arg_values = [filepath, interval, wifi_tx_udp_port, wifi_tx_ip_address, notes]

    return (arg_names,arg_values)


if __name__ == "__main__":

    # Default Values
    get_filepath = ''
    get_interval = .1
    get_wifi_tx_udp_port = 52001
    get_wifi_tx_ip_address = "127.0.0.1"

    # Accept Command Line Arguments
    try:
        get_filepath = sys.argv[1]
        get_interval = float(sys.argv[2])
        get_wifi_tx_udp_port = int(sys.argv[3])
        get_wifi_tx_ip_address = sys.argv[4]
    except:
        pass

#################################################

    if len(get_filepath) > 0:
        # LLC/SNAP/IP/UDP Message in UDP Data -> "wifi_tx.py" Port
        udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
        number_of_bytes = os.path.getsize(get_filepath)
        file = open(get_filepath,"rb")                          # Open the file    
        transfer_data = file.read()  
        final_bytes = str(transfer_data)  
        file.close()
        
        # Send File Data
        while True:
            udp_socket.sendto(final_bytes,(get_wifi_tx_ip_address, get_wifi_tx_udp_port))
            #udp_socket.sendto(binascii.unhexlify(bsm_payload_formatted),(get_wifi_tx_ip_address, get_wifi_tx_udp_port))
            time.sleep(get_interval)


    else:
        print "Invalid File Selected"
