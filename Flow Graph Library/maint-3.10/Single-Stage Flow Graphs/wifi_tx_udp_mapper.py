#!/usr/bin/python2
from scapy.all import *
import base64
import time


#################################################
############ Default FISSURE Header #############
#################################################
def getArguments():
    server_ip = "172.16.1.150"
    server_port = 55555
    magic = "Beacon"
    scanned_port = 1
    scanned_sub = "192.168.1."
    scanned_sub_start = 0
    scanned_sub_end = 255
    wifi_tx_udp_port = 52001
    wifi_tx_ip_address = "127.0.0.1"
    wifi_tx_repeat = 1
    interval = 0.05
    notes = "Transmits LLC/SNAP/IP/UDP data to wifi_tx with the server as the source to map a network for IP addresses and ports."
    
    arg_names = ['server_ip','server_port','magic','scanned_port','scanned_sub','scanned_sub_start','scanned_sub_end','wifi_tx_udp_port','wifi_tx_ip_address','wifi_tx_repeat','interval','notes']
    arg_values = [server_ip,server_port,magic,scanned_port,scanned_sub,scanned_sub_start,scanned_sub_end,wifi_tx_udp_port,wifi_tx_ip_address,wifi_tx_repeat,interval,notes]

    return (arg_names,arg_values)
    
#################################################

#################################################

if __name__ == "__main__":

    # Default Values
    server_ip = "172.16.1.150"
    server_port = 55555
    magic = "Beacon"
    scanned_port = 1
    scanned_sub = "192.168.1."
    scanned_sub_start = 0
    scanned_sub_end = 255
    wifi_tx_udp_port = 52001
    wifi_tx_ip_address = "127.0.0.1"
    wifi_tx_repeat = 1
    interval = 0.05

    # Accept Command Line Arguments
    try:
        server_ip = sys.argv[1]
        server_port = int(sys.argv[2])
        magic = sys.argv[3]
        scanned_port = int(sys.argv[4])
        scanned_sub = sys.argv[5]
        scanned_sub_start = int(sys.argv[6])
        scanned_sub_end = int(sys.argv[7])
        wifi_tx_udp_port = int(sys.argv[8])
        wifi_tx_ip_address = sys.argv[9]
        wifi_tx_repeat = int(sys.argv[10])
        interval = float(sys.argv[11])
    except:
        pass

#################################################
     
    # LLC/SNAP/IP/UDP Message in UDP Data -> "wifi_tx.py" Port
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        
    # LLC/SNAP/IP/UDP
    pip_bytes = LLC()/SNAP()/IP()/UDP()    
    pip_bytes[IP].proto = 17
    pip_bytes[IP].flags = 2  
    #pip_bytes[IP].id = 0x0000
    pip_bytes[IP].dst = server_ip
    pip_bytes[UDP].dport = server_port
    pip_bytes[UDP].sport = scanned_port

    for octe in range(scanned_sub_start, scanned_sub_end+1):
        print("Sending: " + scanned_sub + str(octe))
        pip_bytes[IP].src = scanned_sub + str(octe)
        #dat = Raw(load=magic + (bytes(scanned_sub) + bytes(str(octe))).encode('base64'))
        dat = Raw(load=magic + (bytes(scanned_sub) + bytes(str(octe))))
        pip_bytes2 = str(pip_bytes/dat)
        print(pip_bytes2)  
       
        # Send to wifi_tx Flow Graph Port
        for r in range(0,wifi_tx_repeat):
            udp_socket.sendto(pip_bytes2,(wifi_tx_ip_address, wifi_tx_udp_port)) 
            time.sleep(interval)
        
    print("Done")
