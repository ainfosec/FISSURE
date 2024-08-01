import socket
import sys
import base64
from scapy import *

#################################################
############ Default FISSURE Header #############
#################################################
def getArguments():
    server_ip = "172.16.1.150"
    server_port = 55555
    #response_string = b"Sneakin"
    magic = "Beacon"
    notes = "Responds to UDP messages containing the magic string. Observe the responses in Wireshark to map IP addresses and ports. See wifi_tx UDP Mapper."
    
    arg_names = ['server_ip','server_port','magic','notes']
    arg_values = [server_ip,server_port,magic,notes]

    return (arg_names,arg_values)
    
#################################################


#################################################

if __name__ == "__main__":

    # Default Values
    server_ip = "172.16.1.150"
    server_port = 55555
    #response_string = b"Sneakin"
    magic = "Beacon"

    # Accept Command Line Arguments
    try:
        server_ip = sys.argv[1]
        server_port = int(sys.argv[2])
        magic = sys.argv[3]
    except:
        pass

#################################################

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_address = (server_ip, server_port)
    s.bind(server_address)

    while True:
        data, address = s.recvfrom(4096)
        #print(data)
        print(address)
        payload = data.find(bytes(magic)) + len(bytes(magic))
        if payload > -1:
            print("Received Beacon with {}".format(data[payload:len(data)]))
            #print("Recevied Beacon with {}".format(base64.b64decode(data[payload:len(data)]).decode()))
            #s.sendto(response_string, base64.b64decode(data[payload:len(data)]))
            s.sendto(data[payload:len(data)], address)
