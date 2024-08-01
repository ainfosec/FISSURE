from scapy.all import IP,UDP,LLC,SNAP
import socket
import time
import sys
from pcapfile import savefile
import numpy

#################################################
############ Default FISSURE Header #############
#################################################
def getArguments():
    filepath = ''
    udp_source_ip = "192.168.1.4"
    udp_dest_ip = "192.168.1.5"
    interval = .03
    wifi_tx_udp_port = 52001
    wifi_tx_ip_address = "127.0.0.1"
    notes = 'Reads in a .pcap file, not .pcapng, and transmits UDP data line by line to a wifi_tx port with altered UDP addresses.'
    arg_names = ['filepath','udp_source_ip','udp_dest_ip','interval','wifi_tx_udp_port','wifi_tx_ip_address','notes']
    arg_values = [filepath, udp_source_ip, udp_dest_ip, interval, wifi_tx_udp_port, wifi_tx_ip_address, notes]
    

    return (arg_names,arg_values)


if __name__ == "__main__":

    # Default Values
    get_filepath = ''
    get_udp_source_ip = "192.168.1.4"
    get_udp_dest_ip = "192.168.1.5"
    get_interval = .03
    get_wifi_tx_udp_port = 52001
    get_wifi_tx_ip_address = "127.0.0.1"

    # Accept Command Line Arguments
    try:
        get_filepath = str(sys.argv[1])
        get_udp_source_ip = sys.argv[2]
        get_udp_dest_ip = sys.argv[3]
        get_interval = float(sys.argv[4])
        get_wifi_tx_udp_port = int(sys.argv[5])
        get_wifi_tx_ip_address = sys.argv[6]
    except:
        pass

#################################################
    try:
        # Open PCAP File
        if len(get_filepath) > 0:
            testcap = open(get_filepath,'rb')  
            capfile = savefile.load_savefile(testcap,verbose=True)
            pkt = capfile.packets[0]
            testcap.close() 

            # print len(capfile.packets)
            # print pkt.raw()

            # LLC/SNAP/IP/UDP Message in UDP Data -> "wifi_tx.py" Port
            udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

            # LLC/SNAP/IP/UDP
            pip_bytes = LLC()/SNAP()/IP()#/UDP()
            pip_bytes[IP].src = get_udp_source_ip
            pip_bytes[IP].dst = get_udp_dest_ip
            pip_bytes[IP].proto = 17
            #pip_bytes[IP].id = 0x0000
            pip_bytes[IP].flags = 2
            #pip_bytes[UDP].sport = int(get_udp_source_port)
            #pip_bytes[UDP].dport = int(get_udp_dest_port)

            print "crafting packets"
            for n in range(0,len(capfile.packets)):
                print str(n) + "/" + str(len(capfile.packets)-1) + "\n"
                
                # Acquire UDP Data from PCAP
                pip_udp_data = capfile.packets[n].raw()[34:]#[14:]
                #print (capfile.packets[n].raw()[18:20]).encode('hex')
                pip_bytes[IP].id = numpy.frombuffer((capfile.packets[n].raw()[18:20]),numpy.uint16)
                pip_bytes2 = str(pip_bytes/pip_udp_data)  

                # Send to wifi_tx Flow Graph Port
                udp_socket.sendto(pip_bytes2,(get_wifi_tx_ip_address, get_wifi_tx_udp_port))
                time.sleep(get_interval)
            print "done"
            
            time.sleep(2)

    except:
        time.sleep(5)
