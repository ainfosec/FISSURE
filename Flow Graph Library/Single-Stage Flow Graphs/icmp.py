from scapy.all import ICMP,LLC,SNAP,IP,sendp,Dot11,RadioTap
import socket
import time
import sys

#################################################
############ Default FISSURE Header #############
#################################################
def getArguments():
    source_mac = "AA:BB:CC:DD:EE:FF"
    dest_mac = "11:22:33:44:55:66"
    bssid_mac = "AA:BB:CC:DD:EE:FF"
    source_ip = "192.168.1.1"
    dest_ip = "192.168.1.5"
    icmp_type = 8
    icmp_code = 0
    icmp_id = 0
    icmp_seq = 0    
    interval = .1
    iface = ''
    notes = 'Generates a Scapy ICMP packet and transmits it periodically.'
    arg_names = ['source_mac','dest_mac','bssid_mac','source_ip','dest_ip','icmp_type','icmp_code','icmp_id','icmp_seq','interval','iface','notes']
    arg_values = [source_mac, dest_mac, bssid_mac, source_ip, dest_ip, icmp_type, icmp_code, icmp_id, icmp_seq, interval, iface, notes]

    return (arg_names,arg_values)


if __name__ == "__main__":

    # Default Values
    get_source_mac = "AA:BB:CC:DD:EE:FF"
    get_dest_mac = "11:22:33:44:55:66"
    get_bssid_mac = "AA:BB:CC:DD:EE:FF"
    get_source_ip = "192.168.1.1"
    get_dest_ip = "192.168.1.5"
    get_icmp_type = 8
    get_icmp_code = 0
    get_icmp_id = 0
    get_icmp_seq = 0    
    get_interval = .1
    get_interface = ''

    # Accept Command Line Arguments
    try:
        get_source_mac = sys.argv[1]
        get_dest_mac = sys.argv[2]
        get_bssid_mac = sys.argv[3]
        get_source_ip = sys.argv[4]
        get_dest_ip = sys.argv[5]
        get_icmp_type = int(sys.argv[6])
        get_icmp_code = int(sys.argv[7])
        get_icmp_id = int(sys.argv[8])
        get_icmp_seq = int(sys.argv[9])
        get_interval = float(sys.argv[10])
        get_iface = sys.argv[11]
    except:
        pass

#################################################

    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # LLC/SNAP/IP/ICMP
    pip_bytes = RadioTap()/Dot11()/LLC()/SNAP()/IP()/ICMP()
    pip_bytes[Dot11].addr1 = get_dest_mac
    pip_bytes[Dot11].addr2 = get_source_mac
    pip_bytes[Dot11].addr3 = get_bssid_mac
    pip_bytes[Dot11].type = 2
    pip_bytes[Dot11].subtype = 0
    pip_bytes[IP].src = get_source_ip
    pip_bytes[IP].dst = get_dest_ip
    pip_bytes[ICMP].type = get_icmp_type
    pip_bytes[ICMP].code = get_icmp_code
    pip_bytes[ICMP].id = get_icmp_id
    pip_bytes[ICMP].seq = get_icmp_seq 
    
    pip_bytes_formatted = str(pip_bytes)
    
    sendp(pip_bytes_formatted, iface=get_iface, inter=get_interval, loop=1)


