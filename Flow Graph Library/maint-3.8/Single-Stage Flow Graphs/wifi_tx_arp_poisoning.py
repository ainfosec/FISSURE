from scapy.all import ARP,LLC,SNAP
import socket
import time
import sys

#################################################
############ Default FISSURE Header #############
#################################################
def getArguments():
    hwtype = "1"
    ptype = "2048"
    hwlen = "6"
    plen = "4"
    op = "1"
    hwsrc = "00:11:22:aa:bb:cc"
    psrc = "192.168.1.5"
    hwdst = "b4:fb:e4:3e:bc:d4"
    pdst = "192.168.1.10"
    interval = .1
    wifi_tx_udp_port = 52001
    wifi_tx_ip_address = "127.0.0.1"
    ignore1 = '5'
    ignore2 = '-1'
    single_ip = 'off'
    notes = 'Generates ARP messages that continuously cycle through the last octet of the source IP address. Messages are placed in UDP data and sent to a wifi_tx.py UDP port.'
    arg_names = ['hwtype','ptype','hwlen','plen','op','hwsrc','psrc','hwdst','pdst','interval','wifi_tx_udp_port','wifi_tx_ip_address','ignore1','ignore2','single_ip','notes']
    arg_values = [hwtype, ptype, hwlen, plen, op, hwsrc, psrc, hwdst, pdst, interval, wifi_tx_udp_port, wifi_tx_ip_address, ignore1, ignore2, single_ip, notes]

    return (arg_names,arg_values)


if __name__ == "__main__":

    # Default Values
    get_hwtype = "1"
    get_ptype = "2048"
    get_hwlen = "6"
    get_plen = "4"
    get_op = "1"
    get_hwsrc = "00:11:22:aa:bb:cc"
    get_psrc = "192.168.1.5"
    get_hwdst = "b4:fb:e4:3e:bc:d4"
    get_pdst = "192.168.1.10"
    get_interval = .1
    get_wifi_tx_udp_port = 52001
    get_wifi_tx_ip_address = "127.0.0.1"
    get_ignore1 = '5' 
    get_ignore2 = '-1'
    get_single_ip = 'off'

    # Accept Command Line Arguments
    try:
        get_hwtype = sys.argv[1]
        get_ptype = sys.argv[2]
        get_hwlen = sys.argv[3]
        get_plen = sys.argv[4]
        get_op = sys.argv[5]
        get_hwsrc = sys.argv[6]
        get_psrc = sys.argv[7]
        get_hwdst = sys.argv[8]
        get_pdst = sys.argv[9]        
        get_interval = float(sys.argv[10])
        get_wifi_tx_udp_port = int(sys.argv[11])
        get_wifi_tx_ip_address = sys.argv[12]
        get_ignore1 = int(sys.argv[13])
        get_ignore2 = int(sys.argv[14])
        get_single_ip = sys.argv[15]
    except:
        pass

#################################################

    # LLC/SNAP/ARP Message in UDP Data -> "wifi_tx.py" Port
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # LLC/SNAP/ARP
    pip_bytes = LLC()/SNAP()    
    
    pip_arp_bytes = ARP()
    pip_arp_bytes[ARP].hwtype = int(get_hwtype) & 0xFF
    pip_arp_bytes[ARP].ptype = int(get_ptype) & 0xFFF
    pip_arp_bytes[ARP].hwlen = int(get_hwlen)
    pip_arp_bytes[ARP].plen = int(get_plen)
    pip_arp_bytes[ARP].op = int(get_op)
    pip_arp_bytes[ARP].hwsrc = get_hwsrc
    pip_arp_bytes[ARP].psrc = get_psrc
    pip_arp_bytes[ARP].hwdst = get_hwdst
    pip_arp_bytes[ARP].pdst = get_pdst
    

    if get_ignore1 > 255:
        get_ignore1 = -1
        
    if get_ignore2 > 255:
        get_ignore2 = -1
    
    while True:
        for n in range(0,256):
            
            if n != get_ignore1 or n != get_ignore2:
                if str(get_single_ip) in "off":
                    pip_arp_bytes[ARP].psrc = ".".join(get_psrc.split(".", 3)[:-1]) + '.' + str(n)
                                    
                if int(pip_arp_bytes[ARP].psrc.split(".", 3)[-1]) != get_ignore1 and int(pip_arp_bytes[ARP].psrc.split(".", 3)[-1]) != get_ignore2:
                    pip_bytes_formatted = str(pip_bytes/pip_arp_bytes)  

                    udp_socket.sendto(pip_bytes_formatted,(get_wifi_tx_ip_address, get_wifi_tx_udp_port))      
                    time.sleep(get_interval)


