from scapy.all import ARP,Ether,sendp,RadioTap,LLC,SNAP,IP
import socket
import time
import sys

#################################################
############ Default FISSURE Header #############
#################################################
def getArguments():        
    hwtype = '1'
    ptype = '2048'
    hwlen = '6'
    plen = '4'
    op = '1'
    hwsrc = '00:11:22:aa:bb:cc'
    psrc = '192.168.1.5'
    hwdst = '00:00:00:00:00:00'
    pdst = '192.168.1.1'
    ignore1 = '5'
    ignore2 = '-1'
    iface = ''
    single_ip = 'off'
    notes = 'Generates Scapy ARP messages that continuously cycle through the last octet of the source IP address.'
                
    arg_names = ['hwtype','ptype','hwlen','plen','op','hwsrc','psrc','hwdst','pdst','ignore1','ignore2','iface','single_ip','notes']
    arg_values = [hwtype, ptype, hwlen, plen, op, hwsrc, psrc, hwdst, pdst, ignore1, ignore2, iface, single_ip, notes]

    return (arg_names,arg_values)


if __name__ == "__main__":

    # Default Values
    get_hwtype = '1'
    get_ptype = '2048'
    get_hwlen = '6'
    get_plen = '4'
    get_op = '1'
    get_hwsrc = '00:11:22:aa:bb:cc'
    get_psrc = '192.168.1.58'
    get_hwdst = '00:00:00:00:00:00'
    get_pdst = '192.168.1.10'  
    get_ignore1 = '5' 
    get_ignore2 = '-1'
    get_interface = 'wlx00c0ca956681'
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
        get_ignore1 = int(sys.argv[10])
        get_ignore2 = int(sys.argv[11])
        get_interface = sys.argv[12]
        get_single_ip = sys.argv[13]
        
    except:
        print "ERROR"


#################################################

    arp_bytes = ARP()
    arp_bytes[ARP].hwtype = int(get_hwtype) & 0xFF
    arp_bytes[ARP].ptype = int(get_ptype) & 0xFFF
    arp_bytes[ARP].hwlen = int(get_hwlen)
    arp_bytes[ARP].plen = int(get_plen)
    arp_bytes[ARP].op = int(get_op)
    arp_bytes[ARP].hwsrc = get_hwsrc
    arp_bytes[ARP].psrc = get_psrc
    arp_bytes[ARP].hwdst = get_hwdst
    arp_bytes[ARP].pdst = get_pdst
            
    scapy_data = Ether()/arp_bytes
    
    get_interval = .1
    if get_ignore1 > 255:
        get_ignore1 = -1
    
    #sendp(scapy_data, iface=get_interface, inter=float(get_interval), loop=int(get_loop))

    while True:
        for n in range(0,256):
            if n != get_ignore1 or n != get_ignore2:
                if str(get_single_ip) in "off":
                    arp_bytes[ARP].psrc = ".".join(get_psrc.split(".", 3)[:-1]) + '.' + str(n)
                    #arp_bytes[ARP].psrc = "192.168.1." + str(n)
                print ".".join(get_psrc.split(".", 3)[:-1]) + '.' + str(n)
                scapy_data = Ether()/arp_bytes
                # ip_bytes = IP()
                # ip_bytes[IP].src = "192.168.1.200"
                # ip_bytes[IP].dst = "192.168.1.10"
                # ip_bytes[IP].id = 0x0000
                # ip_bytes[IP].flags = 2
                # scapy_data = RadioTap()/LLC()/SNAP()/ip_bytes/arp_bytes
                sendp(scapy_data, iface=get_interface, loop=0)        
                time.sleep(get_interval)
