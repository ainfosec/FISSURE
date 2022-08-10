import os, sys
import time

#################################################
############ Default FISSURE Header #############
#################################################
def getArguments():
    iface = 'wlan0'	                    # Wireless interface name 
    filepath = ''                       # PCAP Location
    notes = 'Replays the UDP from a .pcap file with udpreplay while connected to a network.'

    arg_names = ['iface','filepath','notes']
    arg_values = [iface,filepath,notes]

    return (arg_names,arg_values)


if __name__ == "__main__":

    # Default Values
    iface = 'wlan0'	                    # Wireless interface name 
    filepath = ''                       # PCAP Location

    # Accept Command Line Arguments
    try:
        iface = sys.argv[1]
        filepath = sys.argv[2]
    except:
        pass

#################################################
        
    # Do the Replay
    print "Executing: udpreplay -i " + iface + ' "' + filepath + '" '
    os.system("udpreplay -i " + iface + ' "' + filepath + '" ')  # Needs quotes for filepaths with spaces
    print "Finished"
    time.sleep(2)

