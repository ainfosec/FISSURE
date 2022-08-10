#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
#  @ File:
#   send.py
#  
#  @ Brief:
#   This script shows how to use opensniffer python module to send data
#   * Your lan IP must be set to 10.10.10.1
#
#  Copyright 2015 Sewio networks

# Import everything from opensniffer module
from opensniffer import *
import sys

# Main
def main():
    
    # Variables
    repeat = sys.argv[2]
    payload = str(sys.argv[1])
    
    # Create opensniffer class object (use sniffer string coded IP address as parameter)
    sniffer = OpenSniffer('10.10.10.2')
    
    # Print sniffer IP address
    print('\nSniffer IP\n-> ' + sniffer.IP)
    # Print sniffer MAC address
    print('\nSniffer MAC\n-> ' + sniffer.MAC)
    # Print sniffer FW version
    print('\nSniffer FW\n-> ' + sniffer.FW)
    
    # Inject (takes band, repeat[how many times to send payload], payload[what to send as hexcoded string] as parameters)
    sniffer.injectBytes(ISM2475, repeat, payload)
    # Print out
    print('\nInjecting\n-> ' + payload)
    
    # Return
    return 0

# Call main
if __name__ == '__main__':
    # Jump to main
    main()
