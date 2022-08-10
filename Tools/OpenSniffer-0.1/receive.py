#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
#  @ File:
#   receive.py
#  
#  @ Brief:
#   This script shows how to use opensniffer python module to receive data
#   * Your lan IP must be set to 10.10.10.1
#
#  Copyright 2015 Sewio networks

# Import everything from opensniffer module
from opensniffer import *

# Main
def main():
    
    # Create opensniffer class object (use sniffer string coded IP address as parameter)
    sniffer = OpenSniffer('10.10.10.2')
    
    # Print sniffer IP address
    print '\nSniffer IP\n-> ' + sniffer.IP
    # Print sniffer MAC address
    print '\nSniffer MAC\n-> ' + sniffer.MAC
    # Print sniffer FW version
    print '\nSniffer FW\n-> ' + sniffer.FW
    
    # Set band to listen on (bands are defined globally in module)
    sniffer.setBand(ISM2420)
    
    # Read bytes (this method is non blocking and returns up to passed number or bytes from socket, returns '' when socket is empty)
    data = sniffer.readBytes(1024).encode('hex')
    # Print out
    print '\nReceived\n-> ' + str(data)
    
    # Return
    return 0

# Call main
if __name__ == '__main__':
    # Jump to main
    main()
