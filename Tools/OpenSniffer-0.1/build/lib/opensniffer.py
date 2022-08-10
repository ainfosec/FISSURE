#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#  
#  @name:
#   opensniffer.py
#
#  @brief: 
#   this is a python opensniffer python module from sewio, serves as an
#   API that that can help automate communication and setup of opensniffer
#
#  Copyright 2015 lego

# Imports ==============================================================
import socket
import urllib3
import array
import sys
import time
import os
import os.path
import subprocess

# Bands ================================================================
    
# Chinese bands
CHINA780 = 'chn=128&modul=1c'
CHINA782 = 'chn=129&modul=1c'
CHINA784 = 'chn=130&modul=1c'
CHINA786 = 'chn=131&modul=1c'
# European band
EUROPE868 = 'chn=0&modul=0'
# American band
AMERICA906 = 'chn=1&modul=4'
AMERICA908 = 'chn=2&modul=4'
AMERICA910 = 'chn=3&modul=4'
AMERICA912 = 'chn=4&modul=4'
AMERICA914 = 'chn=5&modul=4'
AMERICA916 = 'chn=6&modul=4'
AMERICA918 = 'chn=7&modul=4'
AMERICA920 = 'chn=8&modul=4'
AMERICA922 = 'chn=9&modul=4'
AMERICA924 = 'chn=10&modul=4'
# ISM2.4GHZ band
ISM2405 = 'chn=11&modul=0'
ISM2410 = 'chn=12&modul=0'
ISM2415 = 'chn=13&modul=0'
ISM2420 = 'chn=14&modul=0'
ISM2425 = 'chn=15&modul=0'
ISM2430 = 'chn=16&modul=0'
ISM2435 = 'chn=17&modul=0'
ISM2440 = 'chn=18&modul=0'
ISM2445 = 'chn=19&modul=0'
ISM2450 = 'chn=20&modul=0'
ISM2455 = 'chn=21&modul=0'
ISM2460 = 'chn=22&modul=0'
ISM2465 = 'chn=23&modul=0'
ISM2470 = 'chn=24&modul=0'
ISM2475 = 'chn=25&modul=0'
ISM2480 = 'chn=26&modul=0'

# Initilization ========================================================
http = urllib3.PoolManager()
# Create socket (AF_INET -> IPV4, SOCK_GGRAM -> UDP)
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
# Make socket non blocking 
sock.setblocking(0)
# Bind socket
try:
    # Use subprocess process open to call  netsh to retrieve IP address for LAN controller, redirect stdout to pipe
    #proc = subprocess.Popen('netsh interface ip show addresses "Local Area Connection"', stdout=subprocess.PIPE)
    # Read process pipe, so we get LAN controller configuration
    #output = proc.stdout.read()
    # Parse beginning of the IP Address from output
    #indexBeg = output.find('IP Address:') + 38
    # Parse end of the IP Address from output
    #indexEnd = output.find('Subnet Prefix:') - 6
    # Retrieve address from output
    address = '10.10.10.2'
    # Try to bind to that address
    sock.bind((address, 17754))
except:
    # Else notify user of failure
    print('ERR: Bind to socket failed')
    
# Functions ============================================================

# Open sniffer class ===================================================
class OpenSniffer:
    
    # Constructor, takes IP address as parameter
    def __init__(self, address):
        try:
            # Set address
            self.IP = address
            # Gets MAC address and FW version
            self.getInfo()
        except:
            # Else notify user of failure
            print('ERR: Unable to obtain sniffer data, make sure IP address is correct')
            # And exit
            return
    
    # Function that gets SLAVE_MAC and SLAVE_FW from website at given SLAVE_ADDR
    def getInfo(self):
        # Create request
        req = http.request("GET", "http://{}/index.shtml".format(self.IP))
        # Open url
        #handler = urllib2.urlopen(req, timeout = 1)
        # Read web page
        data = str(req.data)
        #data = handler.read()
        # Close handler
        #handler.close()
        # Find index of slave IP address
        index = data.find(self.IP)
        # Parse MAC out
        self.MAC = data[index-18:index-1]
        # Find index of parenthesis
        indexEnd = data.find(')',index) - 1
        # Find index of comma before parenthesis
        indexBeg = data[:indexEnd].rindex(',') + 1
        # Handle older websites
        if((len(data[indexBeg:indexEnd]) > 10) or (0 == len(data[indexBeg:indexEnd]))):
            # Find Firmware version on old web
            indexBeg = data.find('Firmware version ') + 17
            # Find end of FW version
            indexEnd = indexBeg + (data[indexBeg:].find('</p>'))
        # Parse FW version out
        self.FW = data[indexBeg:indexEnd]
    
    # Sets the band open sniffer should listen on
    def setBand(self, band):
        # Append address
        REST = "http://{}".format(self.IP)
        # Append channel & modulation
        REST += "/settings.cgi?{}".format(band)
        # Append rest of the REST msg
        REST += "&rxsens=3&crcfilter=1&crcmode=0"
        # Create request
        req = urllib2.request("GET", REST)
        # Actually open url
        try:
            # Set timeout 
            urllib2.urlopen(req, timeout = 2)
        # In case of any errors are found notify user, and return false
        except:
            # Notify user
            print('ERR: Unable to communicate with sniffer')
            # Return error value
            return False
        
        # Return AOK value
        return True
            
    # Injection REST msg generator
    def injectBytes(self, band, repeat=100, payload='010203'):
        # Append address
        REST = "http://{}".format(self.IP)
        # Append channel & modulation
        REST += "/inject.cgi?{}".format(band)
        # Append repeat time, txlevel etc.
        REST += "&txlevel=0&rxen=0&nrepeat={}&tspace=1&autocrc=1".format(str(repeat))
        # Append payload
        REST += "&spayload={}&len={}".format(payload, str(len(payload)/2))
        # Create request
        req = http.request("GET", "{}".format(REST))
        # Actually open url
        try:
            # Set timeout 
            http.urlopen(req, timeout = 2)
        # In case of any errors are found return false
        except:
            # Set overall pass fail
            self.PASS = 0
            # Notify user
            print('ERR: Unable to communicate with sniffer')
            # Return error value
            return False
        
        # Return AOK value if no errors were detected
        return True
    
    # Retrieves what's in socket
    def readBytes(self, num):
        # So that python knows we mean global variable
        global sock
        # Buffer
        buf = ''
        # Blocking right now
        try:
            # Read as much as you can before timing out
            buf = sock.recv(num)
            # Return buffer
            return buf
        except:
            # In case of timeout return empty string
            return ''
    
    # Flashes selected binary using LMFlasher via ethernet
    def flashViaEthernet(self, fw):
        # Notify user
        print('\r\n---------- FLASHING (ETH) [' + str(fw) + '] ----------\n')
        # See whether binary file exists
        if (os.path.isfile(fw) == False):
            # Set result
            result = 'FAILED'
            # Notify user
            print('\tUnable to locate ' + fw )
        # If it does
        else:
            # Try to call LMFlash
            try:
                # Get LMFlasher EXE path
                LMPath = r'C:\Program Files (x86)\Texas Instruments\Stellaris\LM Flash Programmer\\'
                # Asseble command line command
                LMEthCmd = 'LMFlash.exe -i ethernet -n 10.10.10.1,' + self.IP + ',' + self.MAC + ' ' + str(fw)
                # Call LMFlasher
                proc = subprocess.call(LMPath + LMEthCmd)
                # Add line
                print('\r\n\nResetting...\r\n')
                # Wait for sniffer to reboot properly
                time.sleep(4)
                # Update SLAVE data
                self.getInfo()
            # Handle error
            except:
                raise
                # Notify user
                print('\tERR: Unable to locate LMFlash.exe')
            # Use process handle to determine whether it succeeded
            if(proc == 0):
                result = 'DONE'
            # Or not
            else:
                result = 'FAILED'
        # Notify user
        print('\r\n---------- FLASHING ' + result + ' ----------\n')

# Class end ============================================================
    
