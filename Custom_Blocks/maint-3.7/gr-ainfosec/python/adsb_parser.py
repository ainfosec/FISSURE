#!/usr/bin/env python
# -*- coding: utf-8 -*-
# 
# Copyright 2022 <+YOU OR YOUR COMPANY+>.
# 
# This is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3, or (at your option)
# any later version.
# 
# This software is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this software; see the file COPYING.  If not, write to
# the Free Software Foundation, Inc., 51 Franklin Street,
# Boston, MA 02110-1301, USA.
# 

import numpy
from gnuradio import gr
import pmt
import socket

class adsb_parser(gr.basic_block):
    """
    docstring for block adsb_parser
    """
    def __init__(self, port):
        gr.basic_block.__init__(self,
            name="adsb_parser",
            in_sig=[],
            out_sig=[])

        # Create UDP Socket
        self.udp_port = port
        self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            
        self.message_port_register_in(pmt.intern("Decoded PDU"))
        self.set_msg_handler(pmt.intern("Decoded PDU"), self.handle_msg)


        
    def handle_msg(self, msg):
        """ Converts the PDU of formatted ADS-B bits to bytes.
        """
        # Convert PDU to Bytes
        print("HANDLE MESSAGE")
        #print(msg)
        
        #print(pmt.car(msg))  # ((snr . 20.2942) (df . 17) (icao . a8fc72) (datetime . 2022-09-20 03:21:13.546551 UTC) (timestamp . 1.66364e+09) (num_msgs . 1) (longitude . nan) (latitude . nan) (vertical_rate . nan) (heading . nan) (speed . nan) (altitude . nan) (callsign . UAL599  ))
                        
        a = pmt.serialize_str(pmt.cdr(msg))  # bytes
        #b = str(pmt.serialize_str(pmt.cdr(msg)).hex())  # string
        b = str(pmt.serialize_str(pmt.cdr(msg)).encode('hex'))  # string
        
        c = b.split('70')[1]  # 010001000000010100010100010001000000010101010101000000010101000001000000010000000101000100010001000000000001000001010000010100010001010101000001010101000001010000000000010000000000010001010000010001010001010100000001010101010000
        
        d = c[1::2]  # 101000110110101000111111000111001000100011010101000001001100110101111001111001100000100000101100101101110001111100
        
        #print(d)
    
        # Add Excess Bits
        if len(d) % 8 != 0:
            e = d + '0' * (8 - len(d) % 8)

        # Print Bytes to Output Port    
        data_hex = ('%0*X' % (2, int(e, 2))).zfill(len(e) // 4)        
        
        # Send Message
        self.udp_socket.sendto(data_hex.decode('hex'),("127.0.0.1", self.udp_port))
