#!/usr/bin/env python
# -*- coding: utf-8 -*-
# 
# Copyright 2021 <+YOU OR YOUR COMPANY+>.
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
import time
import threading
import sys
from binascii import unhexlify
from binascii import b2a_hex
import os

class message_generator_pdu(gr.sync_block):
    """
    From: https://www.rfwireless-world.com/Tutorials/z-wave-MAC-layer.html
    
    HomeID: This field is 4 bytes in length. Z-wave HomeID specifies unique network identifier. All nodes in a z-wave network have the same HomeID. It is assigned by a primary node during inclusion.

    Source Node ID: This field is an 8 bit unique identifier of a node. Along with HomeID, NodeID identifies the node of the originated frame.

    Frame Control: This field is 16 bits in length. This frame control field contains information defining the frame type, addressing fields and other control flags.

    Header type subfield: This field defines different frame type i.e. single cast, multicast, ACK, routed frame etc.

    Length: It is 1 byte size and indicates length of the whole MPDU in bytes. A receiving node does not accept more bytes than the maximum length allowed for the actual data rate.

    Sequence Number: This field is a number provided by higher layers when transmitting. The valid range is 0x00 to 0xFF.

    Destination Node ID: The destination NodeID is used to address individual nodes. 0x00 - (Uninitialized NodeID) 0x01 - 0xE8 (NodeID) 0xE9 - 0xFE (Reserved) 0xFF -(Broadcast NodeID)

    Data Payload: This field is variable size in length. It contains information specific to individual frames. An acknowledgment frame do not have this field.

    FCS: An 8-bit frame checksum is used for checking frame correctness for R1 and R2 data rates at the receiver. This error detection technique will help in finding the erroneous frame and hence will initiate retransmission in the z-wave network.
        
    """
    def __init__(self, repetition_interval, configuration, home_id, source_node_id, frame_control, destination_node_id, command_class, command):
        gr.sync_block.__init__(self,
            name="message_generator_pdu",
            in_sig=None,
            out_sig=None)
        
        self.message_port_register_out(pmt.intern('out'))
        
        # Default Values
        self.repetition_interval = repetition_interval
        self.configuration = configuration
        
        self.home_id = home_id
        self.source_node_id = source_node_id
        self.frame_control = frame_control
        #self.payload_length = payload_length
        self.destination_node_id = destination_node_id
        self.command_class = command_class
        self.command = command
        #self.fcs = fcs
        self.fuzz = 0
        
        # Color List
        self.color_list = ["FF9429","FFC58F","FFD6AA","FFF1E0","FFFAF4","FFFFFB","FFFFFF","C9E2FF","409CFF","FFF4E5","F4FFFA","D4EBFF","FFF4F2","FFEFF7","A600FF","D8F7FF","FFD1B2","F2FCFF","FFB74C"]
        
        # Run in a Thread
        c_thread = threading.Thread(target=self.generateMessage, args=())
        c_thread.daemon = True
        c_thread.start()


    
    def generateMessage(self):
        while True:
            print "GENERATE MESSAGE"          
                   
            # Change Colors on Configuration
            if self.configuration == 2:
                self.newColor(0)
            elif self.configuration == 3:
                self.newColor(1)
            
            # Calculate Length
            self.payload_length = hex(10 + 2 + len(self.command)/2)[2:].zfill(2)  # Home ID until the end of the CRC   
            #print self.payload_length
                        
            # Optional Fuzzing 
            #fbyte = 11     
            #self.command = self.command[:2*fbyte] + hex(self.fuzz)[2:].zfill(2) + self.command[2*fbyte+2:] 
            #self.fuzz1 = self.fuzz + 1
            
            # Assemble the Message 
            get_msg = self.home_id + self.source_node_id + self.frame_control + self.payload_length + self.destination_node_id + self.command_class + self.command
            
            # Calculate the CRC
            get_seed = "1D0F"
            get_input = get_msg
            get_poly = int("1021",16)
            
            # Known Seed
            acc = get_seed
            for n in range(0,len(get_input)/2):
                new_byte = get_input[2*n:2*n+2]                
                acc = self.updateCRC(get_poly, acc, new_byte)  # Poly: 0x1021, Seed: 0x1DOF                
            get_msg = get_msg + acc # 2-byte CRC at the end
            print get_msg
                                                                    
            # Send the PDU
            car = pmt.make_dict()           
            preamble = '55'*25 + 'f0'
            postpad = '00000000'
            #data = preamble + 'f0fa1c0b480141070e02260163222200'  # real data
            #data = preamble + 'f0fa1c0b480141070e022601632222' + post_pad  # real data
            data = preamble + get_msg + postpad 
            hex_len = len(data)
            bin_str = bin(int(data, 16))[2:].zfill(hex_len*4)
            inverted_bits = ''
            for x in bin_str:
                inverted_bits = inverted_bits + x.replace("1", "2").replace("0", "1").replace("2", "0")
            
            # Get Rid of Bits on End
            bit_modulo = len(inverted_bits) % 4
            if bit_modulo != 0:
                inverted_bits = inverted_bits[:-bit_modulo]                
            get_hex = str(('%0*X' % (2,int(inverted_bits,2))).zfill(len(inverted_bits)/4))
            data = unhexlify(get_hex)  # '\x11\x22\x33...'           

            data = bytes(data)         
            data = numpy.frombuffer(data, dtype=numpy.uint8)
            cdr = pmt.to_pmt(data)
            pdu = pmt.cons(car, cdr)            
            
            try:
                self.message_port_pub(pmt.intern('out'), pdu)
            except:
                sys.exit(1)

            # Sleep and Repeat
            time.sleep(self.repetition_interval)

    def updateCRC(self, crc_poly, crc_acc, crc_input):
        """ Calculates CRC for bytes.
        """        
        # Convert Hex Byte String to int
        crc_input_int = int(crc_input,16) 
        crc_acc_int = int(crc_acc,16)
        crc_acc_int = crc_acc_int ^ (crc_input_int << 8)
        for i in range(0,8):
            if (crc_acc_int & 32768) == 32768:
                crc_acc_int = crc_acc_int << 1
                crc_acc_int = crc_acc_int^crc_poly
            else:
                crc_acc_int = crc_acc_int << 1
        
        # Convert to Hex String
        crc_acc = "%0.4X" % crc_acc_int

        # Keep Only the Last 2 Bytes
        crc_acc = crc_acc[-4:]  
        
        return crc_acc
        
    def newColor(self, pattern):
        """ Replaces the data for the Color Switch Set command.
            Component ID | Type
                    0x00 | Warm White
                    0x01 | Cold White
                    0x02 | Red
                    0x03 | Green
                    0x04 | Blue       
        """
        # Common Colors (RGB)
        # Candle 255, 147, 41; 0xFF9429
        # 40W Tungsten 255, 197, 143; 0xFFC58F
        # 100W Tungsten 255, 214, 170; 0xFFD6AA
        # Halogen 255, 241, 224; 0xFFF1E0
        # Carbon Arc 255, 250, 244; 0xFFFAF4
        # High Noon Sun 255, 255, 251; 0xFFFFFB
        # Direct Sunlight 255, 255, 255; 0xFFFFFF
        # Overcast Sky 201, 226, 255; 0xC9E2FF
        # Clear Blue Sky 64, 156, 255; 0x409CFF
        # Warm Fluorescent 255, 244, 229; 0xFFF4E5
        # Standard Fluorescent 244, 255, 250; 0xF4FFFA
        # Cool White Fluorescent 212, 235, 255; 0xD4EBFF
        # Full Spectrum Fluorescent 255, 244, 242; 0xFFF4F2
        # Grow Light Fluorescent 255, 239, 247; 0xFFEFF7
        # Black Light Fluorescent 167, 0, 255; 0xA600FF
        # Mercury Vapor 216, 247, 255; 0xD8F7FF
        # Sodium Vapor 255, 209, 178; 0xFFD1B2
        # Metal Halide 242, 252, 255; 0xF2FCFF
        # High Pressure Sodium 255, 183, 76; 0xFFB74C
        
        # Go Through the List
        if pattern == 0:
            if self.fuzz > len(self.color_list)-1:
                self.fuzz = 0
            self.command = "05050000010002" + self.color_list[self.fuzz][0:2] + "03" + self.color_list[self.fuzz][2:4] + "04" + self.color_list[self.fuzz][4:6]
            self.fuzz = self.fuzz + 1
        
        # Random Color
        else:
            random_6hex = b2a_hex(os.urandom(3))
            self.command = "05050000010002" + random_6hex[0:2] + "03" + random_6hex[2:4] + "04" + random_6hex[4:6]
            
        
