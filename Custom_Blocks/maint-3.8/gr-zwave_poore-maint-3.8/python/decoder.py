#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2021 gr-zwave_poore author.
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

class decoder(gr.sync_block):
    """
    docstring for block decoder
    """
    def __init__(self):
        gr.sync_block.__init__(self,
            name="decoder",
            in_sig=[numpy.float32],
            out_sig=[])
            
        self.start_tag = 0
        self.end_tag = 0
        self.if_data = numpy.array([], dtype=numpy.float32)
        self.if_data_list = []
        self.do_analysis = False
        self.message_number = 1
        
        self.message_port_register_out(pmt.intern('out'))
        self.message_port_register_out(pmt.intern('bytes'))
        


    def work(self, input_items, output_items):
        in0 = input_items[0]
        in0_len = len(in0)

        window_start = self.nitems_read(0)

        # Locate Tags
        tags = self.get_tags_in_window(0, 0, in0_len, pmt.string_to_symbol("burst"))
        #if len(tags) > 0:
            #print("Num of tags: " + str(len(tags)))
            #print(in0_len)

        # Tag Exists
        for n in range(0,len(tags)):  #.offset, .key, .value 
            #print(tags[n].value) 
              
            # Get Start Tag Location
            if str(tags[n].value) == "#t":
                self.start_tag = tags[n].offset
                
                # Record on Last Tag in Window
                if n == len(tags)-1:
                    self.if_data = numpy.append(self.if_data, in0[self.start_tag-window_start:])

            # Record on each Stop
            if str(tags[n].value) == "#f":
                self.end_tag = tags[n].offset
                burst_size = self.end_tag - self.start_tag

                # Perfect Size
                if burst_size > 300 and burst_size < 900: 
                    self.do_analysis = True

                    # Multiple Windows
                    if len(self.if_data) > 0:
                        self.if_data = numpy.append(self.if_data, in0[:self.end_tag-window_start])

                    # One Window
                    else:
                        self.if_data = in0[self.start_tag-window_start:self.end_tag-window_start]
                        
                    self.if_data_list.append(self.if_data)
                        
                # Ignore/Reset                
                self.if_data = numpy.array([], dtype=numpy.float32)
                self.start_tag = 0
                self.end_tag = 0

        # Whole Window with no Stop Tag
        if len(tags) == 0 and len(self.if_data) < 900 and len(self.if_data) > 0:
            self.if_data = numpy.append(self.if_data, in0)

        # Do Analysis on all the Data
        if self.do_analysis is True:
            
            #print("DOING ANALYSIS!! " + str(len(self.if_data_list)))
            for n in range(0, len(self.if_data_list)):
                #print(len(self.if_data_list[n]))          

                # Obtain Bitstream
                get_bits = self.getBitstream(self.if_data_list[n])
                #print(len(get_bits))
                
                # Parse Bits
                if len(get_bits) > 104:
                    get_message = self.decodeBitstream(get_bits)
                    
                    # Add Excess Bits
                    if len(get_bits)%8 != 0:
                        get_bits = get_bits + '0'*(8-len(get_bits)%8)
                    
                    # Print Bytes to Output Port    
                    data_hex = ('%0*X' % (2,int(get_bits,2))).zfill(int(len(get_bits)/4))
                    self.message_port_pub(pmt.intern("bytes"), pmt.to_pmt(data_hex))                    

                    # Print to Output Port
                    self.message_port_pub(pmt.intern("out"), pmt.to_pmt(get_message))


            # Reset
            self.do_analysis = False
            self.if_data_list = []

        return in0_len


    def getBitstream(self,if_data):
        """ Prints out the bitstream from the instantaneous frequency.
        """
        try:
            bitstream = ''
            
            # Find the Start
            start_loc1 = -1
            for n in range(300,len(if_data)):
                if all(m == 0 for m in if_data[n-8:n-4]) and all(mm == 1 for mm in if_data[n-4:n]):
                    start_loc1 = n
                    break
            get_bits = if_data[start_loc1:]
            
            # Invert the Bits
            for n in get_bits:
                if n == 0:
                    bitstream = bitstream + '1'
                else:
                    bitstream = bitstream + '0'
                    
        # Error     
        except:
            bitstream = "-1"

        return bitstream        
        
    def decodeBitstream(self, get_bits):
        """ Manchester decodes the bitstream and diffs the bits to produce a message.
        """                   
        try:
            # Calculate Length of Command
            get_length = int('0b'+get_bits[56:64], 0)
            get_length = get_length - 12       
            print(get_length)   
                 
            # Generate Output Message
            if get_length > 0:
                home_id = '%.*X' % (8, int('0b'+get_bits[0:32], 0))
                source_node_id = '%.*X' % (2, int('0b'+get_bits[32:40], 0))
                frame_control = '%.*X' % (2, int('0b'+get_bits[40:56], 0))
                length = '%.*X' % (2, int('0b'+get_bits[56:64], 0))
                destination_node_id = '%.*X' % (2, int('0b'+get_bits[64:72], 0))            
                command_class = '%.*X' % (2, int('0b'+get_bits[72:80], 0))            
                command = '%.*X' % (get_length*2, int('0b'+get_bits[80:80+get_length*8], 0))
                crc = '%.*X' % (4, int('0b'+get_bits[80+get_length*8:80+get_length*8+16], 0))

                # Verify the CRC
                get_seed = "1D0F"
                get_input = home_id + source_node_id + frame_control + length + destination_node_id + command_class + command
                get_poly = int("1021",16)
                
                # Known Seed
                acc = get_seed
                for n in range(0,int(len(get_input)/2)):
                    new_byte = get_input[2*n:2*n+2]   
                    acc = self.updateCRC(get_poly, acc, new_byte)  # Poly: 0x1021, Seed: 0x1DOF                                
                
                # Populate the Message
                msg = "Message #" + str(self.message_number) + ":\n" + \
                      "Bitstream: " + get_bits + "\n" + \
                      "Full Hex: " + home_id + source_node_id + frame_control + length + destination_node_id + command_class + command + crc + "\n" + \
                      "Home ID: 0x" + home_id + "\n" + \
                      "Source Node ID: " + source_node_id + "\n" + \
                      "Frame Control: " + frame_control + "\n" + \
                      "Length: " + length + "\n" + \
                      "Destination Node ID: " + destination_node_id + "\n" + \
                      "Command Class: " + command_class + "\n" + \
                      "Command: " + command + "\n" + \
                      "CRC: " + crc + "\n" + \
                      "Calculated CRC: " + acc +"\n"
                      
                self.message_number = self.message_number + 1
            
            else:
                msg = "Error parsing message"
                
        except:
            msg = "Error parsing message"          
            
        return msg
                    
                
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
         

