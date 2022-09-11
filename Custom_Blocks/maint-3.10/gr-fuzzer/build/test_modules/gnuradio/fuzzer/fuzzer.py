#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2022 gr-fuzzer author.
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
import threading
import time
import ast
import yaml
import random
import os

class fuzzer(gr.sync_block):
    """
    docstring for block fuzzer
    """
    def __init__(self, fuzzing_seed, fuzzing_fields, fuzzing_type, fuzzing_min, fuzzing_max, fuzzing_data, fuzzing_interval, fuzzing_protocol, fuzzing_packet_type, library_filepath):
        gr.sync_block.__init__(self,
            name = "fuzzer",
            in_sig = None,
            out_sig = None)
        
        self.message_port_register_out(pmt.intern('packet_out'))

        # Create Fuzzing Variables
        self.fuzzing_seed = int(fuzzing_seed)
        
        self.fuzzing_fields = ast.literal_eval(fuzzing_fields)
        
        self.fuzzing_type = ast.literal_eval(fuzzing_type)
        
        self.fuzzing_min = ast.literal_eval(fuzzing_min)
        self.fuzzing_min = list(map(int, self.fuzzing_min))
 
        self.fuzzing_max = ast.literal_eval(fuzzing_max)
        self.fuzzing_max = list(map(int, self.fuzzing_max))
                                
        self.fuzzing_data = str(bin(int(fuzzing_data, 16))[2:].zfill(len(fuzzing_data)*4))  # Convert to Binary
        
        self.fuzzing_interval = float(fuzzing_interval)
        self.fuzzing_protocol = fuzzing_protocol
        self.fuzzing_packet_type = fuzzing_packet_type
        
        self.library_filepath = os.path.expanduser(library_filepath)

        # Make a new Thread
        self.stop_event = threading.Event()
        fuzz_thread = threading.Thread(target=self.run, args=())
        fuzz_thread.daemon = True
        fuzz_thread.start()
                    

    def run(self):        
        # Look up the Packet Structure from the Library
        filename = self.library_filepath
        with open(filename) as yaml_config_file:
            fissure_library = yaml.load(yaml_config_file, yaml.FullLoader)
            
        packet_dictionary = fissure_library["Protocols"][self.fuzzing_protocol]["Packet Types"][self.fuzzing_packet_type]["Fields"]

        # Create the Random Number Generator
        generic_rng = random.Random(float(self.fuzzing_seed))
        
        # Store Sequence History
        sequence_gen = []
        for n in range(0,len(self.fuzzing_fields)):
            print(n)
            print(self.fuzzing_min[n])
            sequence_gen.append(self.fuzzing_min[n])
            
        # Fuzz the Fields
        while (not self.stop_event.is_set()):        
            # Single Loop Start Time
            start_time = time.time()
            #~ print(str(start_time))

            # Assemble the Data for the Packet
            sorted_fields = sorted(packet_dictionary,key=lambda x: packet_dictionary[x]['Sort Order'])             
            fuzz_index = 0   
            data_out = ""
            crc_field = []
            current_bit_loc = 0
            for field in sorted_fields:
                # Get Field Length
                field_length = packet_dictionary[field]["Length"]

                # No Fields Selected for Fuzzing
                if len(self.fuzzing_fields) == 0:
                    # Library
                    if self.fuzzing_data == "0000":
                        data_out += packet_dictionary[field]["Default Value"]
                    # Dashboard Table    
                    else:
                        data_out += self.fuzzing_data[current_bit_loc:current_bit_loc+field_length]    
                 
                # Fields Selected for Fuzzing    
                else:
                    # Use the Default Value
                    if field != self.fuzzing_fields[fuzz_index]:  
                        # Library
                        if self.fuzzing_data == "0000":
                            data_out += packet_dictionary[field]["Default Value"]
                        # Dashboard Table    
                        else:
                            data_out += self.fuzzing_data[current_bit_loc:current_bit_loc+field_length]                 
                    
                    # Do Fuzzing    
                    else:                                                      
                        # Check Max/Min with Fields Lengths
                        if self.fuzzing_max[fuzz_index] >= 2**(int(field_length)):
                            self.fuzzing_max[fuzz_index] = 2**(int(field_length))-1
                            
                        if self.fuzzing_min[fuzz_index] >= 2**(int(field_length)):
                            self.fuzzing_min[fuzz_index] = 2**(int(field_length))-1    
                            
                        # Check Min/Max Order
                        if self.fuzzing_min[fuzz_index] > self.fuzzing_max[fuzz_index]:
                            temp_min = self.fuzzing_min[fuzz_index]
                            self.fuzzing_min[fuzz_index] = self.fuzzing_max[fuzz_index]
                            self.fuzzing_max[fuzz_index] = temp_min
                                            
                        # Random Fuzzing Type for Field  (Check if the Length is Greater than some Limit, Break it up into Chunks?)
                        if self.fuzzing_type[fuzz_index] == "Random":
                            new_value = generic_rng.randrange(self.fuzzing_min[fuzz_index],self.fuzzing_max[fuzz_index],1)
                            
                        # Sequence Fuzzing Type for Field  (Check if the Length is Greater than some Limit, Break it up into Chunks?)
                        elif self.fuzzing_type[fuzz_index] == "Sequential":
                            new_value = sequence_gen[fuzz_index]
                            
                            # Reset When Greater than the Max
                            if new_value > self.fuzzing_max[fuzz_index]:
                                new_value = self.fuzzing_min[fuzz_index]
                                sequence_gen[fuzz_index] = self.fuzzing_min[fuzz_index]
                                
                            # Increment for the Next Iteration    
                            sequence_gen[fuzz_index] += 1
                            
                        # Convert Value to Binary
                        new_value = bin(new_value)[2:].zfill(field_length)
                            
                        # Append the Data
                        data_out += new_value
                        
                        # Increment Fuzz Index
                        if fuzz_index < len(self.fuzzing_fields)-1:
                            fuzz_index += 1
                
                # Update Current Bit Location (For Non-Fuzzed Fields)
                current_bit_loc += field_length
                
                # Check for CRC Field
                if packet_dictionary[field]["Is CRC"] == True:
                    crc_field.append( (packet_dictionary[field]["Sort Order"],packet_dictionary[field]["CRC Range"]) )  # (CRC Field Location, Field Locations for Calculation)
                        
            # Remove Spaces in the Binary String
            data_out = data_out.replace(" ","")       
            
            # Calculate the CRC Fields
            for n in range(0,len(crc_field)):
                crc_start_loc = 0
                crc_end_loc = 0
                length_counter = 0
                crc_start_field = int(crc_field[n][1].split("-")[0])
                crc_end_field = int(crc_field[n][1].split("-")[1])
                crc_field_loc = int(crc_field[n][0])
                crc_field_loc_start = 0
                crc_field_loc_end = 0
                
                # Get the Binary Data for the Fields used by CRC
                for field in sorted_fields:
                    
                    # Check for Start
                    if crc_start_field == packet_dictionary[field]["Sort Order"]:
                        crc_start_loc = length_counter
                    
                    # Check for CRC Field Location and Length
                    if crc_field_loc == packet_dictionary[field]["Sort Order"]:
                        crc_field_loc_start = length_counter
                        crc_field_loc_end = length_counter + packet_dictionary[field]["Length"]
                    
                    # Add the Field Length
                    length_counter += packet_dictionary[field]["Length"]
                    
                    # Check for End
                    if crc_end_field == packet_dictionary[field]["Sort Order"]:
                        crc_end_loc = length_counter                  
                        
                crc_data = data_out[crc_start_loc:crc_end_loc]
                
                ########################################################
                # SimpliciTI
                ########################################################
                if self.fuzzing_protocol == "SimpliciTI":
                    # Get the Polynomial/Algorithm  (NEED TO FIX HOW THIS GETS IMPLEMENTED)
                    # CRC Algorithm
                    crc_registers = [1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1]  # From Design Note 502 Figure 1                
                    mseg = [int(i) for i in list(crc_data)]
                    for i in range(0,len(mseg)):
                        bit0 = mseg[i] ^ crc_registers[15]
                        bit2 = bit0 ^ crc_registers[1]
                        bit15 = bit0 ^ crc_registers[14]                    
                        crc_registers = crc_registers[-1:] + crc_registers[:-1]  # rotate list                    
                        crc_registers[0] = bit0
                        crc_registers[2] = bit2
                        crc_registers[15] = bit15
                        
                    crc = list(reversed(crc_registers))
                    bin_str = str(crc).strip('[]')
                    bin_str = bin_str.replace(', ','')
                    
                    # Replace the CRC Field with the Calculated Result
                    data_out = data_out[:crc_field_loc_start] + bin_str + data_out[crc_field_loc_end:]
                    
                    # Convert Binary String to a List of Bytes
                    data_out_bytes = []
                    for nn in range(0,int(len(data_out)/8)):
                        data_out_bytes.append(int(data_out[nn*8:nn*8+8],2))
                
                ########################################################
                # Mode S
                ########################################################
                if self.fuzzing_protocol == "Mode S":
                    # Binary String to Hex
                    bin_str = crc_data.replace(' ', '')
                    hex_str = '%0*X' % ((len(bin_str) + 3) // 4, int(bin_str, 2))

                    # From ADS-B Out: "adsb_encode.py"
                    # CRC Polynomial (25)
                    GENERATOR = "1111111111111010000001001"
                    df17_str = hex_str +"000000"
                    
                    # Calculate CRC
                    hex_len = len(df17_str)
                    bin_str = bin(int(df17_str, 16))[2:].zfill(hex_len*4)                    
                    msgbin = list(bin_str)
                    encode = True
                    if encode:
                        msgbin[-24:] = ['0'] * 24
 
                    # Loop all Bits, Except Last 24 Parity Bits
                    for i in range(len(msgbin)-24):
                        # if 1, perform modulo 2 multiplication,
                        if msgbin[i] == '1':
                            for j in range(len(GENERATOR)):
                                # modulo 2 multiplication = XOR
                                msgbin[i+j] = str((int(msgbin[i+j]) ^ int(GENERATOR[j])))

                    # Last 24 Bits
                    crc = ''.join(msgbin[-24:])   
                                        
                    # Format it
                    bin_str = str(crc).strip('[]')
                    bin_str = bin_str.replace(', ','')
                    
                    # Replace the CRC Field with the Calculated Result
                    data_out = (data_out[:crc_field_loc_start] + bin_str + data_out[crc_field_loc_end:])
                    
                    # Convert Binary String to a List of Bytes
                    data_out_bytes = []
                    for nn in range(0,int(len(data_out)/8)):
                        data_out_bytes.append(int(data_out[nn*8:nn*8+8],2))
                    
                    # Add the Preamle        
                    ppm = [ ]
                    ppm.append( 0xA1 )
                    ppm.append( 0x40 )            

                    # Encode the Message            
                    for i in range(len(data_out_bytes)):

                        # Encode byte
                        manchester_encoded = []
                        for ii in range(7, -1, -1):                    
                            if (~data_out_bytes[i] >> ii) & 0x01:
                                manchester_encoded.append(0)
                                manchester_encoded.append(1)
                            else:
                                manchester_encoded.append(1)
                                manchester_encoded.append(0)             
                                        
                        word16 = numpy.packbits(manchester_encoded)
                        ppm.append(word16[0])
                        ppm.append(word16[1])

                    data_out_bytes = bytearray(ppm)
                    
                ########################################################
                # RDS
                ########################################################
                if self.fuzzing_protocol == "RDS": 
                                                                
                    # CRC Algorithm
                    _GENERATOR_MATRIX = [
                        (0, 0, 0, 1, 1, 1, 0, 1, 1, 1),  # infoword msb
                        (1, 0, 1, 1, 1, 0, 0, 1, 1, 1),  # infoword msb - 1
                        (1, 1, 1, 0, 1, 0, 1, 1, 1, 1),  # infoword msb - 2, ...etc
                        (1, 1, 0, 0, 0, 0, 1, 0, 1, 1),
                        (1, 1, 0, 1, 0, 1, 1, 0, 0, 1),
                        (1, 1, 0, 1, 1, 1, 0, 0, 0, 0),
                        (0, 1, 1, 0, 1, 1, 1, 0, 0, 0),
                        (0, 0, 1, 1, 0, 1, 1, 1, 0, 0),
                        (0, 0, 0, 1, 1, 0, 1, 1, 1, 0),
                        (0, 0, 0, 0, 1, 1, 0, 1, 1, 1),
                        (1, 0, 1, 1, 0, 0, 0, 1, 1, 1),
                        (1, 1, 1, 0, 1, 1, 1, 1, 1, 1),
                        (1, 1, 0, 0, 0, 0, 0, 0, 1, 1),
                        (1, 1, 0, 1, 0, 1, 1, 1, 0, 1),
                        (1, 1, 0, 1, 1, 1, 0, 0, 1, 0),
                        (0, 1, 1, 0, 1, 1, 1, 0, 0, 1)   # infoword lsb
                    ]
                    
                    _OFFSET_WORD = [
                        (0, 0, 1, 1, 1, 1, 1, 1, 0, 0),  # 'A' 
                        (0, 1, 1, 0, 0, 1, 1, 0, 0, 0),  # 'B'
                        (0, 1, 0, 1, 1, 0, 1, 0, 0, 0),  # 'C'
                        (0, 1, 1, 0, 1, 1, 0, 1, 0, 0),  # 'D'
                        (1, 1, 0, 1, 0, 1, 0, 0, 0, 0),  # 'C prime' (used in block 3 if version is type B)
                        #(0, 0, 0, 0, 0, 0, 0, 0, 0, 0)   # 'E'
                    ]
                    
                    mseg = [int(i) for i in list(crc_data)]  # [1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1]
                
                    gen_polys = []
                    for index, bit in enumerate(mseg):
                        if bit:
                            gen_polys.append(_GENERATOR_MATRIX[index])
                    
                    # Add Each Generator mod 2 (XOR)
                    crc_registers = [0,0,0,0,0,0,0,0,0,0]
                    for poly in gen_polys:
                        for nnn in range(0,len(crc_registers)):
                            crc_registers[nnn] = crc_registers[nnn] ^ poly[nnn]

                    # Add CRC and Offset Word
                    for nn in range(0,len(crc_registers)):
                        if self.fuzzing_packet_type == "Message Version B" and n == 2:
                            crc_registers[nn] = crc_registers[nn] ^ _OFFSET_WORD[4][nn]  # C'
                        else:
                            crc_registers[nn] = crc_registers[nn] ^ _OFFSET_WORD[n][nn]
                                                
                    # Format it for the Table ("##########")
                    bin_str = str(crc_registers).strip('[]')
                    bin_str = bin_str.replace(', ','')
                    
                    # Replace the CRC Field with the Calculated Result
                    data_out = data_out[:crc_field_loc_start] + bin_str + data_out[crc_field_loc_end:]
                    
                    # Convert Binary String to a List of Bytes
                    data_out_bytes = []
                    for nn in range(0,int(len(data_out)/8)):
                        data_out_bytes.append(int(data_out[nn*8:nn*8+8],2))
                        
                ########################################################
                # X10
                ########################################################
                if self.fuzzing_protocol == "X10":   
                    inv_bin_str = ""
                    for m in range(0,8):
                        # Address/Data Code (Not Fuzzing the Inverse Fields)
                        if crc_data[m] == "0":
                            inv_bin_str = inv_bin_str + "1"
                        else:
                            inv_bin_str = inv_bin_str + "0"    
                                               
                    # Replace the CRC Field with the Calculated Result
                    data_out = data_out[:crc_field_loc_start] + inv_bin_str + data_out[crc_field_loc_end:]
                    
                    # Convert Binary String to a List of Bytes
                    data_out_bytes = []
                    for nn in range(0,int(len(data_out)/8)):
                        data_out_bytes.append(int(data_out[nn*8:nn*8+8],2))
                    
                ########################################################
                    
                       
            # Convert Packet to a PMT List
            print(data_out_bytes)
            list_out = pmt.list1(pmt.to_pmt(data_out_bytes[0]))
            for n in range(1,len(data_out_bytes)):
                list_out = pmt.list_add(list_out,pmt.to_pmt(data_out_bytes[n]))
            
            # Output the Packet in a Message
            try:
                self.message_port_pub(pmt.intern('packet_out'),list_out)
            except:
                # Stop the Thread When the Block's Program Exits
                print("Stopping the thread")
                self.stop_event.set()
                
            
            # Sleep the Remainder of the Fuzzing Interval
            time_difference = self.fuzzing_interval-(time.time()-start_time)
            time.sleep(time_difference)
            
            
            
            #~ ######
            #~ # Test
            #data_out_bytes = 0xAA,0xAA,0xAA,0xAA,0xD3,0x91,0xD3,0x91,0x0E,0x78,0x56,0x34,0x12,0xAA,0xAA,0xAA,0xAA,0x20,0x03,0x33,0xAA,0x00,0xFF,0xE4,0x0D   
            #print(data_out_bytes2)
            #~ 
            #~ print(str(time.time()))
            #~ data_out1 = 0xAA,0xAA,0xAA,0xAA,0xD3,0x91,0xD3,0x91,0x0E,0x78,0x56,0x34,0x12,0xAA,0xAA,0xAA,0xAA,0x20,0x03,0x33,0xFF,0xFF,0xFF,0x62,0x06
            #~ list_out1 = pmt.list1(pmt.to_pmt(data_out1[0]))
            #~ for n in range(1,len(data_out1)):
                #~ list_out1 = pmt.list_add(list_out1,pmt.to_pmt(data_out1[n]))            
            #~ self.message_port_pub(pmt.intern('packet_out'),list_out1)
            #~ time.sleep(self.fuzzing_interval)
            #~ 
            #~ # Test
            #~ print(str(time.time()))
            #~ data_out1 = 0xAA,0xAA,0xAA,0xAA,0xD3,0x91,0xD3,0x91,0x0E,0x78,0x56,0x34,0x12,0xAA,0xAA,0xAA,0xAA,0x20,0x03,0x33,0x68,0x01,0xFF,0xED,0x25
            #~ list_out1 = pmt.list1(pmt.to_pmt(data_out1[0]))
            #~ for n in range(1,len(data_out1)):
                #~ list_out1 = pmt.list_add(list_out1,pmt.to_pmt(data_out1[n]))            
            #~ self.message_port_pub(pmt.intern('packet_out'),list_out1)
            #~ time.sleep(self.fuzzing_interval)
            #~ ######
            
            

    # Set Functions
    def set_fuzzing_seed(self,fuzzing_seed):
        self.fuzzing_seed = int(fuzzing_seed)
        
    def set_fuzzing_fields(self,fuzzing_fields):
        self.fuzzing_fields = ast.literal_eval(fuzzing_fields)
        
    def set_fuzzing_type(self,fuzzing_type):
        self.fuzzing_type = ast.literal_eval(fuzzing_type)
        
    def set_fuzzing_min(self,fuzzing_min):
        self.fuzzing_min = ast.literal_eval(fuzzing_min)
        self.fuzzing_min = map(int, self.fuzzing_min)
        
    def set_fuzzing_max(self,fuzzing_max):
        self.fuzzing_max = ast.literal_eval(fuzzing_max)
        self.fuzzing_max = map(int, self.fuzzing_max)
        
    def set_fuzzing_data(self,fuzzing_data):
        self.fuzzing_data = str(bin(int(fuzzing_data, 16))[2:].zfill(len(fuzzing_data)*4))  # Convert to Binary
        
    def set_fuzzing_interval(self,fuzzing_interval):
        self.fuzzing_interval = float(fuzzing_interval)
        
    def set_fuzzing_protocol(self,fuzzing_protocol):
        self.fuzzing_protocol = fuzzing_protocol
        
    def set_fuzzing_packet_type(self,fuzzing_packet_type):
        self.fuzzing_packet_type = fuzzing_packet_type        





