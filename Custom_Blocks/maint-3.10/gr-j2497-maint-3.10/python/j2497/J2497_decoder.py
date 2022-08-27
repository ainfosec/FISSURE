#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright 2020 gr-j2497 author.
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

class J2497_decoder(gr.sync_block):
    """
    docstring for block J2497_decoder
    """
    #def __init__(self, if_peak_threshold, if_peak_offset):
    def __init__(self, if_peak_threshold, if_peak_offset,do_udp,udp_port):
        gr.sync_block.__init__(self,
            name="J2497_decoder",
            in_sig=[numpy.float32],
            out_sig=[])

        self.message_port_register_out(pmt.intern("out"))
        self.start_tag = 0
        self.end_tag = 0
        self.if_data = numpy.array([], dtype=numpy.float32)
        self.do_analysis = False
        self.message_number = 0
        self.prev_time = 0
        self.if_peak_threshold = if_peak_threshold
        self.if_peak_offset = if_peak_offset
        self.do_udp = do_udp
        self.udp_port = udp_port
    
        # Create UDP Socket
        if self.do_udp:
            self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)


    def work(self, input_items, output_items):
        in0 = input_items[0]
        in0_len = len(in0)
        window_start = self.nitems_read(0)

        # Locate Tags
        tags = self.get_tags_in_window(0, 0, in0_len, pmt.string_to_symbol("burst"))

        # Tag Exists
        for tag in tags:  #.offset, .key, .value
            
            # Record on Start
            if str(tag.value) == "#t":
                self.start_tag = tag.offset
                self.if_data = numpy.append(self.if_data, in0[self.start_tag-window_start:])

            # Stop Recording on Stop
            if str(tag.value) == "#f":
                self.end_tag = tag.offset
                burst_size = self.end_tag - self.start_tag

                # Perfect Size
                if burst_size > 4000 and burst_size < 50000:  # 1 Sync + 1 MID + 20? Characters + 1 Checksum + Gap = 23 characters * 10 bits * 100 us = 23000 + Gap
                    self.do_analysis = True

                    # Multiple Windows
                    if len(self.if_data) > 0:
                        self.if_data = numpy.append(self.if_data, in0[:self.end_tag-window_start])
                        
                    # One Window
                    else:
                        self.if_data = in0[self.start_tag-window_start:self.end_tag-window_start]

                # Ignore and Reset
                else:
                    self.start_tag = 0
                    self.end_tag = 0
                    self.if_data = numpy.array([], dtype=numpy.float32)

        # Whole Window with no Stop Tag
        if len(tags) == 0 and len(self.if_data) < 50000 and len(self.if_data) > 0:
            self.if_data = numpy.append(self.if_data, in0)

        # Do Analysis on all the Data
        if self.do_analysis is True:

            # Obtain Bitstream
            get_bits = self.getBitstream()

            # Parse Bits
            if len(get_bits) > 8:
                get_message, get_message_hex = self.getFields(get_bits)

                # Print to Output Port
                self.message_port_pub(pmt.intern("out"), pmt.to_pmt(get_message))

                # Send Message to UDP Port
                if self.do_udp and len(get_message_hex) > 0:
                    self.sendUDP(get_message_hex)

            # Reset
            self.start_tag = 0
            self.end_tag = 0
            self.if_data = numpy.array([], dtype=numpy.float32)
            self.do_analysis = False

        return in0_len


    def getBitstream(self):
        """ Prints out the bitstream from the instantaneous frequency.
        """
        initial_offset = self.if_peak_offset  #106#109        # Message start to first peak
        interval = 100              # 100 us between bits
        reference_sample = -8       # Bottom of the Peak

        # Calculate Expected Number of Bits
        num_bits = int(len(self.if_data)/interval)

        # Parse the IF Data
        bitstream = "1"
        for n in range(0,num_bits-1):

            # Phase Change
            if self.if_data[initial_offset+n*interval] - self.if_data[initial_offset+n*interval+reference_sample] > self.if_peak_threshold:
                if bitstream[-1] == "1":
                    bitstream = bitstream + "0"
                else:
                    bitstream = bitstream + "1"

            # No Phase Change
            else:
                bitstream = bitstream + bitstream[-1]

        return bitstream


    def getFields(self, bits):
        """ Prints out the content of the message fields from the bitstream.
        """
        # Update Count
        self.message_number = self.message_number + 1

        # Get Time
        start_time = self.start_tag / 1e6  # 1e6 = Sampling Rate
        delta_time = start_time - self.prev_time

        # Find the Fields from Start/Stop Bits
        start_bit = False
        bit_counter = 0
        data_bytes = ""

        for n in range(0, len(bits)):

            # Start Bit Found
            if start_bit is True:
                data_bytes = data_bytes + bits[n]
                bit_counter = bit_counter + 1

                # Reached End of Byte
                if bit_counter == 8:
                    start_bit = False
                    bit_counter = 0

            # Detect New Start Bit
            else:                
                if bits[n] == "0" and start_bit is False:
                    start_bit = True

        # Get Fields from Data Bits
        if len(data_bytes) >= 24:
            mid = data_bytes[0:8]
            data = data_bytes[8:-8]
            checksum = data_bytes[-8:]

            # Construct the Output Message
            message = ""
            message = message + "MESSAGE NUMBER: " + str(self.message_number) + "\t\t"
            message = message + "TIME: " + str(start_time) + ' s' + "\t\t"
            message = message + "DELTA: " + str(delta_time) + ' s' + "\n"
            message = message + "MID: " + '0x%0*X' % (2,int(mid[::-1],2)) + "\t\t"
            message_hex = '%0*X' % (2,int(mid[::-1],2))

            # Valid Bitstream
            if len(data) % 8 == 0:

                # Order Bytes Correctly from Reversed Bitstream
                wrong_hex_order = ('%0*X' % (2,int(data[::-1],2))).zfill(int(len(data)/4))
                correct_hex_order = ""
                for m in range(0,len(wrong_hex_order),2):
                    correct_hex_order = wrong_hex_order[m:m+2] + correct_hex_order
                message = message + "DATA: " + '0x' + correct_hex_order + "\t\t"
                message_hex = message_hex + correct_hex_order

            # Invalid Bitstream
            else:
                message = message + "DATA: BITS MISSING\t\t"

            message = message + "CHECKSUM: " + '0x%0*X' % (2,int(checksum[::-1],2))
            message_hex = message_hex + '%0*X' % (2,int(checksum[::-1],2))

        # Not Enough Bits
        else:
            
            # Construct the Output Message
            message = ""
            message = message + "MESSAGE NUMBER: " + str(self.message_number) + "\t\t"
            message = message + "TIME: " + str(start_time) + ' s' + "\t\t"
            message = message + "DELTA: " + str(delta_time) + ' s' + "\t\t"
            message = message + "MID: NOT FOUND\t\t"
            message = message + "DATA: NOT FOUND\t\t"
            message = message + "CHECKSUM: NOT FOUND"
            message_hex = ""

        # Store Time
        self.prev_time = start_time

        return message, message_hex


    def setIF_PeakThreshold(self,if_peak_threshold):
        self.if_peak_threshold = if_peak_threshold


    def setIF_PeakOffset(self,if_peak_offset):
        self.if_peak_offset = if_peak_offset


    def sendUDP(self, message_hex):
        """ Converts a message to bytes and sends it to a specified UDP port.
        """
        # Convert Message
        udp_message = message_hex.decode('hex')
        
        # Send Message
        self.udp_socket.sendto(udp_message,("127.0.0.1", self.udp_port))
        
