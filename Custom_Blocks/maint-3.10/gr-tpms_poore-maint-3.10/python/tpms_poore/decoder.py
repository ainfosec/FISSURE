#!/usr/bin/env python3
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
        self.do_analysis = False
        self.message_number = 1

        self.message_port_register_out(pmt.intern('out'))
        self.message_port_register_out(pmt.intern("bytes"))

    def work(self, input_items, output_items):
        in0 = input_items[0]
        in0_len = len(in0)

        window_start = self.nitems_read(0)

        # Locate Tags
        tags = self.get_tags_in_window(0, 0, in0_len, pmt.string_to_symbol("burst"))

        # Tag Exists
        for tag in tags:  # .offset, .key, .value

            # Record on Start
            if str(tag.value) == "#t":
                self.start_tag = tag.offset
                self.if_data = numpy.append(self.if_data, in0[self.start_tag - window_start:])

            # Stop Recording on Stop
            if str(tag.value) == "#f":
                self.end_tag = tag.offset
                burst_size = self.end_tag - self.start_tag

                # Perfect Size
                if 600 < burst_size < 900:
                    self.do_analysis = True

                    # Multiple Windows
                    if len(self.if_data) > 0:
                        self.if_data = numpy.append(self.if_data, in0[:self.end_tag - window_start])

                    # One Window
                    else:
                        self.if_data = in0[self.start_tag - window_start:self.end_tag - window_start]

                # Ignore and Reset
                else:
                    self.start_tag = 0
                    self.end_tag = 0
                    self.if_data = numpy.array([], dtype=numpy.float32)

        # Whole Window with no Stop Tag
        if len(tags) == 0 and 900 > len(self.if_data) > 0:
            self.if_data = numpy.append(self.if_data, in0)

        # Do Analysis on all the Data
        if self.do_analysis is True:

            # print "DOING ANALYSIS!!"
            # print len(self.if_data)

            # Obtain Bitstream
            get_bits = self.getBitstream()

            # Parse Bits
            if len(get_bits) > 130:
                get_message = self.decodeBitstream(get_bits)

                # Print to Output Port
                if get_message != "-1":
                    self.message_port_pub(pmt.intern("out"), pmt.to_pmt(get_message))

            # Reset
            self.start_tag = 0
            self.end_tag = 0
            self.if_data = numpy.array([], dtype=numpy.float32)
            self.do_analysis = False

        return in0_len

    def getBitstream(self):
        """ Prints out the bitstream from the instantaneous frequency.
        """
        try:
            bitstream = "-1"

            # Find the Start
            start_loc2 = -1
            for n in range(20, len(self.if_data)):
                if all(m == 1 for m in self.if_data[n - 20:n - 10]) and all(
                        mm == 0 for mm in self.if_data[n - 10:n - 2]):
                    start_loc1 = n

                    # Find the Start of the First '1'                    
                    for h in range(0, 100):
                        if self.if_data[start_loc1 + h] == 1:
                            start_loc2 = start_loc1 + h
                            break
                    break

            # Produce the Bitstream
            if (start_loc2 > -1) and (start_loc2 < 150):
                bitstream = '0'
                prev_seq = 0
                prev_loc = start_loc2

                # Data Start to End of Tagged Message
                for n in range(start_loc2, len(self.if_data)):

                    # Find the Next Change
                    if int(self.if_data[n]) == prev_seq:
                        point_diff = n - prev_loc

                        # One Manchester Encoded Bit
                        if point_diff < 7:
                            if self.if_data[n] == 0:
                                bitstream = bitstream + '1'
                                prev_seq = 1
                            else:
                                bitstream = bitstream + '0'
                                prev_seq = 0
                            prev_loc = n

                        # Two Manchester Encoded Bits
                        elif (point_diff > 7) and (point_diff < 25):
                            if self.if_data[n] == 0:
                                bitstream = bitstream + '11'
                                prev_seq = 1
                            else:
                                bitstream = bitstream + '00'
                                prev_seq = 0
                            prev_loc = n

                        # Reached the End
                        else:
                            break

            # Pad Some Extra
            bitstream = bitstream + 5 * bitstream[-1]

        # Error     
        except:
            bitstream = "-1"

        return bitstream

    def decodeBitstream(self, get_bits):
        """ Manchester decodes the bitstream and diffs the bits to produce a message.
        """
        # Manchester Decode the Bits
        get_dec_man = ''
        for m in range(0, len(get_bits), 2):
            if get_bits[m:m + 2] == '01':
                get_dec_man = get_dec_man + '0'
            elif get_bits[m:m + 2] == '10':
                get_dec_man = get_dec_man + '1'
            else:
                get_dec_man = get_dec_man + '?'

        # Differentiate the Decoded Bits
        get_diff = ''
        if len(get_dec_man) > 1:
            # Differentiate
            for b in range(1, len(get_dec_man)):
                if get_dec_man[b - 1] == get_dec_man[b]:
                    get_diff = get_diff + '0'
                else:
                    get_diff = get_diff + '1'

                    # Generate Output Message
        msg = ""
        if len(get_diff) >= 66:
            sensor_id = '%.*X' % (2, int('0b' + get_diff[0:28], 0))
            battery_status = get_diff[28]
            counter = get_diff[29:31]
            unknown1 = get_diff[31]
            unknown2 = get_diff[32]
            self_test = get_diff[33]
            tire_pressure = get_diff[34:42]
            tp_psi = str((int(tire_pressure, 2) - 40) * .363)
            tp_complement = get_diff[42:50]
            tire_temp = get_diff[50:58]
            temp_celsius = str(int(tire_temp, 2) - 40)
            temp_fahr = str((int(temp_celsius) * 9 / 5) + 32)
            crc = get_diff[58:66]

            msg = "Message #" + str(self.message_number) + ":\n" + \
                  "Bitstream: " + get_bits + "\n" + \
                  "Decoded Bits: " + get_diff + "\n" + \
                  "Sensor ID: 0x" + sensor_id + "\n" + \
                  "Battery_Status: " + battery_status + "\n" + \
                  "Counter: " + counter + "\n" + \
                  "Unknown1: " + unknown1 + "\n" + \
                  "Unknown2: " + unknown2 + "\n" + \
                  "Self Test Failed: " + self_test + "\n" + \
                  "Tire Pressure: " + tire_pressure + " | PSI: " + tp_psi + "\n" + \
                  "T.P. Complement: " + tp_complement + "\n" + \
                  "Tire Temperature: " + tire_temp + " | Celsius: " + temp_celsius + " | Fahrenheit: " + \
                  temp_fahr + "\n" + \
                  "CRC: " + crc + "\n"

            self.message_number = self.message_number + 1

            # Add Excess Bits
            if len(get_diff) % 8 != 0:
                get_diff = get_diff + '0' * (8 - len(get_diff) % 8)

            # Print Bytes to Output Port    
            data_hex = ('%0*X' % (2, int(get_diff, 2))).zfill(len(get_diff) // 4)
            self.message_port_pub(pmt.intern("bytes"), pmt.to_pmt(data_hex))

        return msg
