#!/usr/bin/env python
# -*- coding: utf-8 -*-
# 
# Copyright 2020 <+YOU OR YOUR COMPANY+>.
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


class x10_decoder(gr.sync_block):
    """
    docstring for block x10_decoder
    """

    def __init__(self):
        gr.sync_block.__init__(self,
                               name="x10_decoder",
                               in_sig=[numpy.float32],
                               out_sig=[])

        self.message_port_register_out(pmt.intern("out"))
        self.message_port_register_out(pmt.intern("bytes"))
        self.record_chips = False
        self.chips = numpy.array([], dtype=numpy.float32)
        self.message_count = 0
        self.start_tag = None

    def work(self, input_items, output_items):
        in0 = input_items[0]
        in0_len = len(in0)
        window_start = self.nitems_read(0)

        # Locate Tags
        if self.record_chips is False:
            tags = self.get_tags_in_window(0, 0, in0_len, pmt.string_to_symbol("Start"))

            # Tag Exists
            for tag in tags:  # .offset, .key, .value

                # Start Recording
                if str(tag.key) == "Start":
                    self.start_tag = tag.offset
                    self.chips = numpy.append(self.chips, in0[self.start_tag - window_start:])
                    self.record_chips = True

        # Recording
        else:
            # Keep Recording
            if len(self.chips) < 440:
                self.chips = numpy.append(self.chips, in0[:])

            # Do Analysis
            else:
                # Find Start
                chips = []
                for n in range(0, len(self.chips)):
                    if self.chips[n] == 1:
                        chips = self.chips[n::].tolist()
                        break

                # Convert Chips to Bits
                if len(chips) > 0:
                    bits = ''
                    consec0 = 0
                    for n in chips:
                        if n == 0:
                            consec0 = consec0 + 1
                        else:
                            if consec0 > 0:
                                # Accounts for sampling/transmission errors
                                if consec0 < 8:
                                    # 4 samples per chip, a '0' bit is [1,1,1,1,0,0,0,0] (Four 0's)
                                    bits = bits + '0'
                                else:
                                    # 4 samples per chip, a '1' bit is [1,1,1,1,0,0,0,0,0,0,0,0,0,0,0,0] (Twelve 0's)
                                    bits = bits + '1'
                            consec0 = 0

                    # for n in range(0,len(chips)-2,2):
                    # if chips[n:n+4] == [1,0,1,0]:
                    # bits = bits + '0'
                    # elif chips[n:n+4] == [1,0,0,0]:
                    # bits = bits + '1'
                    # elif chips[n:n+4] == [0,0,0,0]:
                    # break

                    # Convert Bits to Hex
                    if len(bits) >= 32:
                        address_code = '%.*X' % (2, int('0b' + bits[0:8], 0))
                        # address_code_comp = '%.*X' % (2, int('0b' + bits[8:16], 0))
                        data_code = '%.*X' % (2, int('0b' + bits[16:24], 0))
                        # data_code_comp = '%.*X' % (2, int('0b' + bits[24:32], 0))

                        # Print to Output Port
                        self.message_count = self.message_count + 1
                        message_out = "Message Count: " + str(self.message_count) + "\n" + \
                                      "Address Code: 0x" + str(address_code) + "\t\t" + \
                                      "Data Code: 0x" + str(data_code) + "\nBits: " + str(bits)
                        self.message_port_pub(pmt.intern("out"), pmt.to_pmt(message_out))

                        # Drop Excess Bits
                        if len(bits) % 8 != 0:
                            bits = bits[:-(len(bits) % 8)]

                        # Print Byte to Output Port    
                        data_hex = ('%0*X' % (2, int(bits, 2))).zfill(len(bits) // 4)
                        # print data_hex
                        self.message_port_pub(pmt.intern("bytes"), pmt.to_pmt(data_hex))

                # Reset
                self.chips = numpy.array([], dtype=numpy.float32)
                self.record_chips = False

        return in0_len
