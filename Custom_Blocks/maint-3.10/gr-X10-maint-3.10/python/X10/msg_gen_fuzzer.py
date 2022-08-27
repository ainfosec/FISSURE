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
import scipy
from gnuradio import gr
import pmt
import time


class msg_gen_fuzzer(gr.sync_block):
    """
    docstring for block msg_gen_fuzzer
    """

    def __init__(self, sample_rate, address_code, data_code, press_duration, press_repetition_interval):
        gr.sync_block.__init__(self,
                               name="msg_gen_fuzzer",
                               in_sig=[numpy.complex64],
                               out_sig=[numpy.complex64])

        self.sample_rate = sample_rate
        self.address_code = address_code
        self.data_code = data_code
        self.press_duration = press_duration
        self.press_timer = time.time()
        self.burst_interval = .087132  # 87.132 ms between bursts
        self.chip_duration = .0005
        self.preamble_on = .008066  # 8.066 ms
        self.preamble_off = .004037  # 4.037 ms
        self.replay_index = 0
        self.press_repetition_interval = press_repetition_interval
        self.press_pri_timer = time.time()
        self.preamble = numpy.concatenate([numpy.ones(int(self.preamble_on * self.sample_rate), numpy.complex64),
                                           numpy.zeros(int(self.preamble_off * self.sample_rate), numpy.complex64)])

        self.chips = ""
        self.replay_data = None
        self.message_port_register_in(pmt.intern("fuzzer_in"))
        self.set_msg_handler(pmt.intern("fuzzer_in"), self.set_message)
        self.reset = 0

        self.calculate_chips()  # Make the chips

    def work(self, input_items, output_items):
        in0 = input_items[0]
        out = output_items[0]
        input_len = len(input_items[0])

        # Button Press
        if time.time() < self.press_timer + self.press_duration:

            # Whole Window
            if self.replay_index + input_len < len(self.replay_data):
                out[:] = self.replay_data[self.replay_index:self.replay_index + input_len]
                self.replay_index = self.replay_index + input_len

            # Partial Window
            else:
                chunk1 = self.replay_data[self.replay_index:]
                chunk2 = self.replay_data[0:self.replay_index + input_len - len(self.replay_data)]
                out[:] = numpy.concatenate([chunk1, chunk2])
                self.replay_index = self.replay_index + input_len - len(self.replay_data)

        # Do Nothing
        else:
            if self.replay_index != 0:
                self.replay_index = 0

            # Check Timer
            if time.time() > self.press_pri_timer + self.press_repetition_interval:
                self.press_pri_timer = time.time()
                self.press_timer = self.press_pri_timer

            out[:] = in0

        return len(output_items[0])

    def set_sample_rate(self, sample_rate):
        self.sample_rate = sample_rate
        self.calculate_chips()

    def calculate_chips(self):
        """ Recalculates the chips when address or data code is updated.
        """
        # Get Address Bits
        address_code_hex = self.address_code.replace('0x', '')
        address_bits = '{:08b}'.format(int(address_code_hex, 16))

        # Get Data Bits        
        data_code_hex = self.data_code.replace('0x', '')
        data_bits = '{:08b}'.format(int(data_code_hex, 16))

        # Expand Bits into Chips
        self.chips = ""
        address_chips = ""
        address_comp_chips = ""
        for n in address_bits:
            if n == "0":
                address_chips = address_chips + "10"
                address_comp_chips = address_comp_chips + "1000"
            else:
                address_chips = address_chips + "1000"
                address_comp_chips = address_comp_chips + "10"

        data_chips = ""
        data_comp_chips = ""
        for n in data_bits:
            if n == "0":
                data_chips = data_chips + "10"
                data_comp_chips = data_comp_chips + "1000"
            else:
                data_chips = data_chips + "1000"
                data_comp_chips = data_comp_chips + "10"

        # Add an extra bit for some reason
        self.chips = address_chips + address_comp_chips + data_chips + data_comp_chips + "1000"

        # Make Signal from Chips
        self.replay_data = numpy.zeros(0, numpy.complex64)
        for n in self.chips:
            if n == "0":
                self.replay_data = numpy.concatenate(
                    [self.replay_data, numpy.zeros(int(self.chip_duration * self.sample_rate), numpy.complex64)])
            else:
                self.replay_data = numpy.concatenate(
                    [self.replay_data, numpy.ones(int(self.chip_duration * self.sample_rate), numpy.complex64)])

        # Add Preamble
        self.replay_data = numpy.concatenate([self.preamble, self.replay_data])

        # Add Silence for Burst Interval
        self.replay_data = numpy.concatenate(
            [self.replay_data, numpy.zeros(int(self.burst_interval * self.sample_rate), numpy.complex64)])

    def set_address_code(self, address_code):
        self.address_code = address_code
        self.calculate_chips()

    def set_data_code(self, data_code):
        self.data_code = data_code
        self.calculate_chips()

    def set_press_duration(self, press_duration):
        self.press_duration = press_duration

    def set_press_repetition_interval(self, press_repetition_interval):
        self.press_repetition_interval = press_repetition_interval

    def set_message(self, new_message):
        # print "SET MESSAGE!"
        # print new_message

        # Retrieve Fuzzer Message (###,~###,###,~###)
        get_new_message = []
        for n in range(0, pmt.length(new_message)):
            new_value = numpy.uint8(pmt.to_python(pmt.nth(n, new_message)))
            get_new_message.append(new_value)

        self.address_code = "{0:#0{1}x}".format(get_new_message[0], 4)
        self.data_code = "{0:#0{1}x}".format(get_new_message[2], 4)
        self.calculate_chips()

        self.reset = 1
