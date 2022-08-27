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
import time


class message_generator_433(gr.sync_block):
    """
    docstring for block message_generator_433
    """

    def __init__(self, button, sample_rate, press_repetition_interval):
        gr.sync_block.__init__(self,
                               name="message_generator",
                               in_sig=[numpy.complex64],
                               out_sig=[numpy.complex64])

        self.sample_rate = sample_rate
        self.bits = "10" * 22
        self.press_timer = time.time()
        self.bit_duration = 0.000725

        if button == 2:
            # left button (2)
            self.burst_interval = 0.006825
            # ten bursts (good enough for one cycle, does three cycles if you hold button down)
            self.press_duration = 0.38725 - (
                        self.bit_duration / 2)
        else:
            self.burst_interval = 0.012825  # right button (3)
            self.press_duration = 0.44725 - (self.bit_duration / 2)  # ten bursts

        self.replay_index = 0
        self.press_repetition_interval = press_repetition_interval
        self.press_pri_timer = time.time()

        # Make Signal from Bits
        self.replay_data = numpy.zeros(0, numpy.complex64)
        for n in self.bits:
            if n == "0":
                self.replay_data = numpy.concatenate(
                    [self.replay_data, numpy.zeros(int(self.bit_duration * self.sample_rate), numpy.complex64)])
            else:
                self.replay_data = numpy.concatenate(
                    [self.replay_data, numpy.ones(int(self.bit_duration * self.sample_rate), numpy.complex64)])

        # Add Silence for Burst Interval
        self.replay_data = numpy.concatenate(
            [self.replay_data, numpy.zeros(int(self.burst_interval * self.sample_rate), numpy.complex64)])

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

    def set_button(self, button):
        if button == 2:
            # left button (2)
            self.burst_interval = 0.006825
            # ten bursts (good enough for one cycle, does three cycles if you hold button down)
            self.press_duration = 0.38725 - (
                        self.bit_duration / 2)
        else:
            self.burst_interval = 0.012825  # right button (3)
            self.press_duration = 0.44725 - (self.bit_duration / 2)  # ten bursts

    def set_sample_rate(self, sample_rate):
        self.sample_rate = sample_rate

    def set_press_repetition_interval(self, press_repetition_interval):
        self.press_repetition_interval = press_repetition_interval
