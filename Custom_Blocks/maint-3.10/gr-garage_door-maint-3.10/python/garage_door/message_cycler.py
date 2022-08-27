#!/usr/bin/env python
# -*- coding: utf-8 -*-
# 
# Copyright 2019 <+YOU OR YOUR COMPANY+>.
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


class message_cycler(gr.sync_block):
    """
    docstring for block message_cycler
    """

    def __init__(self, sample_rate, dip_interval, starting_dip, bpd, burst_interval):
        gr.sync_block.__init__(self,
                               name="message_cycler",
                               in_sig=[numpy.complex64],
                               out_sig=[numpy.complex64])

        self.starting_dip = None
        self.replay_data = None
        self.replay_data_single = None
        self.replay_index = None
        self.sample_rate = sample_rate
        self.dip_interval = dip_interval
        self.dip_position = starting_dip
        self.bpd = bpd
        self.burst_interval = burst_interval

        self.chip_duration = .0005

        # Make the First Message
        self.create_message(self.dip_position)
        self.interval_timer = time.time()
        self.replay = True

    def work(self, input_items, output_items):
        in0 = input_items[0]
        out = output_items[0]
        input_len = len(input_items[0])

        # Active
        if self.replay is True:

            # Whole Window
            if self.replay_index + input_len < len(self.replay_data):
                out[:] = self.replay_data[self.replay_index:self.replay_index + input_len]
                self.replay_index = self.replay_index + input_len

            # Reached End
            else:
                self.replay = False
                chunk1 = self.replay_data[self.replay_index:]
                chunk2 = numpy.zeros(self.replay_index + input_len - len(self.replay_data))
                out[:] = numpy.concatenate([chunk1, chunk2])

                # Create New Message
                self.dip_position = self.dip_position + 1
                if self.dip_position > 1023:
                    self.dip_position = 0
                self.create_message(self.dip_position)

        # Do Nothing
        else:
            # Reset Timer
            if time.time() > self.interval_timer + self.dip_interval:
                self.interval_timer = time.time()
                self.replay = True

            out[:] = in0

        return len(output_items[0])

    def create_message(self, current_dip_position):
        """ Updates the DIP switch position and creates a new set of replay data.
        """
        # Expand Bits into Chips
        dip_positions = '{0:010b}'.format(current_dip_position)
        chips = ""
        for n in dip_positions:
            if n == "0":
                chips = chips + "1110"
            else:
                chips = chips + "1000"

        # Make Signal from Chips
        self.replay_data = numpy.zeros(0, numpy.complex64)
        self.replay_data_single = numpy.zeros(0, numpy.complex64)
        for n in chips:
            if n == "0":
                self.replay_data_single = numpy.concatenate(
                    [self.replay_data_single, numpy.zeros(int(self.chip_duration * self.sample_rate), numpy.complex64)])
            else:
                self.replay_data_single = numpy.concatenate(
                    [self.replay_data_single, numpy.ones(int(self.chip_duration * self.sample_rate), numpy.complex64)])

        # Add Silence Between Repeats
        self.replay_data_single = numpy.concatenate([self.replay_data_single,
                                                     numpy.zeros(int(self.burst_interval * self.sample_rate),
                                                                 numpy.complex64)])  # Observed: ~20 ms 

        # Repeat the Message N Times
        for n in range(0, self.bpd):
            self.replay_data = numpy.concatenate([self.replay_data, self.replay_data_single])

        # Reset Replay Index
        self.replay_index = 0
        print("DIP = " + str(self.dip_position) + ' (' + str(dip_positions) + ')')

    def set_sample_rate(self, sample_rate):
        self.sample_rate = sample_rate

    def set_dip_interval(self, dip_interval):
        self.dip_interval = dip_interval

    def set_dip(self, dip):
        self.starting_dip = dip

    def set_bpd(self, bpd):
        self.bpd = bpd

    def set_burst_interval(self, burst_interval):
        self.burst_interval = burst_interval
