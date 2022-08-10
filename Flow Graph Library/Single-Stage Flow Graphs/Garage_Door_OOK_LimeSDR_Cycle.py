#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#
# SPDX-License-Identifier: GPL-3.0
#
# GNU Radio Python Flow Graph
# Title: Garage Door Ook Limesdr Cycle
# GNU Radio version: 3.8.1.0

from gnuradio import blocks
from gnuradio import gr
from gnuradio.filter import firdes
import sys
import signal
from argparse import ArgumentParser
from gnuradio.eng_arg import eng_float, intx
from gnuradio import eng_notation
import garage_door
import limesdr

class Garage_Door_OOK_LimeSDR_Cycle(gr.top_block):

    def __init__(self):
        gr.top_block.__init__(self, "Garage Door Ook Limesdr Cycle")

        ##################################################
        # Variables
        ##################################################
        self.tx_gain = tx_gain = 60
        self.tx_frequency = tx_frequency = 310.4e6
        self.tx_channel = tx_channel = 0
        self.starting_dip = starting_dip = 0
        self.sample_rate = sample_rate = 1e6
        self.notes = notes = "Cycles through DIP switch combinations sequentially."
        self.dip_interval = dip_interval = 0.001
        self.bursts_per_dip = bursts_per_dip = 5
        self.burst_interval = burst_interval = 0.02

        ##################################################
        # Blocks
        ##################################################
        self.limesdr_sink_0 = limesdr.sink('', 0, '', '')


        self.limesdr_sink_0.set_sample_rate(sample_rate)


        self.limesdr_sink_0.set_center_freq(tx_frequency, 0)

        self.limesdr_sink_0.set_bandwidth(5e6, 0)




        self.limesdr_sink_0.set_gain(int(tx_gain), 0)


        self.limesdr_sink_0.set_antenna(255, 0)


        self.limesdr_sink_0.calibrate(5e6, 0)
        self.garage_door_message_cycler_0 = garage_door.message_cycler(sample_rate,dip_interval,starting_dip,bursts_per_dip,burst_interval)
        self.blocks_null_source_0 = blocks.null_source(gr.sizeof_gr_complex*1)
        self.blocks_multiply_const_vxx_0 = blocks.multiply_const_cc(0.9)



        ##################################################
        # Connections
        ##################################################
        self.connect((self.blocks_multiply_const_vxx_0, 0), (self.limesdr_sink_0, 0))
        self.connect((self.blocks_null_source_0, 0), (self.garage_door_message_cycler_0, 0))
        self.connect((self.garage_door_message_cycler_0, 0), (self.blocks_multiply_const_vxx_0, 0))

    def get_tx_gain(self):
        return self.tx_gain

    def set_tx_gain(self, tx_gain):
        self.tx_gain = tx_gain
        self.limesdr_sink_0.set_gain(int(self.tx_gain), 0)
        self.limesdr_sink_0.set_gain(int(self.tx_gain), 1)

    def get_tx_frequency(self):
        return self.tx_frequency

    def set_tx_frequency(self, tx_frequency):
        self.tx_frequency = tx_frequency
        self.limesdr_sink_0.set_center_freq(self.tx_frequency, 0)

    def get_tx_channel(self):
        return self.tx_channel

    def set_tx_channel(self, tx_channel):
        self.tx_channel = tx_channel

    def get_starting_dip(self):
        return self.starting_dip

    def set_starting_dip(self, starting_dip):
        self.starting_dip = starting_dip
        self.garage_door_message_cycler_0.set_dip(self.starting_dip)

    def get_sample_rate(self):
        return self.sample_rate

    def set_sample_rate(self, sample_rate):
        self.sample_rate = sample_rate
        self.garage_door_message_cycler_0.set_sample_rate(self.sample_rate)

    def get_notes(self):
        return self.notes

    def set_notes(self, notes):
        self.notes = notes

    def get_dip_interval(self):
        return self.dip_interval

    def set_dip_interval(self, dip_interval):
        self.dip_interval = dip_interval
        self.garage_door_message_cycler_0.set_dip_interval(self.dip_interval)

    def get_bursts_per_dip(self):
        return self.bursts_per_dip

    def set_bursts_per_dip(self, bursts_per_dip):
        self.bursts_per_dip = bursts_per_dip
        self.garage_door_message_cycler_0.set_bpd(self.bursts_per_dip)

    def get_burst_interval(self):
        return self.burst_interval

    def set_burst_interval(self, burst_interval):
        self.burst_interval = burst_interval
        self.garage_door_message_cycler_0.set_burst_interval(self.burst_interval)



def main(top_block_cls=Garage_Door_OOK_LimeSDR_Cycle, options=None):
    tb = top_block_cls()

    def sig_handler(sig=None, frame=None):
        tb.stop()
        tb.wait()
        sys.exit(0)

    signal.signal(signal.SIGINT, sig_handler)
    signal.signal(signal.SIGTERM, sig_handler)

    tb.start()
    try:
        input('Press Enter to quit: ')
    except EOFError:
        pass
    tb.stop()
    tb.wait()


if __name__ == '__main__':
    main()
