#!/usr/bin/env python2
# -*- coding: utf-8 -*-
##################################################
# GNU Radio Python Flow Graph
# Title: Iq Playback Single Plutosdr
# Generated: Mon Sep  5 16:01:59 2022
##################################################


from gnuradio import blocks
from gnuradio import eng_notation
from gnuradio import gr
from gnuradio import iio
from gnuradio.eng_option import eng_option
from gnuradio.filter import firdes
from optparse import OptionParser


class iq_playback_single_plutosdr(gr.top_block):

    def __init__(self):
        gr.top_block.__init__(self, "Iq Playback Single Plutosdr")

        ##################################################
        # Variables
        ##################################################
        self.tx_gain = tx_gain = 64
        self.tx_frequency = tx_frequency = 2425.715
        self.tx_channel = tx_channel = ""
        self.sample_rate = sample_rate = 4
        self.ip_address = ip_address = "192.168.2.1"
        self.filepath = filepath = ""

        ##################################################
        # Blocks
        ##################################################
        self.pluto_sink_0 = iio.pluto_sink("ip:" + str(ip_address), int(float(tx_frequency)*1e6), int(float(sample_rate)*1e6), 20000000, 0x8000, False, 89.75 - float(tx_gain), '', True)
        self.blocks_file_source_0 = blocks.file_source(gr.sizeof_gr_complex*1, filepath, False)

        ##################################################
        # Connections
        ##################################################
        self.connect((self.blocks_file_source_0, 0), (self.pluto_sink_0, 0))

    def get_tx_gain(self):
        return self.tx_gain

    def set_tx_gain(self, tx_gain):
        self.tx_gain = tx_gain
        self.pluto_sink_0.set_params(int(float(self.tx_frequency)*1e6), int(float(self.sample_rate)*1e6), 20000000, 89.75 - float(self.tx_gain), '', True)

    def get_tx_frequency(self):
        return self.tx_frequency

    def set_tx_frequency(self, tx_frequency):
        self.tx_frequency = tx_frequency
        self.pluto_sink_0.set_params(int(float(self.tx_frequency)*1e6), int(float(self.sample_rate)*1e6), 20000000, 89.75 - float(self.tx_gain), '', True)

    def get_tx_channel(self):
        return self.tx_channel

    def set_tx_channel(self, tx_channel):
        self.tx_channel = tx_channel

    def get_sample_rate(self):
        return self.sample_rate

    def set_sample_rate(self, sample_rate):
        self.sample_rate = sample_rate
        self.pluto_sink_0.set_params(int(float(self.tx_frequency)*1e6), int(float(self.sample_rate)*1e6), 20000000, 89.75 - float(self.tx_gain), '', True)

    def get_ip_address(self):
        return self.ip_address

    def set_ip_address(self, ip_address):
        self.ip_address = ip_address

    def get_filepath(self):
        return self.filepath

    def set_filepath(self, filepath):
        self.filepath = filepath
        self.blocks_file_source_0.open(self.filepath, False)


def main(top_block_cls=iq_playback_single_plutosdr, options=None):

    tb = top_block_cls()
    tb.start()
    tb.wait()


if __name__ == '__main__':
    main()
