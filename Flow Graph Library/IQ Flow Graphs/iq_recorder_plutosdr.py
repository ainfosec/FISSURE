#!/usr/bin/env python2
# -*- coding: utf-8 -*-
##################################################
# GNU Radio Python Flow Graph
# Title: Iq Recorder Plutosdr
# Generated: Mon Sep  5 16:02:05 2022
##################################################


from gnuradio import blocks
from gnuradio import eng_notation
from gnuradio import gr
from gnuradio import iio
from gnuradio.eng_option import eng_option
from gnuradio.filter import firdes
from optparse import OptionParser


class iq_recorder_plutosdr(gr.top_block):

    def __init__(self):
        gr.top_block.__init__(self, "Iq Recorder Plutosdr")

        ##################################################
        # Variables
        ##################################################
        self.sample_rate = sample_rate = 1
        self.rx_gain = rx_gain = 20
        self.rx_frequency = rx_frequency = 2412
        self.rx_channel = rx_channel = ""
        self.rx_antenna = rx_antenna = ""
        self.ip_address = ip_address = "192.168.2.1"
        self.filepath = filepath = ""
        self.file_length = file_length = 100000

        ##################################################
        # Blocks
        ##################################################
        self.pluto_source_0 = iio.pluto_source("ip:" + str(ip_address), int(float(rx_frequency)*1e6), int(float(sample_rate)*1e6), 20000000, 0x8000, False, True, True, "manual", float(rx_gain), '', True)
        self.blocks_skiphead_0 = blocks.skiphead(gr.sizeof_gr_complex*1, 200000)
        self.blocks_head_0 = blocks.head(gr.sizeof_gr_complex*1, file_length)
        self.blocks_file_sink_0 = blocks.file_sink(gr.sizeof_gr_complex*1, filepath, False)
        self.blocks_file_sink_0.set_unbuffered(False)

        ##################################################
        # Connections
        ##################################################
        self.connect((self.blocks_head_0, 0), (self.blocks_file_sink_0, 0))
        self.connect((self.blocks_skiphead_0, 0), (self.blocks_head_0, 0))
        self.connect((self.pluto_source_0, 0), (self.blocks_skiphead_0, 0))

    def get_sample_rate(self):
        return self.sample_rate

    def set_sample_rate(self, sample_rate):
        self.sample_rate = sample_rate
        self.pluto_source_0.set_params(int(float(self.rx_frequency)*1e6), int(float(self.sample_rate)*1e6), 20000000, False, True, True, "manual", float(self.rx_gain), '', True)

    def get_rx_gain(self):
        return self.rx_gain

    def set_rx_gain(self, rx_gain):
        self.rx_gain = rx_gain
        self.pluto_source_0.set_params(int(float(self.rx_frequency)*1e6), int(float(self.sample_rate)*1e6), 20000000, False, True, True, "manual", float(self.rx_gain), '', True)

    def get_rx_frequency(self):
        return self.rx_frequency

    def set_rx_frequency(self, rx_frequency):
        self.rx_frequency = rx_frequency
        self.pluto_source_0.set_params(int(float(self.rx_frequency)*1e6), int(float(self.sample_rate)*1e6), 20000000, False, True, True, "manual", float(self.rx_gain), '', True)

    def get_rx_channel(self):
        return self.rx_channel

    def set_rx_channel(self, rx_channel):
        self.rx_channel = rx_channel

    def get_rx_antenna(self):
        return self.rx_antenna

    def set_rx_antenna(self, rx_antenna):
        self.rx_antenna = rx_antenna

    def get_ip_address(self):
        return self.ip_address

    def set_ip_address(self, ip_address):
        self.ip_address = ip_address

    def get_filepath(self):
        return self.filepath

    def set_filepath(self, filepath):
        self.filepath = filepath
        self.blocks_file_sink_0.open(self.filepath)

    def get_file_length(self):
        return self.file_length

    def set_file_length(self, file_length):
        self.file_length = file_length
        self.blocks_head_0.set_length(self.file_length)


def main(top_block_cls=iq_recorder_plutosdr, options=None):

    tb = top_block_cls()
    tb.start()
    tb.wait()


if __name__ == '__main__':
    main()
