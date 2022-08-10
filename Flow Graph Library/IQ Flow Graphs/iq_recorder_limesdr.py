#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#
# SPDX-License-Identifier: GPL-3.0
#
# GNU Radio Python Flow Graph
# Title: Iq Recorder Limesdr
# GNU Radio version: 3.8.1.0

from gnuradio import blocks
from gnuradio import gr
from gnuradio.filter import firdes
import sys
import signal
from argparse import ArgumentParser
from gnuradio.eng_arg import eng_float, intx
from gnuradio import eng_notation
import limesdr

class iq_recorder_limesdr(gr.top_block):

    def __init__(self):
        gr.top_block.__init__(self, "Iq Recorder Limesdr")

        ##################################################
        # Variables
        ##################################################
        self.sample_rate = sample_rate = 1
        self.rx_gain = rx_gain = 20
        self.rx_frequency = rx_frequency = 2412
        self.rx_channel = rx_channel = "0"
        self.rx_antenna = rx_antenna = "TX/RX"
        self.ip_address = ip_address = "192.168.40.2"
        self.filepath = filepath = ""
        self.file_length = file_length = 100000

        ##################################################
        # Blocks
        ##################################################
        self.limesdr_source_0 = limesdr.source('', 0, '', False)


        self.limesdr_source_0.set_sample_rate(sample_rate*1e6)


        self.limesdr_source_0.set_center_freq(rx_frequency*1e6, 0)

        self.limesdr_source_0.set_bandwidth(5e6, 0)




        self.limesdr_source_0.set_gain(int(rx_gain), 0)


        self.limesdr_source_0.set_antenna(255, 0)


        self.limesdr_source_0.calibrate(5e6, 0)
        self.blocks_skiphead_0 = blocks.skiphead(gr.sizeof_gr_complex*1, 200000)
        self.blocks_head_0 = blocks.head(gr.sizeof_gr_complex*1, file_length)
        self.blocks_file_sink_0 = blocks.file_sink(gr.sizeof_gr_complex*1, filepath, False)
        self.blocks_file_sink_0.set_unbuffered(False)



        ##################################################
        # Connections
        ##################################################
        self.connect((self.blocks_head_0, 0), (self.blocks_file_sink_0, 0))
        self.connect((self.blocks_skiphead_0, 0), (self.blocks_head_0, 0))
        self.connect((self.limesdr_source_0, 0), (self.blocks_skiphead_0, 0))

    def get_sample_rate(self):
        return self.sample_rate

    def set_sample_rate(self, sample_rate):
        self.sample_rate = sample_rate

    def get_rx_gain(self):
        return self.rx_gain

    def set_rx_gain(self, rx_gain):
        self.rx_gain = rx_gain
        self.limesdr_source_0.set_gain(int(self.rx_gain), 0)
        self.limesdr_source_0.set_gain(int(self.rx_gain), 1)

    def get_rx_frequency(self):
        return self.rx_frequency

    def set_rx_frequency(self, rx_frequency):
        self.rx_frequency = rx_frequency
        self.limesdr_source_0.set_center_freq(self.rx_frequency*1e6, 0)

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



def main(top_block_cls=iq_recorder_limesdr, options=None):
    tb = top_block_cls()

    def sig_handler(sig=None, frame=None):
        tb.stop()
        tb.wait()
        sys.exit(0)

    signal.signal(signal.SIGINT, sig_handler)
    signal.signal(signal.SIGTERM, sig_handler)

    tb.start()
    tb.wait()


if __name__ == '__main__':
    main()
