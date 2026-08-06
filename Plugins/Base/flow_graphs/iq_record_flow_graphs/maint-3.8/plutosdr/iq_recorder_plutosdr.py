#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#
# SPDX-License-Identifier: GPL-3.0
#
# GNU Radio Python Flow Graph
# Title: Iq Recorder Plutosdr
# GNU Radio version: 3.8.5.0

from gnuradio import blocks
from gnuradio import gr
from gnuradio.filter import firdes
import sys
import signal
from argparse import ArgumentParser
from gnuradio.eng_arg import eng_float, intx
from gnuradio import eng_notation
import iio


class iq_recorder_plutosdr(gr.top_block):

    def __init__(self, file_length="100000", filepath="", ip_address="192.168.2.1", rx_frequency="2412", rx_gain="64", sample_rate="1"):
        gr.top_block.__init__(self, "Iq Recorder Plutosdr")

        ##################################################
        # Parameters
        ##################################################
        self.file_length = file_length
        self.filepath = filepath
        self.ip_address = ip_address
        self.rx_frequency = rx_frequency
        self.rx_gain = rx_gain
        self.sample_rate = sample_rate

        ##################################################
        # Blocks
        ##################################################
        self.iio_pluto_source_0 = iio.pluto_source("ip:" + str(ip_address), int(float(rx_frequency)*1e6), int(float(sample_rate)*1e6), 20000000, 32768, True, True, True, 'manual', float(rx_gain), '', True)
        self.blocks_skiphead_0 = blocks.skiphead(gr.sizeof_gr_complex*1, 200000)
        self.blocks_head_0 = blocks.head(gr.sizeof_gr_complex*1, int(file_length))
        self.blocks_file_sink_0 = blocks.file_sink(gr.sizeof_gr_complex*1, filepath, False)
        self.blocks_file_sink_0.set_unbuffered(False)


        ##################################################
        # Connections
        ##################################################
        self.connect((self.blocks_head_0, 0), (self.blocks_file_sink_0, 0))
        self.connect((self.blocks_skiphead_0, 0), (self.blocks_head_0, 0))
        self.connect((self.iio_pluto_source_0, 0), (self.blocks_skiphead_0, 0))


    def get_file_length(self):
        return self.file_length

    def set_file_length(self, file_length):
        self.file_length = file_length
        self.blocks_head_0.set_length(int(self.file_length))

    def get_filepath(self):
        return self.filepath

    def set_filepath(self, filepath):
        self.filepath = filepath
        self.blocks_file_sink_0.open(self.filepath)

    def get_ip_address(self):
        return self.ip_address

    def set_ip_address(self, ip_address):
        self.ip_address = ip_address

    def get_rx_frequency(self):
        return self.rx_frequency

    def set_rx_frequency(self, rx_frequency):
        self.rx_frequency = rx_frequency
        self.iio_pluto_source_0.set_params(int(float(self.rx_frequency)*1e6), int(float(self.sample_rate)*1e6), 20000000, True, True, True, 'manual', float(self.rx_gain), '', True)

    def get_rx_gain(self):
        return self.rx_gain

    def set_rx_gain(self, rx_gain):
        self.rx_gain = rx_gain
        self.iio_pluto_source_0.set_params(int(float(self.rx_frequency)*1e6), int(float(self.sample_rate)*1e6), 20000000, True, True, True, 'manual', float(self.rx_gain), '', True)

    def get_sample_rate(self):
        return self.sample_rate

    def set_sample_rate(self, sample_rate):
        self.sample_rate = sample_rate
        self.iio_pluto_source_0.set_params(int(float(self.rx_frequency)*1e6), int(float(self.sample_rate)*1e6), 20000000, True, True, True, 'manual', float(self.rx_gain), '', True)




def argument_parser():
    parser = ArgumentParser()
    parser.add_argument(
        "--file-length", dest="file_length", type=str, default="100000",
        help="Set file_length [default=%(default)r]")
    parser.add_argument(
        "--filepath", dest="filepath", type=str, default="",
        help="Set filepath [default=%(default)r]")
    parser.add_argument(
        "--ip-address", dest="ip_address", type=str, default="192.168.2.1",
        help="Set ip_address [default=%(default)r]")
    parser.add_argument(
        "--rx-frequency", dest="rx_frequency", type=str, default="2412",
        help="Set rx_frequency [default=%(default)r]")
    parser.add_argument(
        "--rx-gain", dest="rx_gain", type=str, default="64",
        help="Set rx_gain [default=%(default)r]")
    parser.add_argument(
        "--sample-rate", dest="sample_rate", type=str, default="1",
        help="Set sample_rate [default=%(default)r]")
    return parser


def main(top_block_cls=iq_recorder_plutosdr, options=None):
    if options is None:
        options = argument_parser().parse_args()
    tb = top_block_cls(file_length=options.file_length, filepath=options.filepath, ip_address=options.ip_address, rx_frequency=options.rx_frequency, rx_gain=options.rx_gain, sample_rate=options.sample_rate)

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
