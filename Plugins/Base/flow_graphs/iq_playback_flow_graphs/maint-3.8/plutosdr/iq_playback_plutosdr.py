#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#
# SPDX-License-Identifier: GPL-3.0
#
# GNU Radio Python Flow Graph
# Title: Iq Playback Plutosdr
# GNU Radio version: 3.8.5.0

from gnuradio import blocks
import pmt
from gnuradio import gr
from gnuradio.filter import firdes
import sys
import signal
from argparse import ArgumentParser
from gnuradio.eng_arg import eng_float, intx
from gnuradio import eng_notation
import iio


class iq_playback_plutosdr(gr.top_block):

    def __init__(self, filepath="", ip_address="192.168.2.1", sample_rate="4", tx_frequency="2425.715", tx_gain="64"):
        gr.top_block.__init__(self, "Iq Playback Plutosdr")

        ##################################################
        # Parameters
        ##################################################
        self.filepath = filepath
        self.ip_address = ip_address
        self.sample_rate = sample_rate
        self.tx_frequency = tx_frequency
        self.tx_gain = tx_gain

        ##################################################
        # Blocks
        ##################################################
        self.iio_pluto_sink_0 = iio.pluto_sink("ip:" + str(ip_address), int(float(tx_frequency)*1e6), int(float(sample_rate)*1e6), 20000000, 32768, False, 89.75 - float(tx_gain), '', True)
        self.blocks_file_source_0 = blocks.file_source(gr.sizeof_gr_complex*1, filepath, True, 0, 0)
        self.blocks_file_source_0.set_begin_tag(pmt.PMT_NIL)


        ##################################################
        # Connections
        ##################################################
        self.connect((self.blocks_file_source_0, 0), (self.iio_pluto_sink_0, 0))


    def get_filepath(self):
        return self.filepath

    def set_filepath(self, filepath):
        self.filepath = filepath
        self.blocks_file_source_0.open(self.filepath, True)

    def get_ip_address(self):
        return self.ip_address

    def set_ip_address(self, ip_address):
        self.ip_address = ip_address

    def get_sample_rate(self):
        return self.sample_rate

    def set_sample_rate(self, sample_rate):
        self.sample_rate = sample_rate
        self.iio_pluto_sink_0.set_params(int(float(self.tx_frequency)*1e6), int(float(self.sample_rate)*1e6), 20000000, 89.75 - float(self.tx_gain), '', True)

    def get_tx_frequency(self):
        return self.tx_frequency

    def set_tx_frequency(self, tx_frequency):
        self.tx_frequency = tx_frequency
        self.iio_pluto_sink_0.set_params(int(float(self.tx_frequency)*1e6), int(float(self.sample_rate)*1e6), 20000000, 89.75 - float(self.tx_gain), '', True)

    def get_tx_gain(self):
        return self.tx_gain

    def set_tx_gain(self, tx_gain):
        self.tx_gain = tx_gain
        self.iio_pluto_sink_0.set_params(int(float(self.tx_frequency)*1e6), int(float(self.sample_rate)*1e6), 20000000, 89.75 - float(self.tx_gain), '', True)




def argument_parser():
    parser = ArgumentParser()
    parser.add_argument(
        "--filepath", dest="filepath", type=str, default="",
        help="Set filepath [default=%(default)r]")
    parser.add_argument(
        "--ip-address", dest="ip_address", type=str, default="192.168.2.1",
        help="Set ip_address [default=%(default)r]")
    parser.add_argument(
        "--sample-rate", dest="sample_rate", type=str, default="4",
        help="Set sample_rate [default=%(default)r]")
    parser.add_argument(
        "--tx-frequency", dest="tx_frequency", type=str, default="2425.715",
        help="Set tx_frequency [default=%(default)r]")
    parser.add_argument(
        "--tx-gain", dest="tx_gain", type=str, default="64",
        help="Set tx_gain [default=%(default)r]")
    return parser


def main(top_block_cls=iq_playback_plutosdr, options=None):
    if options is None:
        options = argument_parser().parse_args()
    tb = top_block_cls(filepath=options.filepath, ip_address=options.ip_address, sample_rate=options.sample_rate, tx_frequency=options.tx_frequency, tx_gain=options.tx_gain)

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
