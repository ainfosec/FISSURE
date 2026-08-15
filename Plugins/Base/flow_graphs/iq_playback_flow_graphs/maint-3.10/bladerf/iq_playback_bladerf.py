#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#
# SPDX-License-Identifier: GPL-3.0
#
# GNU Radio Python Flow Graph
# Title: Iq Playback Bladerf
# GNU Radio version: 3.10.9.2

from gnuradio import blocks
import pmt
from gnuradio import gr
from gnuradio.filter import firdes
from gnuradio.fft import window
import sys
import signal
from argparse import ArgumentParser
from gnuradio.eng_arg import eng_float, intx
from gnuradio import eng_notation
import osmosdr
import time




class iq_playback_bladerf(gr.top_block):

    def __init__(self, filepath="", sample_rate="4", serial="0", tx_antenna="TX/RX", tx_frequency="2425.715", tx_gain="30"):
        gr.top_block.__init__(self, "Iq Playback Bladerf", catch_exceptions=True)

        ##################################################
        # Parameters
        ##################################################
        self.filepath = filepath
        self.sample_rate = sample_rate
        self.serial = serial
        self.tx_antenna = tx_antenna
        self.tx_frequency = tx_frequency
        self.tx_gain = tx_gain

        ##################################################
        # Blocks
        ##################################################

        self.osmosdr_sink_0 = osmosdr.sink(
            args="numchan=" + str(1) + " " + "bladerf=" + str(serial)
        )
        self.osmosdr_sink_0.set_time_unknown_pps(osmosdr.time_spec_t())
        self.osmosdr_sink_0.set_sample_rate((float(sample_rate)*1e6))
        self.osmosdr_sink_0.set_center_freq((float(tx_frequency)*1e6), 0)
        self.osmosdr_sink_0.set_freq_corr(0, 0)
        self.osmosdr_sink_0.set_gain(10, 0)
        self.osmosdr_sink_0.set_if_gain(float(tx_gain), 0)
        self.osmosdr_sink_0.set_bb_gain(20, 0)
        self.osmosdr_sink_0.set_antenna('', 0)
        self.osmosdr_sink_0.set_bandwidth(0, 0)
        self.blocks_file_source_0 = blocks.file_source(gr.sizeof_gr_complex*1, filepath, True, 0, 0)
        self.blocks_file_source_0.set_begin_tag(pmt.PMT_NIL)


        ##################################################
        # Connections
        ##################################################
        self.connect((self.blocks_file_source_0, 0), (self.osmosdr_sink_0, 0))


    def get_filepath(self):
        return self.filepath

    def set_filepath(self, filepath):
        self.filepath = filepath
        self.blocks_file_source_0.open(self.filepath, True)

    def get_sample_rate(self):
        return self.sample_rate

    def set_sample_rate(self, sample_rate):
        self.sample_rate = sample_rate
        self.osmosdr_sink_0.set_sample_rate((float(self.sample_rate)*1e6))

    def get_serial(self):
        return self.serial

    def set_serial(self, serial):
        self.serial = serial

    def get_tx_antenna(self):
        return self.tx_antenna

    def set_tx_antenna(self, tx_antenna):
        self.tx_antenna = tx_antenna

    def get_tx_frequency(self):
        return self.tx_frequency

    def set_tx_frequency(self, tx_frequency):
        self.tx_frequency = tx_frequency
        self.osmosdr_sink_0.set_center_freq((float(self.tx_frequency)*1e6), 0)

    def get_tx_gain(self):
        return self.tx_gain

    def set_tx_gain(self, tx_gain):
        self.tx_gain = tx_gain
        self.osmosdr_sink_0.set_if_gain(float(self.tx_gain), 0)



def argument_parser():
    parser = ArgumentParser()
    parser.add_argument(
        "--filepath", dest="filepath", type=str, default="",
        help="Set filepath [default=%(default)r]")
    parser.add_argument(
        "--sample-rate", dest="sample_rate", type=str, default="4",
        help="Set sample_rate [default=%(default)r]")
    parser.add_argument(
        "--serial", dest="serial", type=str, default="0",
        help="Set serial [default=%(default)r]")
    parser.add_argument(
        "--tx-antenna", dest="tx_antenna", type=str, default="TX/RX",
        help="Set tx_antenna [default=%(default)r]")
    parser.add_argument(
        "--tx-frequency", dest="tx_frequency", type=str, default="2425.715",
        help="Set tx_frequency [default=%(default)r]")
    parser.add_argument(
        "--tx-gain", dest="tx_gain", type=str, default="30",
        help="Set tx_gain [default=%(default)r]")
    return parser


def main(top_block_cls=iq_playback_bladerf, options=None):
    if options is None:
        options = argument_parser().parse_args()
    tb = top_block_cls(filepath=options.filepath, sample_rate=options.sample_rate, serial=options.serial, tx_antenna=options.tx_antenna, tx_frequency=options.tx_frequency, tx_gain=options.tx_gain)

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
