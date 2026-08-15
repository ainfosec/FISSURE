#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#
# SPDX-License-Identifier: GPL-3.0
#
# GNU Radio Python Flow Graph
# Title: Iq Playback Single Bladerf2
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
from gnuradio import soapy




class iq_playback_single_bladerf2(gr.top_block):

    def __init__(self, filepath="", sample_rate="4", serial="0", tx_frequency="2425.715", tx_gain="60"):
        gr.top_block.__init__(self, "Iq Playback Single Bladerf2", catch_exceptions=True)

        ##################################################
        # Parameters
        ##################################################
        self.filepath = filepath
        self.sample_rate = sample_rate
        self.serial = serial
        self.tx_frequency = tx_frequency
        self.tx_gain = tx_gain

        ##################################################
        # Blocks
        ##################################################

        self.soapy_bladerf_sink_0 = None
        dev = 'driver=bladerf'
        stream_args = ''
        tune_args = ['']
        settings = ['']

        self.soapy_bladerf_sink_0 = soapy.sink(dev, "fc32", 1, "bladerf=" + str(serial),
                                  stream_args, tune_args, settings)
        self.soapy_bladerf_sink_0.set_sample_rate(0, float(sample_rate)*1e6)
        self.soapy_bladerf_sink_0.set_bandwidth(0, 0.0)
        self.soapy_bladerf_sink_0.set_frequency(0, (float(tx_frequency)*1e6))
        self.soapy_bladerf_sink_0.set_frequency_correction(0, 0)
        self.soapy_bladerf_sink_0.set_gain(0, min(max(float(tx_gain), 17.0), 73.0))
        self.blocks_file_source_0 = blocks.file_source(gr.sizeof_gr_complex*1, filepath, False, 0, 0)
        self.blocks_file_source_0.set_begin_tag(pmt.PMT_NIL)


        ##################################################
        # Connections
        ##################################################
        self.connect((self.blocks_file_source_0, 0), (self.soapy_bladerf_sink_0, 0))


    def get_filepath(self):
        return self.filepath

    def set_filepath(self, filepath):
        self.filepath = filepath
        self.blocks_file_source_0.open(self.filepath, False)

    def get_sample_rate(self):
        return self.sample_rate

    def set_sample_rate(self, sample_rate):
        self.sample_rate = sample_rate
        self.soapy_bladerf_sink_0.set_sample_rate(0, float(self.sample_rate)*1e6)

    def get_serial(self):
        return self.serial

    def set_serial(self, serial):
        self.serial = serial

    def get_tx_frequency(self):
        return self.tx_frequency

    def set_tx_frequency(self, tx_frequency):
        self.tx_frequency = tx_frequency
        self.soapy_bladerf_sink_0.set_frequency(0, (float(self.tx_frequency)*1e6))

    def get_tx_gain(self):
        return self.tx_gain

    def set_tx_gain(self, tx_gain):
        self.tx_gain = tx_gain
        self.soapy_bladerf_sink_0.set_gain(0, min(max(float(self.tx_gain), 17.0), 73.0))



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
        "--tx-frequency", dest="tx_frequency", type=str, default="2425.715",
        help="Set tx_frequency [default=%(default)r]")
    parser.add_argument(
        "--tx-gain", dest="tx_gain", type=str, default="60",
        help="Set tx_gain [default=%(default)r]")
    return parser


def main(top_block_cls=iq_playback_single_bladerf2, options=None):
    if options is None:
        options = argument_parser().parse_args()
    tb = top_block_cls(filepath=options.filepath, sample_rate=options.sample_rate, serial=options.serial, tx_frequency=options.tx_frequency, tx_gain=options.tx_gain)

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
