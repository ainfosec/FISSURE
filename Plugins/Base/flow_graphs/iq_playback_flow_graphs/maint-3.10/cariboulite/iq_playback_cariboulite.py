#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#
# SPDX-License-Identifier: GPL-3.0
#
# GNU Radio Python Flow Graph
# Title: Iq Playback Cariboulite
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




class iq_playback_cariboulite(gr.top_block):

    def __init__(self, filepath="", ip_address="192.168.40.2", sample_rate="4", serial="False", tx_antenna="TX/RX", tx_channel="A:A", tx_frequency="2425.715", tx_gain="70"):
        gr.top_block.__init__(self, "Iq Playback Cariboulite", catch_exceptions=True)

        ##################################################
        # Parameters
        ##################################################
        self.filepath = filepath
        self.ip_address = ip_address
        self.sample_rate = sample_rate
        self.serial = serial
        self.tx_antenna = tx_antenna
        self.tx_channel = tx_channel
        self.tx_frequency = tx_frequency
        self.tx_gain = tx_gain

        ##################################################
        # Blocks
        ##################################################

        self.soapy_custom_sink_0 = None
        dev = 'driver=' + ''
        stream_args = ''
        tune_args = ['']
        settings = ['']
        self.soapy_custom_sink_0 = soapy.sink(dev, "fc32",
                                1, '',
                                stream_args, tune_args, settings)
        self.soapy_custom_sink_0.set_sample_rate(0, float(sample_rate)*1e6)
        self.soapy_custom_sink_0.set_bandwidth(0, 0)
        self.soapy_custom_sink_0.set_antenna(0, 'TX')
        self.soapy_custom_sink_0.set_frequency(0, (float(tx_frequency)*1e6))
        self.soapy_custom_sink_0.set_frequency_correction(0, 0)
        self.soapy_custom_sink_0.set_gain(0, float(tx_gain))
        self.soapy_custom_sink_0.set_dc_offset(0, 0)
        self.soapy_custom_sink_0.set_iq_balance(0, 0)
        self.blocks_file_source_0 = blocks.file_source(gr.sizeof_gr_complex*1, filepath, True, 0, 0)
        self.blocks_file_source_0.set_begin_tag(pmt.PMT_NIL)


        ##################################################
        # Connections
        ##################################################
        self.connect((self.blocks_file_source_0, 0), (self.soapy_custom_sink_0, 0))


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

    def get_serial(self):
        return self.serial

    def set_serial(self, serial):
        self.serial = serial

    def get_tx_antenna(self):
        return self.tx_antenna

    def set_tx_antenna(self, tx_antenna):
        self.tx_antenna = tx_antenna

    def get_tx_channel(self):
        return self.tx_channel

    def set_tx_channel(self, tx_channel):
        self.tx_channel = tx_channel

    def get_tx_frequency(self):
        return self.tx_frequency

    def set_tx_frequency(self, tx_frequency):
        self.tx_frequency = tx_frequency
        self.soapy_custom_sink_0.set_frequency(0, (float(self.tx_frequency)*1e6))

    def get_tx_gain(self):
        return self.tx_gain

    def set_tx_gain(self, tx_gain):
        self.tx_gain = tx_gain
        self.soapy_custom_sink_0.set_gain(0, float(self.tx_gain))



def argument_parser():
    parser = ArgumentParser()
    parser.add_argument(
        "--filepath", dest="filepath", type=str, default="",
        help="Set filepath [default=%(default)r]")
    parser.add_argument(
        "--ip-address", dest="ip_address", type=str, default="192.168.40.2",
        help="Set ip_address [default=%(default)r]")
    parser.add_argument(
        "--sample-rate", dest="sample_rate", type=str, default="4",
        help="Set sample_rate [default=%(default)r]")
    parser.add_argument(
        "--serial", dest="serial", type=str, default="False",
        help="Set serial [default=%(default)r]")
    parser.add_argument(
        "--tx-antenna", dest="tx_antenna", type=str, default="TX/RX",
        help="Set tx_antenna [default=%(default)r]")
    parser.add_argument(
        "--tx-channel", dest="tx_channel", type=str, default="A:A",
        help="Set tx_channel [default=%(default)r]")
    parser.add_argument(
        "--tx-frequency", dest="tx_frequency", type=str, default="2425.715",
        help="Set tx_frequency [default=%(default)r]")
    parser.add_argument(
        "--tx-gain", dest="tx_gain", type=str, default="70",
        help="Set tx_gain [default=%(default)r]")
    return parser


def main(top_block_cls=iq_playback_cariboulite, options=None):
    if options is None:
        options = argument_parser().parse_args()
    tb = top_block_cls(filepath=options.filepath, ip_address=options.ip_address, sample_rate=options.sample_rate, serial=options.serial, tx_antenna=options.tx_antenna, tx_channel=options.tx_channel, tx_frequency=options.tx_frequency, tx_gain=options.tx_gain)

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
