#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#
# SPDX-License-Identifier: GPL-3.0
#
# GNU Radio Python Flow Graph
# Title: Iq Recorder Bladerf2
# GNU Radio version: 3.10.9.2

from gnuradio import blocks
from gnuradio import gr
from gnuradio.filter import firdes
from gnuradio.fft import window
import sys
import signal
from argparse import ArgumentParser
from gnuradio.eng_arg import eng_float, intx
from gnuradio import eng_notation
from gnuradio import soapy




class iq_recorder_bladerf2(gr.top_block):

    def __init__(self, file_length="100000", filepath="", rx_frequency="2412", rx_gain="50", sample_rate="1", serial="0"):
        gr.top_block.__init__(self, "Iq Recorder Bladerf2", catch_exceptions=True)

        ##################################################
        # Parameters
        ##################################################
        self.file_length = file_length
        self.filepath = filepath
        self.rx_frequency = rx_frequency
        self.rx_gain = rx_gain
        self.sample_rate = sample_rate
        self.serial = serial

        ##################################################
        # Blocks
        ##################################################

        self.soapy_bladerf_source_0 = None
        dev = 'driver=bladerf'
        stream_args = ''
        tune_args = ['']
        settings = ['']

        self.soapy_bladerf_source_0 = soapy.source(dev, "fc32", 1, "bladerf=" + str(serial),
                                  stream_args, tune_args, settings)
        self.soapy_bladerf_source_0.set_sample_rate(0, float(sample_rate)*1e6)
        self.soapy_bladerf_source_0.set_bandwidth(0, 0.0)
        self.soapy_bladerf_source_0.set_frequency(0, (float(rx_frequency)*1e6))
        self.soapy_bladerf_source_0.set_frequency_correction(0, 0)
        self.soapy_bladerf_source_0.set_gain(0, min(max(float(rx_gain), -1.0), 60.0))
        self.blocks_skiphead_0 = blocks.skiphead(gr.sizeof_gr_complex*1, 200000)
        self.blocks_head_0 = blocks.head(gr.sizeof_gr_complex*1, int(file_length))
        self.blocks_file_sink_0 = blocks.file_sink(gr.sizeof_gr_complex*1, filepath, False)
        self.blocks_file_sink_0.set_unbuffered(False)


        ##################################################
        # Connections
        ##################################################
        self.connect((self.blocks_head_0, 0), (self.blocks_file_sink_0, 0))
        self.connect((self.blocks_skiphead_0, 0), (self.blocks_head_0, 0))
        self.connect((self.soapy_bladerf_source_0, 0), (self.blocks_skiphead_0, 0))


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

    def get_rx_frequency(self):
        return self.rx_frequency

    def set_rx_frequency(self, rx_frequency):
        self.rx_frequency = rx_frequency
        self.soapy_bladerf_source_0.set_frequency(0, (float(self.rx_frequency)*1e6))

    def get_rx_gain(self):
        return self.rx_gain

    def set_rx_gain(self, rx_gain):
        self.rx_gain = rx_gain
        self.soapy_bladerf_source_0.set_gain(0, min(max(float(self.rx_gain), -1.0), 60.0))

    def get_sample_rate(self):
        return self.sample_rate

    def set_sample_rate(self, sample_rate):
        self.sample_rate = sample_rate
        self.soapy_bladerf_source_0.set_sample_rate(0, float(self.sample_rate)*1e6)

    def get_serial(self):
        return self.serial

    def set_serial(self, serial):
        self.serial = serial



def argument_parser():
    parser = ArgumentParser()
    parser.add_argument(
        "--file-length", dest="file_length", type=str, default="100000",
        help="Set file_length [default=%(default)r]")
    parser.add_argument(
        "--filepath", dest="filepath", type=str, default="",
        help="Set filepath [default=%(default)r]")
    parser.add_argument(
        "--rx-frequency", dest="rx_frequency", type=str, default="2412",
        help="Set rx_frequency [default=%(default)r]")
    parser.add_argument(
        "--rx-gain", dest="rx_gain", type=str, default="50",
        help="Set rx_gain [default=%(default)r]")
    parser.add_argument(
        "--sample-rate", dest="sample_rate", type=str, default="1",
        help="Set sample_rate [default=%(default)r]")
    parser.add_argument(
        "--serial", dest="serial", type=str, default="0",
        help="Set serial [default=%(default)r]")
    return parser


def main(top_block_cls=iq_recorder_bladerf2, options=None):
    if options is None:
        options = argument_parser().parse_args()
    tb = top_block_cls(file_length=options.file_length, filepath=options.filepath, rx_frequency=options.rx_frequency, rx_gain=options.rx_gain, sample_rate=options.sample_rate, serial=options.serial)

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
