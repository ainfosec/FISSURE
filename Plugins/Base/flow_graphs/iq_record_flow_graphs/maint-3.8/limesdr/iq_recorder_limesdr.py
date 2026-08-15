#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#
# SPDX-License-Identifier: GPL-3.0
#
# GNU Radio Python Flow Graph
# Title: Iq Recorder Limesdr
# GNU Radio version: 3.8.5.0

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

    def __init__(self, file_length="100000", filepath="", rx_frequency="2412", rx_gain="20", sample_rate="1"):
        gr.top_block.__init__(self, "Iq Recorder Limesdr")

        ##################################################
        # Parameters
        ##################################################
        self.file_length = file_length
        self.filepath = filepath
        self.rx_frequency = rx_frequency
        self.rx_gain = rx_gain
        self.sample_rate = sample_rate

        ##################################################
        # Blocks
        ##################################################
        self.limesdr_source_0 = limesdr.source('', 0, '', False)


        self.limesdr_source_0.set_sample_rate(float(sample_rate)*1e6)


        self.limesdr_source_0.set_center_freq(float(rx_frequency)*1e6, 0)

        self.limesdr_source_0.set_bandwidth(5e6, 0)




        self.limesdr_source_0.set_gain(int(rx_gain), 0)


        self.limesdr_source_0.set_antenna(255, 0)


        self.limesdr_source_0.calibrate(5e6, 0)
        self.blocks_skiphead_0 = blocks.skiphead(gr.sizeof_gr_complex*1, 200000)
        self.blocks_head_0 = blocks.head(gr.sizeof_gr_complex*1, int(file_length))
        self.blocks_file_sink_0 = blocks.file_sink(gr.sizeof_gr_complex*1, filepath, False)
        self.blocks_file_sink_0.set_unbuffered(False)


        ##################################################
        # Connections
        ##################################################
        self.connect((self.blocks_head_0, 0), (self.blocks_file_sink_0, 0))
        self.connect((self.blocks_skiphead_0, 0), (self.blocks_head_0, 0))
        self.connect((self.limesdr_source_0, 0), (self.blocks_skiphead_0, 0))


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
        self.limesdr_source_0.set_center_freq(float(self.rx_frequency)*1e6, 0)

    def get_rx_gain(self):
        return self.rx_gain

    def set_rx_gain(self, rx_gain):
        self.rx_gain = rx_gain
        self.limesdr_source_0.set_gain(int(self.rx_gain), 0)
        self.limesdr_source_0.set_gain(int(self.rx_gain), 1)

    def get_sample_rate(self):
        return self.sample_rate

    def set_sample_rate(self, sample_rate):
        self.sample_rate = sample_rate




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
        "--rx-gain", dest="rx_gain", type=str, default="20",
        help="Set rx_gain [default=%(default)r]")
    parser.add_argument(
        "--sample-rate", dest="sample_rate", type=str, default="1",
        help="Set sample_rate [default=%(default)r]")
    return parser


def main(top_block_cls=iq_recorder_limesdr, options=None):
    if options is None:
        options = argument_parser().parse_args()
    tb = top_block_cls(file_length=options.file_length, filepath=options.filepath, rx_frequency=options.rx_frequency, rx_gain=options.rx_gain, sample_rate=options.sample_rate)

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
