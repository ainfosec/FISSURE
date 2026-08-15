#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#
# SPDX-License-Identifier: GPL-3.0
#
# GNU Radio Python Flow Graph
# Title: Not titled yet
# GNU Radio version: 3.10.5.0

from gnuradio import blocks
import pmt
from gnuradio import filter
from gnuradio.filter import firdes
from gnuradio import gr
from gnuradio.fft import window
import sys
import signal
from argparse import ArgumentParser
from gnuradio.eng_arg import eng_float, intx
from gnuradio import eng_notation




class normal(gr.top_block):

    def __init__(self, filepath="/home/user/Conditioner/Data/tpms/four_tires2.iq", sample_rate='1e6', threshold='.002'):
        gr.top_block.__init__(self, "Not titled yet", catch_exceptions=True)

        ##################################################
        # Parameters
        ##################################################
        self.filepath = filepath
        self.sample_rate = sample_rate
        self.threshold = threshold

        ##################################################
        # Blocks
        ##################################################
        self.fir_filter_xxx_1_0 = filter.fir_filter_fff(1, 50*[0.02])
        self.fir_filter_xxx_1_0.declare_sample_delay(0)
        self.blocks_throttle_0 = blocks.throttle(gr.sizeof_gr_complex*1, float(sample_rate),True)
        self.blocks_threshold_ff_0_0 = blocks.threshold_ff(float(threshold), float(threshold), 0)
        self.blocks_tagged_file_sink_0 = blocks.tagged_file_sink(gr.sizeof_short*1, int(float(sample_rate)))
        self.blocks_interleaved_short_to_complex_0 = blocks.interleaved_short_to_complex(False, False,1.0)
        self.blocks_float_to_short_1 = blocks.float_to_short(1, 1)
        self.blocks_file_source_0 = blocks.file_source(gr.sizeof_short*1, filepath, False, 0, 0)
        self.blocks_file_source_0.set_begin_tag(pmt.PMT_NIL)
        self.blocks_delay_1 = blocks.delay(gr.sizeof_gr_complex*1, 50)
        self.blocks_complex_to_mag_squared_0_0 = blocks.complex_to_mag_squared(1)
        self.blocks_complex_to_interleaved_short_0 = blocks.complex_to_interleaved_short(False,1.0)
        self.blocks_burst_tagger_1 = blocks.burst_tagger(gr.sizeof_gr_complex)
        self.blocks_burst_tagger_1.set_true_tag('burst',True)
        self.blocks_burst_tagger_1.set_false_tag('burst',False)


        ##################################################
        # Connections
        ##################################################
        self.connect((self.blocks_burst_tagger_1, 0), (self.blocks_complex_to_interleaved_short_0, 0))
        self.connect((self.blocks_complex_to_interleaved_short_0, 0), (self.blocks_tagged_file_sink_0, 0))
        self.connect((self.blocks_complex_to_mag_squared_0_0, 0), (self.fir_filter_xxx_1_0, 0))
        self.connect((self.blocks_delay_1, 0), (self.blocks_burst_tagger_1, 0))
        self.connect((self.blocks_file_source_0, 0), (self.blocks_interleaved_short_to_complex_0, 0))
        self.connect((self.blocks_float_to_short_1, 0), (self.blocks_burst_tagger_1, 1))
        self.connect((self.blocks_interleaved_short_to_complex_0, 0), (self.blocks_throttle_0, 0))
        self.connect((self.blocks_threshold_ff_0_0, 0), (self.blocks_float_to_short_1, 0))
        self.connect((self.blocks_throttle_0, 0), (self.blocks_complex_to_mag_squared_0_0, 0))
        self.connect((self.blocks_throttle_0, 0), (self.blocks_delay_1, 0))
        self.connect((self.fir_filter_xxx_1_0, 0), (self.blocks_threshold_ff_0_0, 0))


    def get_filepath(self):
        return self.filepath

    def set_filepath(self, filepath):
        self.filepath = filepath
        self.blocks_file_source_0.open(self.filepath, False)

    def get_sample_rate(self):
        return self.sample_rate

    def set_sample_rate(self, sample_rate):
        self.sample_rate = sample_rate
        self.blocks_throttle_0.set_sample_rate(float(self.sample_rate))

    def get_threshold(self):
        return self.threshold

    def set_threshold(self, threshold):
        self.threshold = threshold
        self.blocks_threshold_ff_0_0.set_hi(float(self.threshold))
        self.blocks_threshold_ff_0_0.set_lo(float(self.threshold))



def argument_parser():
    parser = ArgumentParser()
    parser.add_argument(
        "--filepath", dest="filepath", type=str, default="/home/user/Conditioner/Data/tpms/four_tires2.iq",
        help="Set /home/user/Conditioner/Data/tpms/four_tires2.iq [default=%(default)r]")
    parser.add_argument(
        "--sample-rate", dest="sample_rate", type=str, default='1e6',
        help="Set 1e6 [default=%(default)r]")
    parser.add_argument(
        "--threshold", dest="threshold", type=str, default='.002',
        help="Set .002 [default=%(default)r]")
    return parser


def main(top_block_cls=normal, options=None):
    if options is None:
        options = argument_parser().parse_args()
    tb = top_block_cls(filepath=options.filepath, sample_rate=options.sample_rate, threshold=options.threshold)

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
