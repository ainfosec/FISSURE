#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#
# SPDX-License-Identifier: GPL-3.0
#
# GNU Radio Python Flow Graph
# Title: Not titled yet
# Author: user
# GNU Radio version: 3.10.7.0

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
from gnuradio.fft import logpwrfft
import strongest_epy_block_0 as epy_block_0  # embedded python block




class strongest(gr.top_block):

    def __init__(self, fft_size='8192', fft_threshold='-80', filepath="/home/user/Conditioner/Data/tpms/four_tires2.iq", peak_file_location="/home/user/FISSURE/Flow Graph Library/TSI Flow Graphs/Conditioner/peaks.txt", sample_rate='1000000', samples='4169300'):
        gr.top_block.__init__(self, "Not titled yet", catch_exceptions=True)

        ##################################################
        # Parameters
        ##################################################
        self.fft_size = fft_size
        self.fft_threshold = fft_threshold
        self.filepath = filepath
        self.peak_file_location = peak_file_location
        self.sample_rate = sample_rate
        self.samples = samples

        ##################################################
        # Blocks
        ##################################################

        self.logpwrfft_x_0 = logpwrfft.logpwrfft_c(
            sample_rate=float(sample_rate),
            fft_size=int(fft_size),
            ref_scale=2,
            frame_rate=30,
            avg_alpha=1,
            average=False,
            shift=True)
        self.epy_block_0 = epy_block_0.blk(vec_len=int(fft_size), peak_detect_file=str(peak_file_location), fft_threshold=float(fft_threshold), sample_rate=float(sample_rate))
        self.blocks_throttle_0 = blocks.throttle(gr.sizeof_gr_complex*1, float(sample_rate),True)
        self.blocks_interleaved_short_to_complex_0 = blocks.interleaved_short_to_complex(False, False,1.0)
        self.blocks_head_0 = blocks.head(gr.sizeof_gr_complex*1, (int(samples)*5))
        self.blocks_file_source_0_0 = blocks.file_source(gr.sizeof_short*1, filepath, True, 0, 0)
        self.blocks_file_source_0_0.set_begin_tag(pmt.PMT_NIL)


        ##################################################
        # Connections
        ##################################################
        self.connect((self.blocks_file_source_0_0, 0), (self.blocks_interleaved_short_to_complex_0, 0))
        self.connect((self.blocks_head_0, 0), (self.blocks_throttle_0, 0))
        self.connect((self.blocks_interleaved_short_to_complex_0, 0), (self.blocks_head_0, 0))
        self.connect((self.blocks_throttle_0, 0), (self.logpwrfft_x_0, 0))
        self.connect((self.logpwrfft_x_0, 0), (self.epy_block_0, 0))


    def get_fft_size(self):
        return self.fft_size

    def set_fft_size(self, fft_size):
        self.fft_size = fft_size
        self.epy_block_0.vec_len = int(self.fft_size)

    def get_fft_threshold(self):
        return self.fft_threshold

    def set_fft_threshold(self, fft_threshold):
        self.fft_threshold = fft_threshold
        self.epy_block_0.fft_threshold = float(self.fft_threshold)

    def get_filepath(self):
        return self.filepath

    def set_filepath(self, filepath):
        self.filepath = filepath
        self.blocks_file_source_0_0.open(self.filepath, True)

    def get_peak_file_location(self):
        return self.peak_file_location

    def set_peak_file_location(self, peak_file_location):
        self.peak_file_location = peak_file_location
        self.epy_block_0.peak_detect_file = str(self.peak_file_location)

    def get_sample_rate(self):
        return self.sample_rate

    def set_sample_rate(self, sample_rate):
        self.sample_rate = sample_rate
        self.blocks_throttle_0.set_sample_rate(float(self.sample_rate))
        self.epy_block_0.sample_rate = float(self.sample_rate)
        self.logpwrfft_x_0.set_sample_rate(float(self.sample_rate))

    def get_samples(self):
        return self.samples

    def set_samples(self, samples):
        self.samples = samples
        self.blocks_head_0.set_length((int(self.samples)*5))



def argument_parser():
    parser = ArgumentParser()
    parser.add_argument(
        "--fft-size", dest="fft_size", type=str, default='8192',
        help="Set 8192 [default=%(default)r]")
    parser.add_argument(
        "--fft-threshold", dest="fft_threshold", type=str, default='-80',
        help="Set -80 [default=%(default)r]")
    parser.add_argument(
        "--filepath", dest="filepath", type=str, default="/home/user/Conditioner/Data/tpms/four_tires2.iq",
        help="Set /home/user/Conditioner/Data/tpms/four_tires2.iq [default=%(default)r]")
    parser.add_argument(
        "--peak-file-location", dest="peak_file_location", type=str, default="/home/user/FISSURE/Flow Graph Library/TSI Flow Graphs/Conditioner/peaks.txt",
        help="Set /home/user/FISSURE/Flow Graph Library/TSI Flow Graphs/Conditioner/peaks.txt [default=%(default)r]")
    parser.add_argument(
        "--sample-rate", dest="sample_rate", type=str, default='1000000',
        help="Set 1000000 [default=%(default)r]")
    parser.add_argument(
        "--samples", dest="samples", type=str, default='4169300',
        help="Set 4169300 [default=%(default)r]")
    return parser


def main(top_block_cls=strongest, options=None):
    if options is None:
        options = argument_parser().parse_args()
    tb = top_block_cls(fft_size=options.fft_size, fft_threshold=options.fft_threshold, filepath=options.filepath, peak_file_location=options.peak_file_location, sample_rate=options.sample_rate, samples=options.samples)

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
