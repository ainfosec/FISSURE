#!/usr/bin/env python2
# -*- coding: utf-8 -*-
##################################################
# GNU Radio Python Flow Graph
# Title: Strongest
# GNU Radio version: 3.7.13.5
##################################################


from gnuradio import blocks
from gnuradio import eng_notation
from gnuradio import gr
from gnuradio.eng_option import eng_option
from gnuradio.fft import logpwrfft
from gnuradio.filter import firdes
from optparse import OptionParser
import epy_block_0
import pmt


class strongest(gr.top_block):

    def __init__(self, fft_size="8192", fft_threshold="-80", filepath="", peak_file_location="", sample_rate="1e6", samples="4169300"):
        gr.top_block.__init__(self, "Strongest")

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
        	avg_alpha=1.0,
        	average=False,
        )
        self.epy_block_0 = epy_block_0.blk(vec_len=int(fft_size), peak_detect_file=str(peak_file_location), fft_threshold=float(fft_threshold), sample_rate=float(sample_rate))
        self.blocks_throttle_0 = blocks.throttle(gr.sizeof_gr_complex*1, float(sample_rate),True)
        self.blocks_head_0 = blocks.head(gr.sizeof_gr_complex*1, int(samples)*5)
        self.blocks_file_source_0 = blocks.file_source(gr.sizeof_gr_complex*1, filepath, True)
        self.blocks_file_source_0.set_begin_tag(pmt.PMT_NIL)



        ##################################################
        # Connections
        ##################################################
        self.connect((self.blocks_file_source_0, 0), (self.blocks_head_0, 0))
        self.connect((self.blocks_head_0, 0), (self.blocks_throttle_0, 0))
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
        self.blocks_file_source_0.open(self.filepath, True)

    def get_peak_file_location(self):
        return self.peak_file_location

    def set_peak_file_location(self, peak_file_location):
        self.peak_file_location = peak_file_location
        self.epy_block_0.peak_detect_file = str(self.peak_file_location)

    def get_sample_rate(self):
        return self.sample_rate

    def set_sample_rate(self, sample_rate):
        self.sample_rate = sample_rate
        self.logpwrfft_x_0.set_sample_rate(float(self.sample_rate))
        self.epy_block_0.sample_rate = float(self.sample_rate)
        self.blocks_throttle_0.set_sample_rate(float(self.sample_rate))

    def get_samples(self):
        return self.samples

    def set_samples(self, samples):
        self.samples = samples
        self.blocks_head_0.set_length(int(self.samples)*5)


def argument_parser():
    parser = OptionParser(usage="%prog: [options]", option_class=eng_option)
    parser.add_option(
        "", "--fft-size", dest="fft_size", type="string", default="8192",
        help="Set 8192 [default=%default]")
    parser.add_option(
        "", "--fft-threshold", dest="fft_threshold", type="string", default="-80",
        help="Set -80 [default=%default]")
    parser.add_option(
        "", "--filepath", dest="filepath", type="string", default="",
        help="Set filepath [default=%default]")
    parser.add_option(
        "", "--peak-file-location", dest="peak_file_location", type="string", default="",
        help="Set peak_file_location [default=%default]")
    parser.add_option(
        "", "--sample-rate", dest="sample_rate", type="string", default="1e6",
        help="Set 1e6 [default=%default]")
    parser.add_option(
        "", "--samples", dest="samples", type="string", default="4169300",
        help="Set sampes [default=%default]")
    return parser


def main(top_block_cls=strongest, options=None):
    if options is None:
        options, _ = argument_parser().parse_args()

    tb = top_block_cls(fft_size=options.fft_size, fft_threshold=options.fft_threshold, filepath=options.filepath, peak_file_location=options.peak_file_location, sample_rate=options.sample_rate, samples=options.samples)
    tb.start()
    tb.wait()


if __name__ == '__main__':
    main()
