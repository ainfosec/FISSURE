#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#
# SPDX-License-Identifier: GPL-3.0
#
# GNU Radio Python Flow Graph
# Title: Not titled yet
# GNU Radio version: 3.8.5.0

from gnuradio import blocks
import pmt
from gnuradio import filter
from gnuradio.filter import firdes
from gnuradio import gr
import sys
import signal
from argparse import ArgumentParser
from gnuradio.eng_arg import eng_float, intx
from gnuradio import eng_notation


class bandpass(gr.top_block):

    def __init__(self, bandpass_freq='100000', bandpass_width='100000', beta='6.76', filepath="/home/user/Conditioner/Data/tpms/four_tires2.iq", sample_rate='1e6', threshold='.002', transition_width='10e3'):
        gr.top_block.__init__(self, "Not titled yet")

        ##################################################
        # Parameters
        ##################################################
        self.bandpass_freq = bandpass_freq
        self.bandpass_width = bandpass_width
        self.beta = beta
        self.filepath = filepath
        self.sample_rate = sample_rate
        self.threshold = threshold
        self.transition_width = transition_width

        ##################################################
        # Blocks
        ##################################################
        self.fir_filter_xxx_1_0 = filter.fir_filter_fff(1, 50*[0.02])
        self.fir_filter_xxx_1_0.declare_sample_delay(0)
        self.blocks_throttle_0 = blocks.throttle(gr.sizeof_gr_complex*1, float(sample_rate),True)
        self.blocks_threshold_ff_0_0 = blocks.threshold_ff(float(threshold), float(threshold), 0)
        self.blocks_tagged_file_sink_0 = blocks.tagged_file_sink(gr.sizeof_gr_complex*1, int(float(sample_rate)))
        self.blocks_float_to_short_1 = blocks.float_to_short(1, 1)
        self.blocks_file_source_0 = blocks.file_source(gr.sizeof_gr_complex*1, filepath, False, 0, 0)
        self.blocks_file_source_0.set_begin_tag(pmt.PMT_NIL)
        self.blocks_delay_1 = blocks.delay(gr.sizeof_gr_complex*1, 50)
        self.blocks_complex_to_mag_squared_0_0 = blocks.complex_to_mag_squared(1)
        self.blocks_burst_tagger_1 = blocks.burst_tagger(gr.sizeof_gr_complex)
        self.blocks_burst_tagger_1.set_true_tag('burst',True)
        self.blocks_burst_tagger_1.set_false_tag('burst',False)
        self.band_pass_filter_0 = filter.fir_filter_ccf(
            1,
            firdes.band_pass(
                1,
                float(sample_rate),
                float(bandpass_freq)-float(bandpass_width)/2,
                float(bandpass_freq)+float(bandpass_width)/2,
                float(bandpass_width)/10,
                firdes.WIN_HAMMING,
                float(beta)))


        ##################################################
        # Connections
        ##################################################
        self.connect((self.band_pass_filter_0, 0), (self.blocks_complex_to_mag_squared_0_0, 0))
        self.connect((self.band_pass_filter_0, 0), (self.blocks_delay_1, 0))
        self.connect((self.blocks_burst_tagger_1, 0), (self.blocks_tagged_file_sink_0, 0))
        self.connect((self.blocks_complex_to_mag_squared_0_0, 0), (self.fir_filter_xxx_1_0, 0))
        self.connect((self.blocks_delay_1, 0), (self.blocks_burst_tagger_1, 0))
        self.connect((self.blocks_file_source_0, 0), (self.blocks_throttle_0, 0))
        self.connect((self.blocks_float_to_short_1, 0), (self.blocks_burst_tagger_1, 1))
        self.connect((self.blocks_threshold_ff_0_0, 0), (self.blocks_float_to_short_1, 0))
        self.connect((self.blocks_throttle_0, 0), (self.band_pass_filter_0, 0))
        self.connect((self.fir_filter_xxx_1_0, 0), (self.blocks_threshold_ff_0_0, 0))


    def get_bandpass_freq(self):
        return self.bandpass_freq

    def set_bandpass_freq(self, bandpass_freq):
        self.bandpass_freq = bandpass_freq
        self.band_pass_filter_0.set_taps(firdes.band_pass(1, float(self.sample_rate), float(self.bandpass_freq)-float(self.bandpass_width)/2, float(self.bandpass_freq)+float(self.bandpass_width)/2, float(self.bandpass_width)/10, firdes.WIN_HAMMING, float(self.beta)))

    def get_bandpass_width(self):
        return self.bandpass_width

    def set_bandpass_width(self, bandpass_width):
        self.bandpass_width = bandpass_width
        self.band_pass_filter_0.set_taps(firdes.band_pass(1, float(self.sample_rate), float(self.bandpass_freq)-float(self.bandpass_width)/2, float(self.bandpass_freq)+float(self.bandpass_width)/2, float(self.bandpass_width)/10, firdes.WIN_HAMMING, float(self.beta)))

    def get_beta(self):
        return self.beta

    def set_beta(self, beta):
        self.beta = beta
        self.band_pass_filter_0.set_taps(firdes.band_pass(1, float(self.sample_rate), float(self.bandpass_freq)-float(self.bandpass_width)/2, float(self.bandpass_freq)+float(self.bandpass_width)/2, float(self.bandpass_width)/10, firdes.WIN_HAMMING, float(self.beta)))

    def get_filepath(self):
        return self.filepath

    def set_filepath(self, filepath):
        self.filepath = filepath
        self.blocks_file_source_0.open(self.filepath, False)

    def get_sample_rate(self):
        return self.sample_rate

    def set_sample_rate(self, sample_rate):
        self.sample_rate = sample_rate
        self.band_pass_filter_0.set_taps(firdes.band_pass(1, float(self.sample_rate), float(self.bandpass_freq)-float(self.bandpass_width)/2, float(self.bandpass_freq)+float(self.bandpass_width)/2, float(self.bandpass_width)/10, firdes.WIN_HAMMING, float(self.beta)))
        self.blocks_throttle_0.set_sample_rate(float(self.sample_rate))

    def get_threshold(self):
        return self.threshold

    def set_threshold(self, threshold):
        self.threshold = threshold
        self.blocks_threshold_ff_0_0.set_hi(float(self.threshold))
        self.blocks_threshold_ff_0_0.set_lo(float(self.threshold))

    def get_transition_width(self):
        return self.transition_width

    def set_transition_width(self, transition_width):
        self.transition_width = transition_width




def argument_parser():
    parser = ArgumentParser()
    parser.add_argument(
        "--bandpass-freq", dest="bandpass_freq", type=str, default='100000',
        help="Set 100000 [default=%(default)r]")
    parser.add_argument(
        "--bandpass-width", dest="bandpass_width", type=str, default='100000',
        help="Set 100000 [default=%(default)r]")
    parser.add_argument(
        "--beta", dest="beta", type=str, default='6.76',
        help="Set 6.76 [default=%(default)r]")
    parser.add_argument(
        "--filepath", dest="filepath", type=str, default="/home/user/Conditioner/Data/tpms/four_tires2.iq",
        help="Set /home/user/Conditioner/Data/tpms/four_tires2.iq [default=%(default)r]")
    parser.add_argument(
        "--sample-rate", dest="sample_rate", type=str, default='1e6',
        help="Set 1e6 [default=%(default)r]")
    parser.add_argument(
        "--threshold", dest="threshold", type=str, default='.002',
        help="Set .002 [default=%(default)r]")
    parser.add_argument(
        "--transition-width", dest="transition_width", type=str, default='10e3',
        help="Set 10e3 [default=%(default)r]")
    return parser


def main(top_block_cls=bandpass, options=None):
    if options is None:
        options = argument_parser().parse_args()
    tb = top_block_cls(bandpass_freq=options.bandpass_freq, bandpass_width=options.bandpass_width, beta=options.beta, filepath=options.filepath, sample_rate=options.sample_rate, threshold=options.threshold, transition_width=options.transition_width)

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
