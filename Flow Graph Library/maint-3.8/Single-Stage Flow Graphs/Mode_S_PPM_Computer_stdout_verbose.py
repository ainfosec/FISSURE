#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#
# SPDX-License-Identifier: GPL-3.0
#
# GNU Radio Python Flow Graph
# Title: Mode S Ppm Computer Stdout Verbose
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
import adsb


class Mode_S_PPM_Computer_stdout_verbose(gr.top_block):

    def __init__(self, filepath="/home/laptop1/Documents/ads-b_signals/airport/adsb.iq", samp_rate='2e6', threshold='0.01'):
        gr.top_block.__init__(self, "Mode S Ppm Computer Stdout Verbose")

        ##################################################
        # Parameters
        ##################################################
        self.filepath = filepath
        self.samp_rate = samp_rate
        self.threshold = threshold

        ##################################################
        # Variables
        ##################################################
        self.notes = notes = "Prints formatted decoded ADSB data (gr-adsb) originating from an IQ file to stdout with the brief option selected."

        ##################################################
        # Blocks
        ##################################################
        self.blocks_throttle_0 = blocks.throttle(gr.sizeof_gr_complex*1, float(samp_rate),True)
        self.blocks_null_sink_0 = blocks.null_sink(gr.sizeof_float*1)
        self.blocks_file_source_0 = blocks.file_source(gr.sizeof_gr_complex*1, str(filepath), False, 0, 0)
        self.blocks_file_source_0.set_begin_tag(pmt.PMT_NIL)
        self.blocks_complex_to_mag_squared_0 = blocks.complex_to_mag_squared(1)
        self.adsb_framer_1 = adsb.framer(float(samp_rate), float(threshold))
        self.adsb_demod_0 = adsb.demod(float(samp_rate))
        self.adsb_decoder_0_0 = adsb.decoder("All Messages", "None", "Verbose")


        ##################################################
        # Connections
        ##################################################
        self.msg_connect((self.adsb_demod_0, 'demodulated'), (self.adsb_decoder_0_0, 'demodulated'))
        self.connect((self.adsb_demod_0, 0), (self.blocks_null_sink_0, 0))
        self.connect((self.adsb_framer_1, 0), (self.adsb_demod_0, 0))
        self.connect((self.blocks_complex_to_mag_squared_0, 0), (self.adsb_framer_1, 0))
        self.connect((self.blocks_file_source_0, 0), (self.blocks_throttle_0, 0))
        self.connect((self.blocks_throttle_0, 0), (self.blocks_complex_to_mag_squared_0, 0))


    def get_filepath(self):
        return self.filepath

    def set_filepath(self, filepath):
        self.filepath = filepath
        self.blocks_file_source_0.open(str(self.filepath), False)

    def get_samp_rate(self):
        return self.samp_rate

    def set_samp_rate(self, samp_rate):
        self.samp_rate = samp_rate
        self.blocks_throttle_0.set_sample_rate(float(self.samp_rate))

    def get_threshold(self):
        return self.threshold

    def set_threshold(self, threshold):
        self.threshold = threshold
        self.adsb_framer_1.set_threshold(float(self.threshold))

    def get_notes(self):
        return self.notes

    def set_notes(self, notes):
        self.notes = notes




def argument_parser():
    parser = ArgumentParser()
    parser.add_argument(
        "--filepath", dest="filepath", type=str, default="/home/laptop1/Documents/ads-b_signals/airport/adsb.iq",
        help="Set filepath [default=%(default)r]")
    parser.add_argument(
        "--samp-rate", dest="samp_rate", type=str, default='2e6',
        help="Set samp_rate [default=%(default)r]")
    parser.add_argument(
        "--threshold", dest="threshold", type=str, default='0.01',
        help="Set threshold [default=%(default)r]")
    return parser


def main(top_block_cls=Mode_S_PPM_Computer_stdout_verbose, options=None):
    if options is None:
        options = argument_parser().parse_args()
    tb = top_block_cls(filepath=options.filepath, samp_rate=options.samp_rate, threshold=options.threshold)

    def sig_handler(sig=None, frame=None):
        tb.stop()
        tb.wait()

        sys.exit(0)

    signal.signal(signal.SIGINT, sig_handler)
    signal.signal(signal.SIGTERM, sig_handler)

    tb.start()

    try:
        input('Press Enter to quit: ')
    except EOFError:
        pass
    tb.stop()
    tb.wait()


if __name__ == '__main__':
    main()
