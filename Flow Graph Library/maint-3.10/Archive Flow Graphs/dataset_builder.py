#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#
# SPDX-License-Identifier: GPL-3.0
#
# GNU Radio Python Flow Graph
# Title: Dataset Builder
# Author: user
# GNU Radio version: 3.10.7.0

from gnuradio import analog
from gnuradio import blocks
import math
import pmt
from gnuradio import gr
from gnuradio.filter import firdes
from gnuradio.fft import window
import sys
import signal
from argparse import ArgumentParser
from gnuradio.eng_arg import eng_float, intx
from gnuradio import eng_notation




class dataset_builder(gr.top_block):

    def __init__(self, filepath='', freq_shift='0', frequency='0', new_filepath='', noise='0', phase_rot='0', sample_rate='0', scale='1'):
        gr.top_block.__init__(self, "Dataset Builder", catch_exceptions=True)

        ##################################################
        # Parameters
        ##################################################
        self.filepath = filepath
        self.freq_shift = freq_shift
        self.frequency = frequency
        self.new_filepath = new_filepath
        self.noise = noise
        self.phase_rot = phase_rot
        self.sample_rate = sample_rate
        self.scale = scale

        ##################################################
        # Blocks
        ##################################################

        self.blocks_rotator_cc_0 = blocks.rotator_cc(float(phase_rot), False)
        self.blocks_multiply_const_vxx_0 = blocks.multiply_const_cc(float(scale))
        self.blocks_freqshift_cc_0 = blocks.rotator_cc(2.0*math.pi*float(freq_shift)/float(sample_rate))
        self.blocks_file_source_0 = blocks.file_source(gr.sizeof_gr_complex*1, filepath, False, 0, 0)
        self.blocks_file_source_0.set_begin_tag(pmt.PMT_NIL)
        self.blocks_file_sink_0 = blocks.file_sink(gr.sizeof_gr_complex*1, new_filepath, False)
        self.blocks_file_sink_0.set_unbuffered(False)
        self.blocks_add_xx_0 = blocks.add_vcc(1)
        self.analog_fastnoise_source_x_0 = analog.fastnoise_source_c(analog.GR_GAUSSIAN, float(noise), 0, 8192)


        ##################################################
        # Connections
        ##################################################
        self.connect((self.analog_fastnoise_source_x_0, 0), (self.blocks_add_xx_0, 1))
        self.connect((self.blocks_add_xx_0, 0), (self.blocks_file_sink_0, 0))
        self.connect((self.blocks_file_source_0, 0), (self.blocks_rotator_cc_0, 0))
        self.connect((self.blocks_freqshift_cc_0, 0), (self.blocks_multiply_const_vxx_0, 0))
        self.connect((self.blocks_multiply_const_vxx_0, 0), (self.blocks_add_xx_0, 0))
        self.connect((self.blocks_rotator_cc_0, 0), (self.blocks_freqshift_cc_0, 0))


    def get_filepath(self):
        return self.filepath

    def set_filepath(self, filepath):
        self.filepath = filepath
        self.blocks_file_source_0.open(self.filepath, False)

    def get_freq_shift(self):
        return self.freq_shift

    def set_freq_shift(self, freq_shift):
        self.freq_shift = freq_shift
        self.blocks_freqshift_cc_0.set_phase_inc(2.0*math.pi*float(self.freq_shift)/float(self.sample_rate))

    def get_frequency(self):
        return self.frequency

    def set_frequency(self, frequency):
        self.frequency = frequency

    def get_new_filepath(self):
        return self.new_filepath

    def set_new_filepath(self, new_filepath):
        self.new_filepath = new_filepath
        self.blocks_file_sink_0.open(self.new_filepath)

    def get_noise(self):
        return self.noise

    def set_noise(self, noise):
        self.noise = noise
        self.analog_fastnoise_source_x_0.set_amplitude(float(self.noise))

    def get_phase_rot(self):
        return self.phase_rot

    def set_phase_rot(self, phase_rot):
        self.phase_rot = phase_rot
        self.blocks_rotator_cc_0.set_phase_inc(float(self.phase_rot))

    def get_sample_rate(self):
        return self.sample_rate

    def set_sample_rate(self, sample_rate):
        self.sample_rate = sample_rate
        self.blocks_freqshift_cc_0.set_phase_inc(2.0*math.pi*float(self.freq_shift)/float(self.sample_rate))

    def get_scale(self):
        return self.scale

    def set_scale(self, scale):
        self.scale = scale
        self.blocks_multiply_const_vxx_0.set_k(float(self.scale))



def argument_parser():
    parser = ArgumentParser()
    parser.add_argument(
        "--filepath", dest="filepath", type=str, default='',
        help="Set filepath [default=%(default)r]")
    parser.add_argument(
        "--freq-shift", dest="freq_shift", type=str, default='0',
        help="Set freq_shift [default=%(default)r]")
    parser.add_argument(
        "--frequency", dest="frequency", type=str, default='0',
        help="Set frequency [default=%(default)r]")
    parser.add_argument(
        "--new-filepath", dest="new_filepath", type=str, default='',
        help="Set new_filepath [default=%(default)r]")
    parser.add_argument(
        "--noise", dest="noise", type=str, default='0',
        help="Set noise [default=%(default)r]")
    parser.add_argument(
        "--phase-rot", dest="phase_rot", type=str, default='0',
        help="Set phase_rot [default=%(default)r]")
    parser.add_argument(
        "--sample-rate", dest="sample_rate", type=str, default='0',
        help="Set sample_rate [default=%(default)r]")
    parser.add_argument(
        "--scale", dest="scale", type=str, default='1',
        help="Set scale [default=%(default)r]")
    return parser


def main(top_block_cls=dataset_builder, options=None):
    if options is None:
        options = argument_parser().parse_args()
    tb = top_block_cls(filepath=options.filepath, freq_shift=options.freq_shift, frequency=options.frequency, new_filepath=options.new_filepath, noise=options.noise, phase_rot=options.phase_rot, sample_rate=options.sample_rate, scale=options.scale)

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
