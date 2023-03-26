#!/usr/bin/env python2
# -*- coding: utf-8 -*-
##################################################
# GNU Radio Python Flow Graph
# Title: Dataset Builder
# GNU Radio version: 3.7.13.5
##################################################


from gnuradio import analog
from gnuradio import blocks
from gnuradio import eng_notation
from gnuradio import gr
from gnuradio.eng_option import eng_option
from gnuradio.filter import firdes
from optparse import OptionParser
import pmt


class dataset_builder(gr.top_block):

    def __init__(self, filepath="", freq_shift="", frequency='0', new_filepath="", noise="0", phase_rot="0", sample_rate='0', scale="1"):
        gr.top_block.__init__(self, "Dataset Builder")

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
        self.blocks_rotator_cc_0 = blocks.rotator_cc(float(phase_rot))
        self.blocks_multiply_const_vxx_0 = blocks.multiply_const_vcc((float(scale), ))
        self.blocks_file_source_0 = blocks.file_source(gr.sizeof_gr_complex*1, filepath, False)
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
        self.connect((self.blocks_multiply_const_vxx_0, 0), (self.blocks_add_xx_0, 0))
        self.connect((self.blocks_rotator_cc_0, 0), (self.blocks_multiply_const_vxx_0, 0))

    def get_filepath(self):
        return self.filepath

    def set_filepath(self, filepath):
        self.filepath = filepath
        self.blocks_file_source_0.open(self.filepath, False)

    def get_freq_shift(self):
        return self.freq_shift

    def set_freq_shift(self, freq_shift):
        self.freq_shift = freq_shift

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

    def get_scale(self):
        return self.scale

    def set_scale(self, scale):
        self.scale = scale
        self.blocks_multiply_const_vxx_0.set_k((float(self.scale), ))


def argument_parser():
    parser = OptionParser(usage="%prog: [options]", option_class=eng_option)
    parser.add_option(
        "", "--filepath", dest="filepath", type="string", default="",
        help="Set filepath [default=%default]")
    parser.add_option(
        "", "--freq-shift", dest="freq_shift", type="string", default="",
        help="Set freq_shift [default=%default]")
    parser.add_option(
        "", "--frequency", dest="frequency", type="string", default='0',
        help="Set frequency [default=%default]")
    parser.add_option(
        "", "--new-filepath", dest="new_filepath", type="string", default="",
        help="Set new_filepath [default=%default]")
    parser.add_option(
        "", "--noise", dest="noise", type="string", default="0",
        help="Set noise [default=%default]")
    parser.add_option(
        "", "--phase-rot", dest="phase_rot", type="string", default="0",
        help="Set phase_rot [default=%default]")
    parser.add_option(
        "", "--sample-rate", dest="sample_rate", type="string", default='0',
        help="Set sample_rate [default=%default]")
    parser.add_option(
        "", "--scale", dest="scale", type="string", default="1",
        help="Set scale [default=%default]")
    return parser


def main(top_block_cls=dataset_builder, options=None):
    if options is None:
        options, _ = argument_parser().parse_args()

    tb = top_block_cls(filepath=options.filepath, freq_shift=options.freq_shift, frequency=options.frequency, new_filepath=options.new_filepath, noise=options.noise, phase_rot=options.phase_rot, sample_rate=options.sample_rate, scale=options.scale)
    tb.start()
    tb.wait()


if __name__ == '__main__':
    main()
