#!/usr/bin/env python2
# -*- coding: utf-8 -*-
##################################################
# GNU Radio Python Flow Graph
# Title: Normal Decay
# GNU Radio version: 3.7.13.5
##################################################


from gnuradio import blocks
from gnuradio import eng_notation
from gnuradio import gr
from gnuradio.eng_option import eng_option
from gnuradio.filter import firdes
from optparse import OptionParser
import pmt


class normal_decay(gr.top_block):

    def __init__(self, filepath="", threshold="5000", sample_rate="1e6", decay="0.0002"):
        gr.top_block.__init__(self, "Normal Decay")

        ##################################################
        # Parameters
        ##################################################
        self.filepath = filepath
        self.threshold = threshold
        self.sample_rate = sample_rate
        self.decay = decay

        ##################################################
        # Blocks
        ##################################################
        self.blocks_throttle_0 = blocks.throttle(gr.sizeof_gr_complex*1, float(sample_rate),True)
        self.blocks_threshold_ff_0 = blocks.threshold_ff(float(threshold), float(threshold), 0)
        self.blocks_tagged_file_sink_0 = blocks.tagged_file_sink(gr.sizeof_short*1, int(float(sample_rate)))
        self.blocks_rms_xx_0 = blocks.rms_ff(float(decay))
        self.blocks_interleaved_short_to_complex_0 = blocks.interleaved_short_to_complex(False, False)
        self.blocks_float_to_short_0 = blocks.float_to_short(1, 1)
        self.blocks_file_source_0 = blocks.file_source(gr.sizeof_short*1, filepath, False)
        self.blocks_file_source_0.set_begin_tag(pmt.PMT_NIL)
        self.blocks_delay_0 = blocks.delay(gr.sizeof_gr_complex*1, 5000)
        self.blocks_complex_to_mag_squared_0 = blocks.complex_to_mag_squared(1)
        self.blocks_complex_to_interleaved_short_0 = blocks.complex_to_interleaved_short(False)
        self.blocks_burst_tagger_0 = blocks.burst_tagger(gr.sizeof_gr_complex)
        self.blocks_burst_tagger_0.set_true_tag('burst',True)
        self.blocks_burst_tagger_0.set_false_tag('burst',False)




        ##################################################
        # Connections
        ##################################################
        self.connect((self.blocks_burst_tagger_0, 0), (self.blocks_complex_to_interleaved_short_0, 0))
        self.connect((self.blocks_complex_to_interleaved_short_0, 0), (self.blocks_tagged_file_sink_0, 0))
        self.connect((self.blocks_complex_to_mag_squared_0, 0), (self.blocks_rms_xx_0, 0))
        self.connect((self.blocks_delay_0, 0), (self.blocks_burst_tagger_0, 0))
        self.connect((self.blocks_file_source_0, 0), (self.blocks_interleaved_short_to_complex_0, 0))
        self.connect((self.blocks_float_to_short_0, 0), (self.blocks_burst_tagger_0, 1))
        self.connect((self.blocks_interleaved_short_to_complex_0, 0), (self.blocks_throttle_0, 0))
        self.connect((self.blocks_rms_xx_0, 0), (self.blocks_threshold_ff_0, 0))
        self.connect((self.blocks_threshold_ff_0, 0), (self.blocks_float_to_short_0, 0))
        self.connect((self.blocks_throttle_0, 0), (self.blocks_complex_to_mag_squared_0, 0))
        self.connect((self.blocks_throttle_0, 0), (self.blocks_delay_0, 0))

    def get_filepath(self):
        return self.filepath

    def set_filepath(self, filepath):
        self.filepath = filepath
        self.blocks_file_source_0.open(self.filepath, False)

    def get_threshold(self):
        return self.threshold

    def set_threshold(self, threshold):
        self.threshold = threshold
        self.blocks_threshold_ff_0.set_hi(float(self.threshold))
        self.blocks_threshold_ff_0.set_lo(float(self.threshold))

    def get_sample_rate(self):
        return self.sample_rate

    def set_sample_rate(self, sample_rate):
        self.sample_rate = sample_rate
        self.blocks_throttle_0.set_sample_rate(float(self.sample_rate))

    def get_decay(self):
        return self.decay

    def set_decay(self, decay):
        self.decay = decay
        self.blocks_rms_xx_0.set_alpha(float(self.decay))


def argument_parser():
    parser = OptionParser(usage="%prog: [options]", option_class=eng_option)
    parser.add_option(
        "", "--filepath", dest="filepath", type="string", default="",
        help="Set filepath [default=%default]")
    parser.add_option(
        "", "--threshold", dest="threshold", type="string", default="5000",
        help="Set 5000 [default=%default]")
    parser.add_option(
        "", "--sample-rate", dest="sample_rate", type="string", default="1e6",
        help="Set 1e6 [default=%default]")
    parser.add_option(
        "", "--decay", dest="decay", type="string", default="0.0002",
        help="Set 0.0002 [default=%default]")
    return parser


def main(top_block_cls=normal_decay, options=None):
    if options is None:
        options, _ = argument_parser().parse_args()

    tb = top_block_cls(filepath=options.filepath, threshold=options.threshold, sample_rate=options.sample_rate, decay=options.decay)
    tb.start()
    tb.wait()


if __name__ == '__main__':
    main()
