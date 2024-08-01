#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#
# SPDX-License-Identifier: GPL-3.0
#
# GNU Radio Python Flow Graph
# Title: X10 Ook Limesdr Decode
# GNU Radio version: 3.10.7.0

from gnuradio import blocks
from gnuradio import blocks, gr
from gnuradio import digital
from gnuradio import filter
from gnuradio.filter import firdes
from gnuradio import gr
from gnuradio.fft import window
import sys
import signal
from argparse import ArgumentParser
from gnuradio.eng_arg import eng_float, intx
from gnuradio import eng_notation
import gnuradio.X10 as X10
import gnuradio.limesdr as limesdr




class X10_OOK_LimeSDR_Decode(gr.top_block):

    def __init__(self):
        gr.top_block.__init__(self, "X10 Ook Limesdr Decode", catch_exceptions=True)

        ##################################################
        # Variables
        ##################################################
        self.sample_rate = sample_rate = 1e6
        self.rx_gain = rx_gain = 60
        self.rx_frequency = rx_frequency = 310.8e6
        self.rx_channel = rx_channel = 0
        self.notes = notes = "Decodes X10 signals and prints the output."

        ##################################################
        # Blocks
        ##################################################

        self.limesdr_source_0 = limesdr.source('', 0, '')

        self.fir_filter_xxx_0_0 = filter.fir_filter_fff(1, [0.125]*8)
        self.fir_filter_xxx_0_0.declare_sample_delay(0)
        self.digital_correlate_access_code_tag_xx_0 = digital.correlate_access_code_tag_bb('111111111111111111111111111111111111111100000000000000000000', 0, 'Start')
        self.blocks_threshold_ff_0_0 = blocks.threshold_ff(.05, .05, 0)
        self.blocks_multiply_const_vxx_0 = blocks.multiply_const_ff(1000)
        self.blocks_message_debug_0 = blocks.message_debug(True, gr.log_levels.info)
        self.blocks_keep_one_in_n_0_0 = blocks.keep_one_in_n(gr.sizeof_float*1, 125)
        self.blocks_float_to_uchar_0 = blocks.float_to_uchar()
        self.blocks_complex_to_mag_squared_0 = blocks.complex_to_mag_squared(1)
        self.blocks_char_to_float_0 = blocks.char_to_float(1, 1)
        self.X10_x10_decoder_0 = X10.x10_decoder()


        ##################################################
        # Connections
        ##################################################
        self.msg_connect((self.X10_x10_decoder_0, 'out'), (self.blocks_message_debug_0, 'print'))
        self.connect((self.blocks_char_to_float_0, 0), (self.X10_x10_decoder_0, 0))
        self.connect((self.blocks_complex_to_mag_squared_0, 0), (self.fir_filter_xxx_0_0, 0))
        self.connect((self.blocks_float_to_uchar_0, 0), (self.digital_correlate_access_code_tag_xx_0, 0))
        self.connect((self.blocks_keep_one_in_n_0_0, 0), (self.blocks_float_to_uchar_0, 0))
        self.connect((self.blocks_multiply_const_vxx_0, 0), (self.blocks_threshold_ff_0_0, 0))
        self.connect((self.blocks_threshold_ff_0_0, 0), (self.blocks_keep_one_in_n_0_0, 0))
        self.connect((self.digital_correlate_access_code_tag_xx_0, 0), (self.blocks_char_to_float_0, 0))
        self.connect((self.fir_filter_xxx_0_0, 0), (self.blocks_multiply_const_vxx_0, 0))
        self.connect((self.limesdr_source_0, 0), (self.blocks_complex_to_mag_squared_0, 0))


    def get_sample_rate(self):
        return self.sample_rate

    def set_sample_rate(self, sample_rate):
        self.sample_rate = sample_rate

    def get_rx_gain(self):
        return self.rx_gain

    def set_rx_gain(self, rx_gain):
        self.rx_gain = rx_gain
        self.limesdr_source_0.set_gain(int(self.rx_gain),0)
        self.limesdr_source_0.set_gain(int(self.rx_gain),1)

    def get_rx_frequency(self):
        return self.rx_frequency

    def set_rx_frequency(self, rx_frequency):
        self.rx_frequency = rx_frequency
        self.limesdr_source_0.set_center_freq(self.rx_frequency, 0)

    def get_rx_channel(self):
        return self.rx_channel

    def set_rx_channel(self, rx_channel):
        self.rx_channel = rx_channel

    def get_notes(self):
        return self.notes

    def set_notes(self, notes):
        self.notes = notes




def main(top_block_cls=X10_OOK_LimeSDR_Decode, options=None):
    tb = top_block_cls()

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
