#!/usr/bin/env python2
# -*- coding: utf-8 -*-
##################################################
# GNU Radio Python Flow Graph
# Title: X10 Ook Limesdr Decode
# GNU Radio version: 3.7.13.5
##################################################


from gnuradio import blocks
from gnuradio import digital
from gnuradio import eng_notation
from gnuradio import filter
from gnuradio import gr
from gnuradio.eng_option import eng_option
from gnuradio.filter import firdes
from optparse import OptionParser
import X10
import limesdr


class X10_OOK_LimeSDR_Decode(gr.top_block):

    def __init__(self):
        gr.top_block.__init__(self, "X10 Ook Limesdr Decode")

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
        self.limesdr_source_0 = limesdr.source('', int(rx_channel), '')
        self.limesdr_source_0.set_sample_rate(sample_rate)
        self.limesdr_source_0.set_center_freq(rx_frequency, 0)
        self.limesdr_source_0.set_bandwidth(5e6,0)
        self.limesdr_source_0.set_gain(int(rx_gain),0)
        self.limesdr_source_0.set_antenna(255,0)
        self.limesdr_source_0.calibrate(5e6, 0)

        self.fir_filter_xxx_0_0 = filter.fir_filter_fff(1, ([0.125]*8))
        self.fir_filter_xxx_0_0.declare_sample_delay(0)
        self.digital_correlate_access_code_tag_xx_0 = digital.correlate_access_code_tag_bb('111111111111111111111111111111111111111100000000000000000000', 0, 'Start')
        self.blocks_threshold_ff_0_0 = blocks.threshold_ff(.05, .05, 0)
        self.blocks_multiply_const_vxx_0 = blocks.multiply_const_vff((1000, ))
        self.blocks_message_debug_0 = blocks.message_debug()
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
    tb.start()
    try:
        raw_input('Press Enter to quit: ')
    except EOFError:
        pass
    tb.stop()
    tb.wait()


if __name__ == '__main__':
    main()
