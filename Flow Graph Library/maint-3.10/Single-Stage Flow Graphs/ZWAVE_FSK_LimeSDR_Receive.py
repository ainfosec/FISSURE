#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#
# SPDX-License-Identifier: GPL-3.0
#
# GNU Radio Python Flow Graph
# Title: Zwave Fsk Limesdr Receive
# GNU Radio version: 3.10.7.0

from gnuradio import analog
import math
from gnuradio import blocks
from gnuradio import blocks, gr
from gnuradio import filter
from gnuradio.filter import firdes
from gnuradio import gr
from gnuradio.fft import window
import sys
import signal
from argparse import ArgumentParser
from gnuradio.eng_arg import eng_float, intx
from gnuradio import eng_notation
import gnuradio.limesdr as limesdr
import gnuradio.zwave_poore as zwave_poore




class ZWAVE_FSK_LimeSDR_Receive(gr.top_block):

    def __init__(self):
        gr.top_block.__init__(self, "Zwave Fsk Limesdr Receive", catch_exceptions=True)

        ##################################################
        # Variables
        ##################################################
        self.sample_rate = sample_rate = 1e6
        self.rx_gain = rx_gain = 60
        self.rx_frequency = rx_frequency = 916e6
        self.rx_channel = rx_channel = 0
        self.notes = notes = "Decodes Z-Wave messages and prints the output. Tested against a Monoprice Z-Wave Plus RGB Smart Bulb."

        ##################################################
        # Blocks
        ##################################################

        self.zwave_poore_decoder_0 = zwave_poore.decoder()
        self.limesdr_source_0 = limesdr.source('', int(rx_channel), '')

        self.fir_filter_xxx_1_0 = filter.fir_filter_fff(1, 20*[0.05])
        self.fir_filter_xxx_1_0.declare_sample_delay(0)
        self.fir_filter_xxx_0 = filter.fir_filter_fff(1, 4*[0.25])
        self.fir_filter_xxx_0.declare_sample_delay(0)
        self.blocks_threshold_ff_0_0 = blocks.threshold_ff(.004, .004, 0)
        self.blocks_threshold_ff_0 = blocks.threshold_ff(0, 0, 0)
        self.blocks_message_debug_0 = blocks.message_debug(True, gr.log_levels.info)
        self.blocks_keep_one_in_n_0 = blocks.keep_one_in_n(gr.sizeof_float*1, 10)
        self.blocks_float_to_short_1 = blocks.float_to_short(1, 1)
        self.blocks_delay_1 = blocks.delay(gr.sizeof_gr_complex*1, 20)
        self.blocks_delay_0 = blocks.delay(gr.sizeof_float*1, 0)
        self.blocks_complex_to_mag_squared_0_0 = blocks.complex_to_mag_squared(1)
        self.blocks_burst_tagger_1 = blocks.burst_tagger(gr.sizeof_gr_complex)
        self.blocks_burst_tagger_1.set_true_tag('burst',True)
        self.blocks_burst_tagger_1.set_false_tag('burst',False)
        self.analog_quadrature_demod_cf_0 = analog.quadrature_demod_cf((sample_rate/(2*math.pi*80000/8.0)))


        ##################################################
        # Connections
        ##################################################
        self.msg_connect((self.zwave_poore_decoder_0, 'out'), (self.blocks_message_debug_0, 'print'))
        self.connect((self.analog_quadrature_demod_cf_0, 0), (self.fir_filter_xxx_0, 0))
        self.connect((self.blocks_burst_tagger_1, 0), (self.analog_quadrature_demod_cf_0, 0))
        self.connect((self.blocks_complex_to_mag_squared_0_0, 0), (self.fir_filter_xxx_1_0, 0))
        self.connect((self.blocks_delay_0, 0), (self.blocks_keep_one_in_n_0, 0))
        self.connect((self.blocks_delay_1, 0), (self.blocks_burst_tagger_1, 0))
        self.connect((self.blocks_float_to_short_1, 0), (self.blocks_burst_tagger_1, 1))
        self.connect((self.blocks_keep_one_in_n_0, 0), (self.zwave_poore_decoder_0, 0))
        self.connect((self.blocks_threshold_ff_0, 0), (self.blocks_delay_0, 0))
        self.connect((self.blocks_threshold_ff_0_0, 0), (self.blocks_float_to_short_1, 0))
        self.connect((self.fir_filter_xxx_0, 0), (self.blocks_threshold_ff_0, 0))
        self.connect((self.fir_filter_xxx_1_0, 0), (self.blocks_threshold_ff_0_0, 0))
        self.connect((self.limesdr_source_0, 0), (self.blocks_complex_to_mag_squared_0_0, 0))
        self.connect((self.limesdr_source_0, 0), (self.blocks_delay_1, 0))


    def get_sample_rate(self):
        return self.sample_rate

    def set_sample_rate(self, sample_rate):
        self.sample_rate = sample_rate
        self.analog_quadrature_demod_cf_0.set_gain((self.sample_rate/(2*math.pi*80000/8.0)))

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




def main(top_block_cls=ZWAVE_FSK_LimeSDR_Receive, options=None):
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
