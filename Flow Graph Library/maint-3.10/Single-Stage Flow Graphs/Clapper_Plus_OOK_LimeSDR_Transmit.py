#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#
# SPDX-License-Identifier: GPL-3.0
#
# GNU Radio Python Flow Graph
# Title: Clapper Plus Ook Limesdr Transmit
# GNU Radio version: 3.10.7.0

from gnuradio import blocks
from gnuradio import gr
from gnuradio.filter import firdes
from gnuradio.fft import window
import sys
import signal
from argparse import ArgumentParser
from gnuradio.eng_arg import eng_float, intx
from gnuradio import eng_notation
import gnuradio.clapper_plus as clapper_plus
import gnuradio.limesdr as limesdr




class Clapper_Plus_OOK_LimeSDR_Transmit(gr.top_block):

    def __init__(self):
        gr.top_block.__init__(self, "Clapper Plus Ook Limesdr Transmit", catch_exceptions=True)

        ##################################################
        # Variables
        ##################################################
        self.tx_gain = tx_gain = 60
        self.tx_frequency = tx_frequency = 433.966e6
        self.tx_channel = tx_channel = 0
        self.sample_rate = sample_rate = 1e6
        self.press_repetition_interval = press_repetition_interval = 5
        self.notes = notes = "Generates a signal that is similar to one of two buttons on a Clapper Plus remote control."
        self.button2or3 = button2or3 = 2

        ##################################################
        # Blocks
        ##################################################

        self.limesdr_sink_0 = limesdr.sink('', int(tx_channel), '', '')

        self.clapper_plus_message_generator_433_0 = clapper_plus.message_generator_433(button2or3,sample_rate,press_repetition_interval)
        self.blocks_null_source_0 = blocks.null_source(gr.sizeof_gr_complex*1)
        self.blocks_multiply_const_vxx_0 = blocks.multiply_const_cc(0.9)


        ##################################################
        # Connections
        ##################################################
        self.connect((self.blocks_multiply_const_vxx_0, 0), (self.limesdr_sink_0, 0))
        self.connect((self.blocks_null_source_0, 0), (self.clapper_plus_message_generator_433_0, 0))
        self.connect((self.clapper_plus_message_generator_433_0, 0), (self.blocks_multiply_const_vxx_0, 0))


    def get_tx_gain(self):
        return self.tx_gain

    def set_tx_gain(self, tx_gain):
        self.tx_gain = tx_gain
        self.limesdr_sink_0.set_gain(int(self.tx_gain),0)
        self.limesdr_sink_0.set_gain(int(self.tx_gain),1)

    def get_tx_frequency(self):
        return self.tx_frequency

    def set_tx_frequency(self, tx_frequency):
        self.tx_frequency = tx_frequency
        self.limesdr_sink_0.set_center_freq(self.tx_frequency, 0)

    def get_tx_channel(self):
        return self.tx_channel

    def set_tx_channel(self, tx_channel):
        self.tx_channel = tx_channel

    def get_sample_rate(self):
        return self.sample_rate

    def set_sample_rate(self, sample_rate):
        self.sample_rate = sample_rate
        self.clapper_plus_message_generator_433_0.set_sample_rate(self.sample_rate)

    def get_press_repetition_interval(self):
        return self.press_repetition_interval

    def set_press_repetition_interval(self, press_repetition_interval):
        self.press_repetition_interval = press_repetition_interval
        self.clapper_plus_message_generator_433_0.set_press_repetition_interval(self.press_repetition_interval)

    def get_notes(self):
        return self.notes

    def set_notes(self, notes):
        self.notes = notes

    def get_button2or3(self):
        return self.button2or3

    def set_button2or3(self, button2or3):
        self.button2or3 = button2or3
        self.clapper_plus_message_generator_433_0.set_button(self.button2or3)




def main(top_block_cls=Clapper_Plus_OOK_LimeSDR_Transmit, options=None):
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
