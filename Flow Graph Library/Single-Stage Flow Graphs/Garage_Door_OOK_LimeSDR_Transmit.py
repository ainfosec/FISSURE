#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#
# SPDX-License-Identifier: GPL-3.0
#
# GNU Radio Python Flow Graph
# Title: Garage Door Ook Limesdr Transmit
# GNU Radio version: 3.10.1.1

from gnuradio import blocks
from gnuradio import gr
from gnuradio.filter import firdes
from gnuradio.fft import window
import sys
import signal
from argparse import ArgumentParser
from gnuradio.eng_arg import eng_float, intx
from gnuradio import eng_notation
import gnuradio.garage_door as garage_door
import gnuradio.limesdr as limesdr




class Garage_Door_OOK_LimeSDR_Transmit(gr.top_block):

    def __init__(self):
        gr.top_block.__init__(self, "Garage Door Ook Limesdr Transmit", catch_exceptions=True)

        ##################################################
        # Variables
        ##################################################
        self.tx_gain = tx_gain = 60
        self.tx_frequency = tx_frequency = 310.4e6
        self.tx_channel = tx_channel = 0
        self.string_variables = string_variables = ["dip_positions"]
        self.sample_rate = sample_rate = 1e6
        self.press_repetition_interval = press_repetition_interval = 60
        self.press_duration = press_duration = 0.5
        self.notes = notes = "Simulates a remote control button press for one DIP switch value."
        self.dip_positions = dip_positions = "1010101010"

        ##################################################
        # Blocks
        ##################################################
        self.limesdr_sink_0 = limesdr.sink('', int(tx_channel), '', '')

        self.garage_door_message_generator_0 = garage_door.message_generator(sample_rate,dip_positions,press_duration,press_repetition_interval)
        self.blocks_null_source_0 = blocks.null_source(gr.sizeof_gr_complex*1)
        self.blocks_multiply_const_vxx_0 = blocks.multiply_const_cc(0.9)


        ##################################################
        # Connections
        ##################################################
        self.connect((self.blocks_multiply_const_vxx_0, 0), (self.limesdr_sink_0, 0))
        self.connect((self.blocks_null_source_0, 0), (self.garage_door_message_generator_0, 0))
        self.connect((self.garage_door_message_generator_0, 0), (self.blocks_multiply_const_vxx_0, 0))


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

    def get_string_variables(self):
        return self.string_variables

    def set_string_variables(self, string_variables):
        self.string_variables = string_variables

    def get_sample_rate(self):
        return self.sample_rate

    def set_sample_rate(self, sample_rate):
        self.sample_rate = sample_rate
        self.garage_door_message_generator_0.set_sample_rate(self.sample_rate)

    def get_press_repetition_interval(self):
        return self.press_repetition_interval

    def set_press_repetition_interval(self, press_repetition_interval):
        self.press_repetition_interval = press_repetition_interval
        self.garage_door_message_generator_0.set_press_repetition_interval(self.press_repetition_interval)

    def get_press_duration(self):
        return self.press_duration

    def set_press_duration(self, press_duration):
        self.press_duration = press_duration
        self.garage_door_message_generator_0.set_press_duration(self.press_duration)

    def get_notes(self):
        return self.notes

    def set_notes(self, notes):
        self.notes = notes

    def get_dip_positions(self):
        return self.dip_positions

    def set_dip_positions(self, dip_positions):
        self.dip_positions = dip_positions
        self.garage_door_message_generator_0.set_dip_positions(self.dip_positions)




def main(top_block_cls=Garage_Door_OOK_LimeSDR_Transmit, options=None):
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
