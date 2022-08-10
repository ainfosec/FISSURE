#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#
# SPDX-License-Identifier: GPL-3.0
#
# GNU Radio Python Flow Graph
# Title: X10 Ook Limesdr X10 On
# GNU Radio version: 3.8.1.0

from gnuradio import blocks
from gnuradio import gr
from gnuradio.filter import firdes
import sys
import signal
from argparse import ArgumentParser
from gnuradio.eng_arg import eng_float, intx
from gnuradio import eng_notation
import X10
import limesdr

class X10_OOK_LimeSDR_X10_On(gr.top_block):

    def __init__(self):
        gr.top_block.__init__(self, "X10 Ook Limesdr X10 On")

        ##################################################
        # Variables
        ##################################################
        self.tx_gain = tx_gain = 60
        self.tx_frequency = tx_frequency = 310.8e6
        self.tx_channel = tx_channel = 0
        self.string_variables = string_variables = ["address_code","data_code"]
        self.sample_rate = sample_rate = 1e6
        self.press_repetition_interval = press_repetition_interval = 10
        self.press_duration = press_duration = 4
        self.notes = notes = "Transmits an on message for a RadioShack Plug'n power outlet switch."
        self.data_code = data_code = "0x00"
        self.address_code = address_code = "0x60"

        ##################################################
        # Blocks
        ##################################################
        self.limesdr_sink_0 = limesdr.sink('', 0, '', '')


        self.limesdr_sink_0.set_sample_rate(sample_rate)


        self.limesdr_sink_0.set_center_freq(tx_frequency, 0)

        self.limesdr_sink_0.set_bandwidth(5e6, 0)




        self.limesdr_sink_0.set_gain(int(tx_gain), 0)


        self.limesdr_sink_0.set_antenna(255, 0)


        self.limesdr_sink_0.calibrate(5e6, 0)
        self.blocks_null_source_0 = blocks.null_source(gr.sizeof_gr_complex*1)
        self.blocks_multiply_const_vxx_0 = blocks.multiply_const_cc(0.9)
        self.X10_message_generator_0 = X10.message_generator(sample_rate,address_code,data_code,press_duration,press_repetition_interval)



        ##################################################
        # Connections
        ##################################################
        self.connect((self.X10_message_generator_0, 0), (self.blocks_multiply_const_vxx_0, 0))
        self.connect((self.blocks_multiply_const_vxx_0, 0), (self.limesdr_sink_0, 0))
        self.connect((self.blocks_null_source_0, 0), (self.X10_message_generator_0, 0))

    def get_tx_gain(self):
        return self.tx_gain

    def set_tx_gain(self, tx_gain):
        self.tx_gain = tx_gain
        self.limesdr_sink_0.set_gain(int(self.tx_gain), 0)
        self.limesdr_sink_0.set_gain(int(self.tx_gain), 1)

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

    def get_press_repetition_interval(self):
        return self.press_repetition_interval

    def set_press_repetition_interval(self, press_repetition_interval):
        self.press_repetition_interval = press_repetition_interval

    def get_press_duration(self):
        return self.press_duration

    def set_press_duration(self, press_duration):
        self.press_duration = press_duration

    def get_notes(self):
        return self.notes

    def set_notes(self, notes):
        self.notes = notes

    def get_data_code(self):
        return self.data_code

    def set_data_code(self, data_code):
        self.data_code = data_code

    def get_address_code(self):
        return self.address_code

    def set_address_code(self, address_code):
        self.address_code = address_code



def main(top_block_cls=X10_OOK_LimeSDR_X10_On, options=None):
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
