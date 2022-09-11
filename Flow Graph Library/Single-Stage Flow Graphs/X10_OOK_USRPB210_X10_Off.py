#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#
# SPDX-License-Identifier: GPL-3.0
#
# GNU Radio Python Flow Graph
# Title: X10 Ook Usrpb210 X10 Off
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
from gnuradio import uhd
import time
import gnuradio.X10 as X10




class X10_OOK_USRPB210_X10_Off(gr.top_block):

    def __init__(self):
        gr.top_block.__init__(self, "X10 Ook Usrpb210 X10 Off", catch_exceptions=True)

        ##################################################
        # Variables
        ##################################################
        self.tx_usrp_gain = tx_usrp_gain = 60
        self.tx_usrp_frequency = tx_usrp_frequency = 310.8e6
        self.tx_usrp_channel = tx_usrp_channel = "A:A"
        self.tx_usrp_antenna = tx_usrp_antenna = "TX/RX"
        self.string_variables = string_variables = ["address_code","data_code"]
        self.serial = serial = "False"
        self.sample_rate = sample_rate = 1e6
        self.press_repetition_interval = press_repetition_interval = 10
        self.press_duration = press_duration = 4
        self.notes = notes = "Transmits an off message for a RadioShack Plug'n power outlet switch."
        self.data_code = data_code = "0x20"
        self.address_code = address_code = "0x60"

        ##################################################
        # Blocks
        ##################################################
        self.uhd_usrp_sink_0 = uhd.usrp_sink(
            ",".join((serial, "")),
            uhd.stream_args(
                cpu_format="fc32",
                args='',
                channels=list(range(0,1)),
            ),
            '',
        )
        self.uhd_usrp_sink_0.set_subdev_spec(tx_usrp_channel, 0)
        self.uhd_usrp_sink_0.set_samp_rate(sample_rate)
        self.uhd_usrp_sink_0.set_time_unknown_pps(uhd.time_spec(0))

        self.uhd_usrp_sink_0.set_center_freq(tx_usrp_frequency, 0)
        self.uhd_usrp_sink_0.set_antenna(tx_usrp_antenna, 0)
        self.uhd_usrp_sink_0.set_gain(tx_usrp_gain, 0)
        self.blocks_null_source_0 = blocks.null_source(gr.sizeof_gr_complex*1)
        self.blocks_multiply_const_vxx_0 = blocks.multiply_const_cc(0.9)
        self.X10_message_generator_0 = X10.message_generator(sample_rate,address_code,data_code,press_duration,press_repetition_interval)


        ##################################################
        # Connections
        ##################################################
        self.connect((self.X10_message_generator_0, 0), (self.blocks_multiply_const_vxx_0, 0))
        self.connect((self.blocks_multiply_const_vxx_0, 0), (self.uhd_usrp_sink_0, 0))
        self.connect((self.blocks_null_source_0, 0), (self.X10_message_generator_0, 0))


    def get_tx_usrp_gain(self):
        return self.tx_usrp_gain

    def set_tx_usrp_gain(self, tx_usrp_gain):
        self.tx_usrp_gain = tx_usrp_gain
        self.uhd_usrp_sink_0.set_gain(self.tx_usrp_gain, 0)

    def get_tx_usrp_frequency(self):
        return self.tx_usrp_frequency

    def set_tx_usrp_frequency(self, tx_usrp_frequency):
        self.tx_usrp_frequency = tx_usrp_frequency
        self.uhd_usrp_sink_0.set_center_freq(self.tx_usrp_frequency, 0)

    def get_tx_usrp_channel(self):
        return self.tx_usrp_channel

    def set_tx_usrp_channel(self, tx_usrp_channel):
        self.tx_usrp_channel = tx_usrp_channel

    def get_tx_usrp_antenna(self):
        return self.tx_usrp_antenna

    def set_tx_usrp_antenna(self, tx_usrp_antenna):
        self.tx_usrp_antenna = tx_usrp_antenna
        self.uhd_usrp_sink_0.set_antenna(self.tx_usrp_antenna, 0)

    def get_string_variables(self):
        return self.string_variables

    def set_string_variables(self, string_variables):
        self.string_variables = string_variables

    def get_serial(self):
        return self.serial

    def set_serial(self, serial):
        self.serial = serial

    def get_sample_rate(self):
        return self.sample_rate

    def set_sample_rate(self, sample_rate):
        self.sample_rate = sample_rate
        self.X10_message_generator_0.set_sample_rate(self.sample_rate)
        self.uhd_usrp_sink_0.set_samp_rate(self.sample_rate)

    def get_press_repetition_interval(self):
        return self.press_repetition_interval

    def set_press_repetition_interval(self, press_repetition_interval):
        self.press_repetition_interval = press_repetition_interval
        self.X10_message_generator_0.set_press_repetition_interval(self.press_repetition_interval)

    def get_press_duration(self):
        return self.press_duration

    def set_press_duration(self, press_duration):
        self.press_duration = press_duration
        self.X10_message_generator_0.set_press_duration(self.press_duration)

    def get_notes(self):
        return self.notes

    def set_notes(self, notes):
        self.notes = notes

    def get_data_code(self):
        return self.data_code

    def set_data_code(self, data_code):
        self.data_code = data_code
        self.X10_message_generator_0.set_data_code(self.data_code)

    def get_address_code(self):
        return self.address_code

    def set_address_code(self, address_code):
        self.address_code = address_code
        self.X10_message_generator_0.set_address_code(self.address_code)




def main(top_block_cls=X10_OOK_USRPB210_X10_Off, options=None):
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
