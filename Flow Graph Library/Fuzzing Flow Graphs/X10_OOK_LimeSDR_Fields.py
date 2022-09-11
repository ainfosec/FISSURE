#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#
# SPDX-License-Identifier: GPL-3.0
#
# GNU Radio Python Flow Graph
# Title: X10 Ook Limesdr Fields
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
import fuzzer
import gnuradio.X10 as X10
import gnuradio.limesdr as limesdr




class X10_OOK_LimeSDR_Fields(gr.top_block):

    def __init__(self):
        gr.top_block.__init__(self, "X10 Ook Limesdr Fields", catch_exceptions=True)

        ##################################################
        # Variables
        ##################################################
        self.tx_gain = tx_gain = 60
        self.tx_frequency = tx_frequency = 310.8e6
        self.tx_channel = tx_channel = 0
        self.transmit_interval = transmit_interval = 4
        self.string_variables = string_variables = ["address_code","data_code"]
        self.sample_rate = sample_rate = 1e6
        self.library_filepath = library_filepath = "~/FISSURE/YAML/library.yaml"
        self.fuzzing_type = fuzzing_type = "['Random']"
        self.fuzzing_seed = fuzzing_seed = "0"
        self.fuzzing_protocol = fuzzing_protocol = "X10"
        self.fuzzing_packet_type = fuzzing_packet_type = "Default"
        self.fuzzing_min = fuzzing_min = "['0']"
        self.fuzzing_max = fuzzing_max = "['65535']"
        self.fuzzing_interval = fuzzing_interval = "5"
        self.fuzzing_fields = fuzzing_fields = "['Address Code']"
        self.fuzzing_data = fuzzing_data = "0"
        self.data_code = data_code = "0x00"
        self.address_code = address_code = "0x60"

        ##################################################
        # Blocks
        ##################################################
        self.limesdr_sink_0 = limesdr.sink('', int(tx_channel), '', '')

        self.fuzzer_fuzzer_0_0 = fuzzer.fuzzer(fuzzing_seed,fuzzing_fields,fuzzing_type,fuzzing_min,fuzzing_max,fuzzing_data,fuzzing_interval,fuzzing_protocol,fuzzing_packet_type,library_filepath)
        self.blocks_null_source_0 = blocks.null_source(gr.sizeof_gr_complex*1)
        self.blocks_multiply_const_vxx_0 = blocks.multiply_const_cc(0.9)
        self.X10_msg_gen_fuzzer_0 = X10.msg_gen_fuzzer(sample_rate,address_code,data_code,transmit_interval/2,transmit_interval)


        ##################################################
        # Connections
        ##################################################
        self.msg_connect((self.fuzzer_fuzzer_0_0, 'packet_out'), (self.X10_msg_gen_fuzzer_0, 'fuzzer_in'))
        self.connect((self.X10_msg_gen_fuzzer_0, 0), (self.blocks_multiply_const_vxx_0, 0))
        self.connect((self.blocks_multiply_const_vxx_0, 0), (self.limesdr_sink_0, 0))
        self.connect((self.blocks_null_source_0, 0), (self.X10_msg_gen_fuzzer_0, 0))


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

    def get_transmit_interval(self):
        return self.transmit_interval

    def set_transmit_interval(self, transmit_interval):
        self.transmit_interval = transmit_interval
        self.X10_msg_gen_fuzzer_0.set_press_duration(self.transmit_interval/2)
        self.X10_msg_gen_fuzzer_0.set_press_repetition_interval(self.transmit_interval)

    def get_string_variables(self):
        return self.string_variables

    def set_string_variables(self, string_variables):
        self.string_variables = string_variables

    def get_sample_rate(self):
        return self.sample_rate

    def set_sample_rate(self, sample_rate):
        self.sample_rate = sample_rate
        self.X10_msg_gen_fuzzer_0.set_sample_rate(self.sample_rate)

    def get_library_filepath(self):
        return self.library_filepath

    def set_library_filepath(self, library_filepath):
        self.library_filepath = library_filepath

    def get_fuzzing_type(self):
        return self.fuzzing_type

    def set_fuzzing_type(self, fuzzing_type):
        self.fuzzing_type = fuzzing_type

    def get_fuzzing_seed(self):
        return self.fuzzing_seed

    def set_fuzzing_seed(self, fuzzing_seed):
        self.fuzzing_seed = fuzzing_seed

    def get_fuzzing_protocol(self):
        return self.fuzzing_protocol

    def set_fuzzing_protocol(self, fuzzing_protocol):
        self.fuzzing_protocol = fuzzing_protocol

    def get_fuzzing_packet_type(self):
        return self.fuzzing_packet_type

    def set_fuzzing_packet_type(self, fuzzing_packet_type):
        self.fuzzing_packet_type = fuzzing_packet_type

    def get_fuzzing_min(self):
        return self.fuzzing_min

    def set_fuzzing_min(self, fuzzing_min):
        self.fuzzing_min = fuzzing_min

    def get_fuzzing_max(self):
        return self.fuzzing_max

    def set_fuzzing_max(self, fuzzing_max):
        self.fuzzing_max = fuzzing_max

    def get_fuzzing_interval(self):
        return self.fuzzing_interval

    def set_fuzzing_interval(self, fuzzing_interval):
        self.fuzzing_interval = fuzzing_interval

    def get_fuzzing_fields(self):
        return self.fuzzing_fields

    def set_fuzzing_fields(self, fuzzing_fields):
        self.fuzzing_fields = fuzzing_fields

    def get_fuzzing_data(self):
        return self.fuzzing_data

    def set_fuzzing_data(self, fuzzing_data):
        self.fuzzing_data = fuzzing_data

    def get_data_code(self):
        return self.data_code

    def set_data_code(self, data_code):
        self.data_code = data_code
        self.X10_msg_gen_fuzzer_0.set_data_code(self.data_code)

    def get_address_code(self):
        return self.address_code

    def set_address_code(self, address_code):
        self.address_code = address_code
        self.X10_msg_gen_fuzzer_0.set_address_code(self.address_code)




def main(top_block_cls=X10_OOK_LimeSDR_Fields, options=None):
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
