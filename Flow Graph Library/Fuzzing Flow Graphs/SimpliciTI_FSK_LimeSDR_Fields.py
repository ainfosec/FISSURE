#!/usr/bin/env python2
# -*- coding: utf-8 -*-
##################################################
# GNU Radio Python Flow Graph
# Title: Simpliciti Fsk Limesdr Fields
# Generated: Fri Oct  8 19:49:41 2021
##################################################


from gnuradio import blocks
from gnuradio import digital
from gnuradio import eng_notation
from gnuradio import filter
from gnuradio import gr
from gnuradio.eng_option import eng_option
from gnuradio.filter import firdes
from optparse import OptionParser
import fuzzer
import limesdr


class SimpliciTI_FSK_LimeSDR_Fields(gr.top_block):

    def __init__(self):
        gr.top_block.__init__(self, "Simpliciti Fsk Limesdr Fields")

        ##################################################
        # Variables
        ##################################################
        self.tx_gain = tx_gain = 60
        self.tx_frequency = tx_frequency = 2425.715e6
        self.tx_channel = tx_channel = 0
        self.sampling_multiple = sampling_multiple = 16
        self.sampling_factor = sampling_factor = 100
        self.sample_rate = sample_rate = 4e6
        self.library_filepath = library_filepath = "~/FISSURE/YAML/library.yaml"
        self.fuzzing_type = fuzzing_type = "['Random','Sequential']"
        self.fuzzing_seed = fuzzing_seed = "0"
        self.fuzzing_protocol = fuzzing_protocol = "SimpliciTI"
        self.fuzzing_packet_type = fuzzing_packet_type = "ED-Data"
        self.fuzzing_min = fuzzing_min = "['0','0']"
        self.fuzzing_max = fuzzing_max = "['255','255']"
        self.fuzzing_interval = fuzzing_interval = "1"
        self.fuzzing_fields = fuzzing_fields = "['Temperature LSB','Voltage']"
        self.fuzzing_data = fuzzing_data = "0"
        self.filepath = filepath = "/home/user/FISSURE/Flow Graph Library/Single-Stage Flow Graphs/Attack Files/SimpliciTI_Add_Node2.bin"
        self.data_rate = data_rate = 2398.9677429

        ##################################################
        # Blocks
        ##################################################
        self.limesdr_sink_0 = limesdr.sink('', int(tx_channel), '', '')
        self.limesdr_sink_0.set_sample_rate(sample_rate)
        self.limesdr_sink_0.set_center_freq(tx_frequency, 0)
        self.limesdr_sink_0.set_bandwidth(5e6,0)
        self.limesdr_sink_0.set_gain(int(tx_gain),0)
        self.limesdr_sink_0.set_antenna(255,0)
        self.limesdr_sink_0.calibrate(5e6, 0)

        self.fuzzer_packet_insert_0 = fuzzer.packet_insert((0, ), 20, 0)
        self.fuzzer_fuzzer_0 = fuzzer.fuzzer(fuzzing_seed,fuzzing_fields,fuzzing_type,fuzzing_min,fuzzing_max,fuzzing_data,fuzzing_interval,fuzzing_protocol,fuzzing_packet_type, library_filepath)
        self.fractional_resampler_xx_0_0_0_0 = filter.fractional_resampler_cc(0, sampling_factor*data_rate*sampling_multiple/sample_rate)
        self.digital_gfsk_mod_0 = digital.gfsk_mod(
        	samples_per_symbol=200,
        	sensitivity=0.1,
        	bt=0.5,
        	verbose=False,
        	log=False,
        )
        self.blocks_unpack_k_bits_bb_0 = blocks.unpack_k_bits_bb(8)
        self.blocks_null_source_0 = blocks.null_source(gr.sizeof_char*1)
        self.blocks_multiply_const_vxx_1 = blocks.multiply_const_vcc((0.1, ))
        self.blocks_multiply_const_vxx_0 = blocks.multiply_const_vff((-1, ))
        self.blocks_float_to_char_0 = blocks.float_to_char(1, 1)
        self.blocks_char_to_float_0 = blocks.char_to_float(1, 1)

        ##################################################
        # Connections
        ##################################################
        self.msg_connect((self.fuzzer_fuzzer_0, 'packet_out'), (self.fuzzer_packet_insert_0, 'packet_in'))
        self.connect((self.blocks_char_to_float_0, 0), (self.blocks_multiply_const_vxx_0, 0))
        self.connect((self.blocks_float_to_char_0, 0), (self.digital_gfsk_mod_0, 0))
        self.connect((self.blocks_multiply_const_vxx_0, 0), (self.blocks_float_to_char_0, 0))
        self.connect((self.blocks_multiply_const_vxx_1, 0), (self.limesdr_sink_0, 0))
        self.connect((self.blocks_null_source_0, 0), (self.fuzzer_packet_insert_0, 0))
        self.connect((self.blocks_unpack_k_bits_bb_0, 0), (self.blocks_char_to_float_0, 0))
        self.connect((self.digital_gfsk_mod_0, 0), (self.fractional_resampler_xx_0_0_0_0, 0))
        self.connect((self.fractional_resampler_xx_0_0_0_0, 0), (self.blocks_multiply_const_vxx_1, 0))
        self.connect((self.fuzzer_packet_insert_0, 0), (self.blocks_unpack_k_bits_bb_0, 0))

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

    def get_sampling_multiple(self):
        return self.sampling_multiple

    def set_sampling_multiple(self, sampling_multiple):
        self.sampling_multiple = sampling_multiple
        self.fractional_resampler_xx_0_0_0_0.set_resamp_ratio(self.sampling_factor*self.data_rate*self.sampling_multiple/self.sample_rate)

    def get_sampling_factor(self):
        return self.sampling_factor

    def set_sampling_factor(self, sampling_factor):
        self.sampling_factor = sampling_factor
        self.fractional_resampler_xx_0_0_0_0.set_resamp_ratio(self.sampling_factor*self.data_rate*self.sampling_multiple/self.sample_rate)

    def get_sample_rate(self):
        return self.sample_rate

    def set_sample_rate(self, sample_rate):
        self.sample_rate = sample_rate
        self.fractional_resampler_xx_0_0_0_0.set_resamp_ratio(self.sampling_factor*self.data_rate*self.sampling_multiple/self.sample_rate)

    def get_library_filepath(self):
        return self.library_filepath

    def set_library_filepath(self, library_filepath):
        self.library_filepath = library_filepath

    def get_fuzzing_type(self):
        return self.fuzzing_type

    def set_fuzzing_type(self, fuzzing_type):
        self.fuzzing_type = fuzzing_type
        self.fuzzer_fuzzer_0.set_fuzzing_type(self.fuzzing_type)

    def get_fuzzing_seed(self):
        return self.fuzzing_seed

    def set_fuzzing_seed(self, fuzzing_seed):
        self.fuzzing_seed = fuzzing_seed
        self.fuzzer_fuzzer_0.set_fuzzing_seed(self.fuzzing_seed)

    def get_fuzzing_protocol(self):
        return self.fuzzing_protocol

    def set_fuzzing_protocol(self, fuzzing_protocol):
        self.fuzzing_protocol = fuzzing_protocol
        self.fuzzer_fuzzer_0.set_fuzzing_protocol(self.fuzzing_protocol)

    def get_fuzzing_packet_type(self):
        return self.fuzzing_packet_type

    def set_fuzzing_packet_type(self, fuzzing_packet_type):
        self.fuzzing_packet_type = fuzzing_packet_type
        self.fuzzer_fuzzer_0.set_fuzzing_packet_type(self.fuzzing_packet_type)

    def get_fuzzing_min(self):
        return self.fuzzing_min

    def set_fuzzing_min(self, fuzzing_min):
        self.fuzzing_min = fuzzing_min
        self.fuzzer_fuzzer_0.set_fuzzing_min(self.fuzzing_min)

    def get_fuzzing_max(self):
        return self.fuzzing_max

    def set_fuzzing_max(self, fuzzing_max):
        self.fuzzing_max = fuzzing_max
        self.fuzzer_fuzzer_0.set_fuzzing_max(self.fuzzing_max)

    def get_fuzzing_interval(self):
        return self.fuzzing_interval

    def set_fuzzing_interval(self, fuzzing_interval):
        self.fuzzing_interval = fuzzing_interval
        self.fuzzer_fuzzer_0.set_fuzzing_interval(self.fuzzing_interval)

    def get_fuzzing_fields(self):
        return self.fuzzing_fields

    def set_fuzzing_fields(self, fuzzing_fields):
        self.fuzzing_fields = fuzzing_fields
        self.fuzzer_fuzzer_0.set_fuzzing_fields(self.fuzzing_fields)

    def get_fuzzing_data(self):
        return self.fuzzing_data

    def set_fuzzing_data(self, fuzzing_data):
        self.fuzzing_data = fuzzing_data
        self.fuzzer_fuzzer_0.set_fuzzing_data(self.fuzzing_data)

    def get_filepath(self):
        return self.filepath

    def set_filepath(self, filepath):
        self.filepath = filepath

    def get_data_rate(self):
        return self.data_rate

    def set_data_rate(self, data_rate):
        self.data_rate = data_rate
        self.fractional_resampler_xx_0_0_0_0.set_resamp_ratio(self.sampling_factor*self.data_rate*self.sampling_multiple/self.sample_rate)


def main(top_block_cls=SimpliciTI_FSK_LimeSDR_Fields, options=None):

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
