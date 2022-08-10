#!/usr/bin/env python2
# -*- coding: utf-8 -*-
##################################################
# GNU Radio Python Flow Graph
# Title: Rds Bpsk Limesdr Fields
# Generated: Thu Oct  7 21:09:47 2021
##################################################


from gnuradio import analog
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
import math


class RDS_BPSK_LimeSDR_Fields(gr.top_block):

    def __init__(self):
        gr.top_block.__init__(self, "Rds Bpsk Limesdr Fields")

        ##################################################
        # Variables
        ##################################################
        self.tx_gain = tx_gain = 60
        self.tx_frequency = tx_frequency = 106500000
        self.tx_channel = tx_channel = 0
        self.transmit_interval = transmit_interval = 1
        self.stereo_gain = stereo_gain = .3
        self.samp_rate = samp_rate = 1e6
        self.rds_gain = rds_gain = .5
        self.pilot_gain = pilot_gain = .3
        self.outbuffer = outbuffer = 0
        self.lower_rate = lower_rate = 380000
        self.library_filepath = library_filepath = "~/FISSURE/YAML/library.yaml"
        self.input_gain = input_gain = .3
        self.fuzzing_type = fuzzing_type = "['Random']"
        self.fuzzing_seed = fuzzing_seed = "0"
        self.fuzzing_protocol = fuzzing_protocol = "RDS"
        self.fuzzing_packet_type = fuzzing_packet_type = "Message Version A"
        self.fuzzing_min = fuzzing_min = "['0']"
        self.fuzzing_max = fuzzing_max = "['15']"
        self.fuzzing_interval = fuzzing_interval = "1"
        self.fuzzing_fields = fuzzing_fields = "['Country Code']"
        self.fuzzing_data = fuzzing_data = "0"
        self.fm_max_dev = fm_max_dev = 80000

        ##################################################
        # Blocks
        ##################################################
        self.low_pass_filter_0 = filter.interp_fir_filter_fff(1, firdes.low_pass(
        	1, lower_rate, 2.5e3, .5e3, firdes.WIN_HAMMING, 6.76))
        self.limesdr_sink_0 = limesdr.sink('', int(tx_channel), '', '')
        self.limesdr_sink_0.set_sample_rate(samp_rate)
        self.limesdr_sink_0.set_center_freq(tx_frequency, 0)
        self.limesdr_sink_0.set_bandwidth(5e6,0)
        self.limesdr_sink_0.set_gain(int(tx_gain),0)
        self.limesdr_sink_0.set_antenna(255,0)
        self.limesdr_sink_0.calibrate(5e6, 0)

        self.gr_unpack_k_bits_bb_0 = blocks.unpack_k_bits_bb(2)
        self.gr_sig_source_x_0_0 = analog.sig_source_f(lower_rate, analog.GR_SIN_WAVE, 57e3, 1, 0)
        self.gr_multiply_xx_0 = blocks.multiply_vff(1)
        self.gr_map_bb_1 = digital.map_bb(([1,2]))
        self.gr_map_bb_0 = digital.map_bb(([-1,1]))
        self.gr_frequency_modulator_fc_0 = analog.frequency_modulator_fc(2*math.pi*fm_max_dev/lower_rate)
        self.gr_diff_encoder_bb_0 = digital.diff_encoder_bb(2)
        self.gr_char_to_float_0 = blocks.char_to_float(1, 1)
        self.fuzzer_fuzzer_0_0 = fuzzer.fuzzer(fuzzing_seed,fuzzing_fields,fuzzing_type,fuzzing_min,fuzzing_max,fuzzing_data,fuzzing_interval,fuzzing_protocol,fuzzing_packet_type, library_filepath)
        self.fuzzer_continuous_insert_0 = fuzzer.continuous_insert(((99, 147, 114, 129, 114, 161, 206, 17, 122, 136, 204, 130, 179)))
        self.fractional_resampler_xx_1 = filter.fractional_resampler_ff(0, .00625)
        self.fractional_resampler_xx_0_0_0 = filter.fractional_resampler_cc(0, (lower_rate/10000)/100.0)
        self.blocks_unpack_k_bits_bb_0 = blocks.unpack_k_bits_bb(8)
        self.blocks_null_source_0_0 = blocks.null_source(gr.sizeof_char*1)
        self.blocks_multiply_const_vxx_0_0 = blocks.multiply_const_vff((rds_gain, ))

        ##################################################
        # Connections
        ##################################################
        self.msg_connect((self.fuzzer_fuzzer_0_0, 'packet_out'), (self.fuzzer_continuous_insert_0, 'packet_in'))
        self.connect((self.blocks_multiply_const_vxx_0_0, 0), (self.gr_frequency_modulator_fc_0, 0))
        self.connect((self.blocks_null_source_0_0, 0), (self.fuzzer_continuous_insert_0, 0))
        self.connect((self.blocks_unpack_k_bits_bb_0, 0), (self.gr_diff_encoder_bb_0, 0))
        self.connect((self.fractional_resampler_xx_0_0_0, 0), (self.limesdr_sink_0, 0))
        self.connect((self.fractional_resampler_xx_1, 0), (self.low_pass_filter_0, 0))
        self.connect((self.fuzzer_continuous_insert_0, 0), (self.blocks_unpack_k_bits_bb_0, 0))
        self.connect((self.gr_char_to_float_0, 0), (self.fractional_resampler_xx_1, 0))
        self.connect((self.gr_diff_encoder_bb_0, 0), (self.gr_map_bb_1, 0))
        self.connect((self.gr_frequency_modulator_fc_0, 0), (self.fractional_resampler_xx_0_0_0, 0))
        self.connect((self.gr_map_bb_0, 0), (self.gr_char_to_float_0, 0))
        self.connect((self.gr_map_bb_1, 0), (self.gr_unpack_k_bits_bb_0, 0))
        self.connect((self.gr_multiply_xx_0, 0), (self.blocks_multiply_const_vxx_0_0, 0))
        self.connect((self.gr_sig_source_x_0_0, 0), (self.gr_multiply_xx_0, 0))
        self.connect((self.gr_unpack_k_bits_bb_0, 0), (self.gr_map_bb_0, 0))
        self.connect((self.low_pass_filter_0, 0), (self.gr_multiply_xx_0, 1))

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

    def get_stereo_gain(self):
        return self.stereo_gain

    def set_stereo_gain(self, stereo_gain):
        self.stereo_gain = stereo_gain

    def get_samp_rate(self):
        return self.samp_rate

    def set_samp_rate(self, samp_rate):
        self.samp_rate = samp_rate

    def get_rds_gain(self):
        return self.rds_gain

    def set_rds_gain(self, rds_gain):
        self.rds_gain = rds_gain
        self.blocks_multiply_const_vxx_0_0.set_k((self.rds_gain, ))

    def get_pilot_gain(self):
        return self.pilot_gain

    def set_pilot_gain(self, pilot_gain):
        self.pilot_gain = pilot_gain

    def get_outbuffer(self):
        return self.outbuffer

    def set_outbuffer(self, outbuffer):
        self.outbuffer = outbuffer

    def get_lower_rate(self):
        return self.lower_rate

    def set_lower_rate(self, lower_rate):
        self.lower_rate = lower_rate
        self.low_pass_filter_0.set_taps(firdes.low_pass(1, self.lower_rate, 2.5e3, .5e3, firdes.WIN_HAMMING, 6.76))
        self.gr_sig_source_x_0_0.set_sampling_freq(self.lower_rate)
        self.gr_frequency_modulator_fc_0.set_sensitivity(2*math.pi*self.fm_max_dev/self.lower_rate)
        self.fractional_resampler_xx_0_0_0.set_resamp_ratio((self.lower_rate/10000)/100.0)

    def get_library_filepath(self):
        return self.library_filepath

    def set_library_filepath(self, library_filepath):
        self.library_filepath = library_filepath

    def get_input_gain(self):
        return self.input_gain

    def set_input_gain(self, input_gain):
        self.input_gain = input_gain

    def get_fuzzing_type(self):
        return self.fuzzing_type

    def set_fuzzing_type(self, fuzzing_type):
        self.fuzzing_type = fuzzing_type
        self.fuzzer_fuzzer_0_0.set_fuzzing_type(self.fuzzing_type)

    def get_fuzzing_seed(self):
        return self.fuzzing_seed

    def set_fuzzing_seed(self, fuzzing_seed):
        self.fuzzing_seed = fuzzing_seed
        self.fuzzer_fuzzer_0_0.set_fuzzing_seed(self.fuzzing_seed)

    def get_fuzzing_protocol(self):
        return self.fuzzing_protocol

    def set_fuzzing_protocol(self, fuzzing_protocol):
        self.fuzzing_protocol = fuzzing_protocol
        self.fuzzer_fuzzer_0_0.set_fuzzing_protocol(self.fuzzing_protocol)

    def get_fuzzing_packet_type(self):
        return self.fuzzing_packet_type

    def set_fuzzing_packet_type(self, fuzzing_packet_type):
        self.fuzzing_packet_type = fuzzing_packet_type
        self.fuzzer_fuzzer_0_0.set_fuzzing_packet_type(self.fuzzing_packet_type)

    def get_fuzzing_min(self):
        return self.fuzzing_min

    def set_fuzzing_min(self, fuzzing_min):
        self.fuzzing_min = fuzzing_min
        self.fuzzer_fuzzer_0_0.set_fuzzing_min(self.fuzzing_min)

    def get_fuzzing_max(self):
        return self.fuzzing_max

    def set_fuzzing_max(self, fuzzing_max):
        self.fuzzing_max = fuzzing_max
        self.fuzzer_fuzzer_0_0.set_fuzzing_max(self.fuzzing_max)

    def get_fuzzing_interval(self):
        return self.fuzzing_interval

    def set_fuzzing_interval(self, fuzzing_interval):
        self.fuzzing_interval = fuzzing_interval
        self.fuzzer_fuzzer_0_0.set_fuzzing_interval(self.fuzzing_interval)

    def get_fuzzing_fields(self):
        return self.fuzzing_fields

    def set_fuzzing_fields(self, fuzzing_fields):
        self.fuzzing_fields = fuzzing_fields
        self.fuzzer_fuzzer_0_0.set_fuzzing_fields(self.fuzzing_fields)

    def get_fuzzing_data(self):
        return self.fuzzing_data

    def set_fuzzing_data(self, fuzzing_data):
        self.fuzzing_data = fuzzing_data
        self.fuzzer_fuzzer_0_0.set_fuzzing_data(self.fuzzing_data)

    def get_fm_max_dev(self):
        return self.fm_max_dev

    def set_fm_max_dev(self, fm_max_dev):
        self.fm_max_dev = fm_max_dev
        self.gr_frequency_modulator_fc_0.set_sensitivity(2*math.pi*self.fm_max_dev/self.lower_rate)


def main(top_block_cls=RDS_BPSK_LimeSDR_Fields, options=None):

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
