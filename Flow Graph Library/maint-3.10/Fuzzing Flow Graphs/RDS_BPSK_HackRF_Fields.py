#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#
# SPDX-License-Identifier: GPL-3.0
#
# GNU Radio Python Flow Graph
# Title: Rds Bpsk Hackrf Fields
# GNU Radio version: 3.10.7.0

from gnuradio import analog
from gnuradio import blocks
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
import gnuradio.fuzzer as fuzzer
import math
import osmosdr
import time




class RDS_BPSK_HackRF_Fields(gr.top_block):

    def __init__(self):
        gr.top_block.__init__(self, "Rds Bpsk Hackrf Fields", catch_exceptions=True)

        ##################################################
        # Variables
        ##################################################
        self.transmit_interval = transmit_interval = 1
        self.stereo_gain = stereo_gain = .3
        self.serial = serial = "0"
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
        self.freq = freq = 106500000
        self.fm_max_dev = fm_max_dev = 80000

        ##################################################
        # Blocks
        ##################################################

        self.osmosdr_sink_0 = osmosdr.sink(
            args="numchan=" + str(1) + " " + "hackrf=" + str(serial)
        )
        self.osmosdr_sink_0.set_time_unknown_pps(osmosdr.time_spec_t())
        self.osmosdr_sink_0.set_sample_rate(1e6)
        self.osmosdr_sink_0.set_center_freq(freq, 0)
        self.osmosdr_sink_0.set_freq_corr(0, 0)
        self.osmosdr_sink_0.set_gain(10, 0)
        self.osmosdr_sink_0.set_if_gain(30, 0)
        self.osmosdr_sink_0.set_bb_gain(20, 0)
        self.osmosdr_sink_0.set_antenna('', 0)
        self.osmosdr_sink_0.set_bandwidth(0, 0)
        self.mmse_resampler_xx_1 = filter.mmse_resampler_cc(0, ((lower_rate/10000)/100.0))
        self.mmse_resampler_xx_0 = filter.mmse_resampler_ff(0, .00625)
        self.low_pass_filter_0 = filter.interp_fir_filter_fff(
            1,
            firdes.low_pass(
                1,
                lower_rate,
                2.5e3,
                .5e3,
                window.WIN_HAMMING,
                6.76))
        self.gr_unpack_k_bits_bb_0 = blocks.unpack_k_bits_bb(2)
        self.gr_sig_source_x_0_0 = analog.sig_source_f(lower_rate, analog.GR_SIN_WAVE, 57e3, 1, 0, 0)
        self.gr_multiply_xx_0 = blocks.multiply_vff(1)
        self.gr_map_bb_1 = digital.map_bb([1,2])
        self.gr_map_bb_0 = digital.map_bb([-1,1])
        self.gr_frequency_modulator_fc_0 = analog.frequency_modulator_fc((2*math.pi*fm_max_dev/lower_rate))
        self.gr_diff_encoder_bb_0 = digital.diff_encoder_bb(2, digital.DIFF_DIFFERENTIAL)
        self.gr_char_to_float_0 = blocks.char_to_float(1, 1)
        self.fuzzer_fuzzer_0_0 = fuzzer.fuzzer(fuzzing_seed,fuzzing_fields,fuzzing_type,fuzzing_min,fuzzing_max,fuzzing_data,fuzzing_interval,fuzzing_protocol,fuzzing_packet_type,library_filepath)
        self.fuzzer_continuous_insert_0 = fuzzer.continuous_insert((99, 147, 114, 129, 114, 161, 206, 17, 122, 136, 204, 130, 179))
        self.blocks_unpack_k_bits_bb_0 = blocks.unpack_k_bits_bb(8)
        self.blocks_null_source_0_0 = blocks.null_source(gr.sizeof_char*1)
        self.blocks_multiply_const_vxx_0_0 = blocks.multiply_const_ff(rds_gain)


        ##################################################
        # Connections
        ##################################################
        self.msg_connect((self.fuzzer_fuzzer_0_0, 'packet_out'), (self.fuzzer_continuous_insert_0, 'packet_in'))
        self.connect((self.blocks_multiply_const_vxx_0_0, 0), (self.gr_frequency_modulator_fc_0, 0))
        self.connect((self.blocks_null_source_0_0, 0), (self.fuzzer_continuous_insert_0, 0))
        self.connect((self.blocks_unpack_k_bits_bb_0, 0), (self.gr_diff_encoder_bb_0, 0))
        self.connect((self.fuzzer_continuous_insert_0, 0), (self.blocks_unpack_k_bits_bb_0, 0))
        self.connect((self.gr_char_to_float_0, 0), (self.mmse_resampler_xx_0, 0))
        self.connect((self.gr_diff_encoder_bb_0, 0), (self.gr_map_bb_1, 0))
        self.connect((self.gr_frequency_modulator_fc_0, 0), (self.mmse_resampler_xx_1, 0))
        self.connect((self.gr_map_bb_0, 0), (self.gr_char_to_float_0, 0))
        self.connect((self.gr_map_bb_1, 0), (self.gr_unpack_k_bits_bb_0, 0))
        self.connect((self.gr_multiply_xx_0, 0), (self.blocks_multiply_const_vxx_0_0, 0))
        self.connect((self.gr_sig_source_x_0_0, 0), (self.gr_multiply_xx_0, 0))
        self.connect((self.gr_unpack_k_bits_bb_0, 0), (self.gr_map_bb_0, 0))
        self.connect((self.low_pass_filter_0, 0), (self.gr_multiply_xx_0, 1))
        self.connect((self.mmse_resampler_xx_0, 0), (self.low_pass_filter_0, 0))
        self.connect((self.mmse_resampler_xx_1, 0), (self.osmosdr_sink_0, 0))


    def get_transmit_interval(self):
        return self.transmit_interval

    def set_transmit_interval(self, transmit_interval):
        self.transmit_interval = transmit_interval

    def get_stereo_gain(self):
        return self.stereo_gain

    def set_stereo_gain(self, stereo_gain):
        self.stereo_gain = stereo_gain

    def get_serial(self):
        return self.serial

    def set_serial(self, serial):
        self.serial = serial

    def get_samp_rate(self):
        return self.samp_rate

    def set_samp_rate(self, samp_rate):
        self.samp_rate = samp_rate

    def get_rds_gain(self):
        return self.rds_gain

    def set_rds_gain(self, rds_gain):
        self.rds_gain = rds_gain
        self.blocks_multiply_const_vxx_0_0.set_k(self.rds_gain)

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
        self.gr_frequency_modulator_fc_0.set_sensitivity((2*math.pi*self.fm_max_dev/self.lower_rate))
        self.gr_sig_source_x_0_0.set_sampling_freq(self.lower_rate)
        self.low_pass_filter_0.set_taps(firdes.low_pass(1, self.lower_rate, 2.5e3, .5e3, window.WIN_HAMMING, 6.76))
        self.mmse_resampler_xx_1.set_resamp_ratio(((self.lower_rate/10000)/100.0))

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

    def get_freq(self):
        return self.freq

    def set_freq(self, freq):
        self.freq = freq
        self.osmosdr_sink_0.set_center_freq(self.freq, 0)

    def get_fm_max_dev(self):
        return self.fm_max_dev

    def set_fm_max_dev(self, fm_max_dev):
        self.fm_max_dev = fm_max_dev
        self.gr_frequency_modulator_fc_0.set_sensitivity((2*math.pi*self.fm_max_dev/self.lower_rate))




def main(top_block_cls=RDS_BPSK_HackRF_Fields, options=None):
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
