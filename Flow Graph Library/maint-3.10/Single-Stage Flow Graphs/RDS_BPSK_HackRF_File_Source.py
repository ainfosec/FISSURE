#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#
# SPDX-License-Identifier: GPL-3.0
#
# GNU Radio Python Flow Graph
# Title: Rds Bpsk Hackrf File Source
# GNU Radio version: 3.10.7.0

from gnuradio import analog
from gnuradio import blocks
import pmt
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
import math
import osmosdr
import time




class RDS_BPSK_HackRF_File_Source(gr.top_block):

    def __init__(self):
        gr.top_block.__init__(self, "Rds Bpsk Hackrf File Source", catch_exceptions=True)

        ##################################################
        # Variables
        ##################################################
        self.stereo_gain = stereo_gain = .3
        self.serial = serial = "0"
        self.rds_gain = rds_gain = .5
        self.pilot_gain = pilot_gain = .3
        self.outbuffer = outbuffer = 10
        self.notes = notes = "Replays RDS data on repeat supplied from a file. No audio is added."
        self.lower_rate = lower_rate = 380000
        self.input_gain = input_gain = .3
        self.freq = freq = 106500000
        self.fm_max_dev = fm_max_dev = 80000
        self.filepath = filepath = "/home/laptop2/FISSURE/Crafted Packets/rdsA2.bin"

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
        self.mmse_resampler_xx_2 = filter.mmse_resampler_ff(0, (44.1/(lower_rate/1000)))
        self.mmse_resampler_xx_1 = filter.mmse_resampler_ff(0, (44.1/(lower_rate/1000)))
        self.mmse_resampler_xx_0 = filter.mmse_resampler_cc(0, ((lower_rate/10000)/100.0))
        self.low_pass_filter_0 = filter.interp_fir_filter_fff(
            1,
            firdes.low_pass(
                1,
                lower_rate,
                2.5e3,
                .5e3,
                window.WIN_HAMMING,
                6.76))
        self.low_pass_filter_0.set_max_output_buffer(outbuffer)
        self.gr_unpack_k_bits_bb_0 = blocks.unpack_k_bits_bb(2)
        self.gr_unpack_k_bits_bb_0.set_max_output_buffer(outbuffer)
        self.gr_sub_xx_0 = blocks.sub_ff(1)
        self.gr_sig_source_x_0_1 = analog.sig_source_f(lower_rate, analog.GR_SIN_WAVE, 19e3, 1, 0, 0)
        self.gr_sig_source_x_0_0 = analog.sig_source_f(lower_rate, analog.GR_SIN_WAVE, 57e3, 1, 0, 0)
        self.gr_sig_source_x_0 = analog.sig_source_f(lower_rate, analog.GR_SIN_WAVE, 38e3, 1, 0, 0)
        self.gr_multiply_xx_1 = blocks.multiply_vff(1)
        self.gr_multiply_xx_0 = blocks.multiply_vff(1)
        self.gr_multiply_xx_0.set_max_output_buffer(outbuffer)
        self.gr_map_bb_1 = digital.map_bb([1,2])
        self.gr_map_bb_1.set_max_output_buffer(outbuffer)
        self.gr_map_bb_0 = digital.map_bb([-1,1])
        self.gr_map_bb_0.set_max_output_buffer(outbuffer)
        self.gr_frequency_modulator_fc_0 = analog.frequency_modulator_fc((2*math.pi*fm_max_dev/lower_rate))
        self.gr_frequency_modulator_fc_0.set_max_output_buffer(outbuffer)
        self.gr_diff_encoder_bb_0 = digital.diff_encoder_bb(2, digital.DIFF_DIFFERENTIAL)
        self.gr_diff_encoder_bb_0.set_max_output_buffer(outbuffer)
        self.gr_char_to_float_0 = blocks.char_to_float(1, 1)
        self.gr_char_to_float_0.set_max_output_buffer(outbuffer)
        self.gr_add_xx_1 = blocks.add_vff(1)
        self.gr_add_xx_1.set_max_output_buffer(outbuffer)
        self.gr_add_xx_0 = blocks.add_vff(1)
        self.blocks_unpack_k_bits_bb_0 = blocks.unpack_k_bits_bb(8)
        self.blocks_repeat_0 = blocks.repeat(gr.sizeof_float*1, 160)
        self.blocks_null_source_0 = blocks.null_source(gr.sizeof_float*1)
        self.blocks_multiply_const_vxx_0_1 = blocks.multiply_const_ff(input_gain)
        self.blocks_multiply_const_vxx_0_0_1 = blocks.multiply_const_ff(pilot_gain)
        self.blocks_multiply_const_vxx_0_0 = blocks.multiply_const_ff(rds_gain)
        self.blocks_multiply_const_vxx_0_0.set_max_output_buffer(outbuffer)
        self.blocks_multiply_const_vxx_0 = blocks.multiply_const_ff(input_gain)
        self.blocks_file_source_0 = blocks.file_source(gr.sizeof_char*1, filepath, True, 0, 0)
        self.blocks_file_source_0.set_begin_tag(pmt.PMT_NIL)


        ##################################################
        # Connections
        ##################################################
        self.connect((self.blocks_file_source_0, 0), (self.blocks_unpack_k_bits_bb_0, 0))
        self.connect((self.blocks_multiply_const_vxx_0, 0), (self.mmse_resampler_xx_2, 0))
        self.connect((self.blocks_multiply_const_vxx_0_0, 0), (self.gr_add_xx_1, 0))
        self.connect((self.blocks_multiply_const_vxx_0_0_1, 0), (self.gr_add_xx_1, 1))
        self.connect((self.blocks_multiply_const_vxx_0_1, 0), (self.mmse_resampler_xx_1, 0))
        self.connect((self.blocks_null_source_0, 0), (self.blocks_multiply_const_vxx_0, 0))
        self.connect((self.blocks_null_source_0, 0), (self.blocks_multiply_const_vxx_0_1, 0))
        self.connect((self.blocks_repeat_0, 0), (self.low_pass_filter_0, 0))
        self.connect((self.blocks_unpack_k_bits_bb_0, 0), (self.gr_diff_encoder_bb_0, 0))
        self.connect((self.gr_add_xx_0, 0), (self.gr_add_xx_1, 3))
        self.connect((self.gr_add_xx_1, 0), (self.gr_frequency_modulator_fc_0, 0))
        self.connect((self.gr_char_to_float_0, 0), (self.blocks_repeat_0, 0))
        self.connect((self.gr_diff_encoder_bb_0, 0), (self.gr_map_bb_1, 0))
        self.connect((self.gr_frequency_modulator_fc_0, 0), (self.mmse_resampler_xx_0, 0))
        self.connect((self.gr_map_bb_0, 0), (self.gr_char_to_float_0, 0))
        self.connect((self.gr_map_bb_1, 0), (self.gr_unpack_k_bits_bb_0, 0))
        self.connect((self.gr_multiply_xx_0, 0), (self.blocks_multiply_const_vxx_0_0, 0))
        self.connect((self.gr_multiply_xx_1, 0), (self.gr_add_xx_1, 2))
        self.connect((self.gr_sig_source_x_0, 0), (self.gr_multiply_xx_1, 0))
        self.connect((self.gr_sig_source_x_0_0, 0), (self.gr_multiply_xx_0, 0))
        self.connect((self.gr_sig_source_x_0_1, 0), (self.blocks_multiply_const_vxx_0_0_1, 0))
        self.connect((self.gr_sub_xx_0, 0), (self.gr_multiply_xx_1, 1))
        self.connect((self.gr_unpack_k_bits_bb_0, 0), (self.gr_map_bb_0, 0))
        self.connect((self.low_pass_filter_0, 0), (self.gr_multiply_xx_0, 1))
        self.connect((self.mmse_resampler_xx_0, 0), (self.osmosdr_sink_0, 0))
        self.connect((self.mmse_resampler_xx_1, 0), (self.gr_add_xx_0, 1))
        self.connect((self.mmse_resampler_xx_1, 0), (self.gr_sub_xx_0, 1))
        self.connect((self.mmse_resampler_xx_2, 0), (self.gr_add_xx_0, 0))
        self.connect((self.mmse_resampler_xx_2, 0), (self.gr_sub_xx_0, 0))


    def get_stereo_gain(self):
        return self.stereo_gain

    def set_stereo_gain(self, stereo_gain):
        self.stereo_gain = stereo_gain

    def get_serial(self):
        return self.serial

    def set_serial(self, serial):
        self.serial = serial

    def get_rds_gain(self):
        return self.rds_gain

    def set_rds_gain(self, rds_gain):
        self.rds_gain = rds_gain
        self.blocks_multiply_const_vxx_0_0.set_k(self.rds_gain)

    def get_pilot_gain(self):
        return self.pilot_gain

    def set_pilot_gain(self, pilot_gain):
        self.pilot_gain = pilot_gain
        self.blocks_multiply_const_vxx_0_0_1.set_k(self.pilot_gain)

    def get_outbuffer(self):
        return self.outbuffer

    def set_outbuffer(self, outbuffer):
        self.outbuffer = outbuffer

    def get_notes(self):
        return self.notes

    def set_notes(self, notes):
        self.notes = notes

    def get_lower_rate(self):
        return self.lower_rate

    def set_lower_rate(self, lower_rate):
        self.lower_rate = lower_rate
        self.gr_frequency_modulator_fc_0.set_sensitivity((2*math.pi*self.fm_max_dev/self.lower_rate))
        self.gr_sig_source_x_0.set_sampling_freq(self.lower_rate)
        self.gr_sig_source_x_0_0.set_sampling_freq(self.lower_rate)
        self.gr_sig_source_x_0_1.set_sampling_freq(self.lower_rate)
        self.low_pass_filter_0.set_taps(firdes.low_pass(1, self.lower_rate, 2.5e3, .5e3, window.WIN_HAMMING, 6.76))
        self.mmse_resampler_xx_0.set_resamp_ratio(((self.lower_rate/10000)/100.0))
        self.mmse_resampler_xx_1.set_resamp_ratio((44.1/(self.lower_rate/1000)))
        self.mmse_resampler_xx_2.set_resamp_ratio((44.1/(self.lower_rate/1000)))

    def get_input_gain(self):
        return self.input_gain

    def set_input_gain(self, input_gain):
        self.input_gain = input_gain
        self.blocks_multiply_const_vxx_0.set_k(self.input_gain)
        self.blocks_multiply_const_vxx_0_1.set_k(self.input_gain)

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

    def get_filepath(self):
        return self.filepath

    def set_filepath(self, filepath):
        self.filepath = filepath
        self.blocks_file_source_0.open(self.filepath, True)




def main(top_block_cls=RDS_BPSK_HackRF_File_Source, options=None):
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
