#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#
# SPDX-License-Identifier: GPL-3.0
#
# GNU Radio Python Flow Graph
# Title: Rds Bpsk Usrpb205Mini File Source
# GNU Radio version: 3.10.1.1

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
from gnuradio import uhd
import time
import math




class RDS_BPSK_USRPB205mini_File_Source(gr.top_block):

    def __init__(self):
        gr.top_block.__init__(self, "Rds Bpsk Usrpb205Mini File Source", catch_exceptions=True)

        ##################################################
        # Variables
        ##################################################
        self.usrp_rate = usrp_rate = 380000
        self.tx_usrp_gain = tx_usrp_gain = 70
        self.tx_usrp_freq = tx_usrp_freq = 106500000
        self.tx_usrp_channel = tx_usrp_channel = "A:A"
        self.stereo_gain = stereo_gain = .3
        self.serial = serial = "False"
        self.rds_gain = rds_gain = .5
        self.pilot_gain = pilot_gain = .3
        self.outbuffer = outbuffer = 10
        self.notes = notes = "Replays RDS data on repeat supplied from a file. No audio is added."
        self.input_gain = input_gain = .3
        self.fm_max_dev = fm_max_dev = 80000
        self.filepath = filepath = "/home/user/FISSURE/Crafted Packets/rdsA2.bin"

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
        self.uhd_usrp_sink_0.set_samp_rate(1e6)
        self.uhd_usrp_sink_0.set_time_unknown_pps(uhd.time_spec(0))

        self.uhd_usrp_sink_0.set_center_freq(tx_usrp_freq, 0)
        self.uhd_usrp_sink_0.set_antenna('TX/RX', 0)
        self.uhd_usrp_sink_0.set_gain(tx_usrp_gain, 0)
        self.mmse_resampler_xx_1 = filter.mmse_resampler_cc(0, (usrp_rate/10000)/100.0)
        self.mmse_resampler_xx_0_0 = filter.mmse_resampler_ff(0, 44.1/(usrp_rate/1000))
        self.mmse_resampler_xx_0 = filter.mmse_resampler_ff(0, 44.1/(usrp_rate/1000))
        self.low_pass_filter_0 = filter.interp_fir_filter_fff(
            1,
            firdes.low_pass(
                1,
                usrp_rate,
                2.5e3,
                .5e3,
                window.WIN_HAMMING,
                6.76))
        self.low_pass_filter_0.set_max_output_buffer(10)
        self.gr_unpack_k_bits_bb_0 = blocks.unpack_k_bits_bb(2)
        self.gr_unpack_k_bits_bb_0.set_max_output_buffer(10)
        self.gr_sub_xx_0 = blocks.sub_ff(1)
        self.gr_sig_source_x_0_1 = analog.sig_source_f(usrp_rate, analog.GR_SIN_WAVE, 19e3, 1, 0, 0)
        self.gr_sig_source_x_0_0 = analog.sig_source_f(usrp_rate, analog.GR_SIN_WAVE, 57e3, 1, 0, 0)
        self.gr_sig_source_x_0 = analog.sig_source_f(usrp_rate, analog.GR_SIN_WAVE, 38e3, 1, 0, 0)
        self.gr_multiply_xx_1 = blocks.multiply_vff(1)
        self.gr_multiply_xx_0 = blocks.multiply_vff(1)
        self.gr_multiply_xx_0.set_max_output_buffer(10)
        self.gr_map_bb_1 = digital.map_bb([1,2])
        self.gr_map_bb_1.set_max_output_buffer(10)
        self.gr_map_bb_0 = digital.map_bb([-1,1])
        self.gr_map_bb_0.set_max_output_buffer(10)
        self.gr_frequency_modulator_fc_0 = analog.frequency_modulator_fc(2*math.pi*fm_max_dev/usrp_rate)
        self.gr_frequency_modulator_fc_0.set_max_output_buffer(10)
        self.gr_diff_encoder_bb_0 = digital.diff_encoder_bb(2, digital.DIFF_DIFFERENTIAL)
        self.gr_diff_encoder_bb_0.set_max_output_buffer(10)
        self.gr_char_to_float_0 = blocks.char_to_float(1, 1)
        self.gr_char_to_float_0.set_max_output_buffer(10)
        self.gr_add_xx_1 = blocks.add_vff(1)
        self.gr_add_xx_1.set_max_output_buffer(10)
        self.gr_add_xx_0 = blocks.add_vff(1)
        self.blocks_unpack_k_bits_bb_0 = blocks.unpack_k_bits_bb(8)
        self.blocks_repeat_0 = blocks.repeat(gr.sizeof_float*1, 160)
        self.blocks_null_source_0 = blocks.null_source(gr.sizeof_float*1)
        self.blocks_multiply_const_vxx_0_1 = blocks.multiply_const_ff(input_gain)
        self.blocks_multiply_const_vxx_0_0_1 = blocks.multiply_const_ff(pilot_gain)
        self.blocks_multiply_const_vxx_0_0 = blocks.multiply_const_ff(rds_gain)
        self.blocks_multiply_const_vxx_0_0.set_max_output_buffer(10)
        self.blocks_multiply_const_vxx_0 = blocks.multiply_const_ff(input_gain)
        self.blocks_file_source_0 = blocks.file_source(gr.sizeof_char*1, filepath, True, 0, 0)
        self.blocks_file_source_0.set_begin_tag(pmt.PMT_NIL)


        ##################################################
        # Connections
        ##################################################
        self.connect((self.blocks_file_source_0, 0), (self.blocks_unpack_k_bits_bb_0, 0))
        self.connect((self.blocks_multiply_const_vxx_0, 0), (self.mmse_resampler_xx_0, 0))
        self.connect((self.blocks_multiply_const_vxx_0_0, 0), (self.gr_add_xx_1, 0))
        self.connect((self.blocks_multiply_const_vxx_0_0_1, 0), (self.gr_add_xx_1, 1))
        self.connect((self.blocks_multiply_const_vxx_0_1, 0), (self.mmse_resampler_xx_0_0, 0))
        self.connect((self.blocks_null_source_0, 0), (self.blocks_multiply_const_vxx_0, 0))
        self.connect((self.blocks_null_source_0, 0), (self.blocks_multiply_const_vxx_0_1, 0))
        self.connect((self.blocks_repeat_0, 0), (self.low_pass_filter_0, 0))
        self.connect((self.blocks_unpack_k_bits_bb_0, 0), (self.gr_diff_encoder_bb_0, 0))
        self.connect((self.gr_add_xx_0, 0), (self.gr_add_xx_1, 3))
        self.connect((self.gr_add_xx_1, 0), (self.gr_frequency_modulator_fc_0, 0))
        self.connect((self.gr_char_to_float_0, 0), (self.blocks_repeat_0, 0))
        self.connect((self.gr_diff_encoder_bb_0, 0), (self.gr_map_bb_1, 0))
        self.connect((self.gr_frequency_modulator_fc_0, 0), (self.mmse_resampler_xx_1, 0))
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
        self.connect((self.mmse_resampler_xx_0, 0), (self.gr_add_xx_0, 0))
        self.connect((self.mmse_resampler_xx_0, 0), (self.gr_sub_xx_0, 0))
        self.connect((self.mmse_resampler_xx_0_0, 0), (self.gr_add_xx_0, 1))
        self.connect((self.mmse_resampler_xx_0_0, 0), (self.gr_sub_xx_0, 1))
        self.connect((self.mmse_resampler_xx_1, 0), (self.uhd_usrp_sink_0, 0))


    def get_usrp_rate(self):
        return self.usrp_rate

    def set_usrp_rate(self, usrp_rate):
        self.usrp_rate = usrp_rate
        self.gr_frequency_modulator_fc_0.set_sensitivity(2*math.pi*self.fm_max_dev/self.usrp_rate)
        self.gr_sig_source_x_0.set_sampling_freq(self.usrp_rate)
        self.gr_sig_source_x_0_0.set_sampling_freq(self.usrp_rate)
        self.gr_sig_source_x_0_1.set_sampling_freq(self.usrp_rate)
        self.low_pass_filter_0.set_taps(firdes.low_pass(1, self.usrp_rate, 2.5e3, .5e3, window.WIN_HAMMING, 6.76))
        self.mmse_resampler_xx_0.set_resamp_ratio(44.1/(self.usrp_rate/1000))
        self.mmse_resampler_xx_0_0.set_resamp_ratio(44.1/(self.usrp_rate/1000))
        self.mmse_resampler_xx_1.set_resamp_ratio((self.usrp_rate/10000)/100.0)

    def get_tx_usrp_gain(self):
        return self.tx_usrp_gain

    def set_tx_usrp_gain(self, tx_usrp_gain):
        self.tx_usrp_gain = tx_usrp_gain
        self.uhd_usrp_sink_0.set_gain(self.tx_usrp_gain, 0)

    def get_tx_usrp_freq(self):
        return self.tx_usrp_freq

    def set_tx_usrp_freq(self, tx_usrp_freq):
        self.tx_usrp_freq = tx_usrp_freq
        self.uhd_usrp_sink_0.set_center_freq(self.tx_usrp_freq, 0)

    def get_tx_usrp_channel(self):
        return self.tx_usrp_channel

    def set_tx_usrp_channel(self, tx_usrp_channel):
        self.tx_usrp_channel = tx_usrp_channel

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

    def get_input_gain(self):
        return self.input_gain

    def set_input_gain(self, input_gain):
        self.input_gain = input_gain
        self.blocks_multiply_const_vxx_0.set_k(self.input_gain)
        self.blocks_multiply_const_vxx_0_1.set_k(self.input_gain)

    def get_fm_max_dev(self):
        return self.fm_max_dev

    def set_fm_max_dev(self, fm_max_dev):
        self.fm_max_dev = fm_max_dev
        self.gr_frequency_modulator_fc_0.set_sensitivity(2*math.pi*self.fm_max_dev/self.usrp_rate)

    def get_filepath(self):
        return self.filepath

    def set_filepath(self, filepath):
        self.filepath = filepath
        self.blocks_file_source_0.open(self.filepath, True)




def main(top_block_cls=RDS_BPSK_USRPB205mini_File_Source, options=None):
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
