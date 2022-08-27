#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#
# SPDX-License-Identifier: GPL-3.0
#
# GNU Radio Python Flow Graph
# Title: Hd Tx Am Hackrf
# GNU Radio version: 3.9.0.0

from gnuradio import blocks
from gnuradio import fft
from gnuradio.fft import window
from gnuradio import filter
from gnuradio.filter import firdes
from gnuradio import gr
import sys
import signal
from argparse import ArgumentParser
from gnuradio.eng_arg import eng_float, intx
from gnuradio import eng_notation
import math
import nrsc5
import osmosdr
import time




class hd_tx_am_hackrf(gr.top_block):

    def __init__(self):
        gr.top_block.__init__(self, "Hd Tx Am Hackrf", catch_exceptions=True)

        ##################################################
        # Variables
        ##################################################
        self.samp_rate = samp_rate = 2000000
        self.freq = freq = 1710e3
        self.audio_rate = audio_rate = 44100

        ##################################################
        # Blocks
        ##################################################
        self.rational_resampler_xxx_2 = filter.rational_resampler_ccc(
                interpolation=4096,
                decimation=243,
                taps=[],
                fractional_bw=-1.0)
        self.rational_resampler_xxx_1 = filter.rational_resampler_ccc(
                interpolation=125,
                decimation=49,
                taps=[],
                fractional_bw=-1.0)
        self.rational_resampler_xxx_0_0 = filter.rational_resampler_ccc(
                interpolation=200,
                decimation=21,
                taps=[],
                fractional_bw=-1.0)
        self.rational_resampler_xxx_0 = filter.rational_resampler_ccc(
                interpolation=100,
                decimation=21,
                taps=[],
                fractional_bw=-1.0)
        self.osmosdr_sink_0 = osmosdr.sink(
            args="numchan=" + str(1) + " " + ""
        )
        self.osmosdr_sink_0.set_time_unknown_pps(osmosdr.time_spec_t())
        self.osmosdr_sink_0.set_sample_rate(samp_rate)
        self.osmosdr_sink_0.set_center_freq(freq + 100000, 0)
        self.osmosdr_sink_0.set_freq_corr(0, 0)
        self.osmosdr_sink_0.set_gain(0, 0)
        self.osmosdr_sink_0.set_if_gain(1, 0)
        self.osmosdr_sink_0.set_bb_gain(20, 0)
        self.osmosdr_sink_0.set_antenna('', 0)
        self.osmosdr_sink_0.set_bandwidth(1.5e6, 0)
        self.nrsc5_sis_encoder_0 = nrsc5.sis_encoder('ABCD')
        self.nrsc5_psd_encoder_0 = nrsc5.psd_encoder(0, 'Title', 'Artist')
        self.nrsc5_l2_encoder_0 = nrsc5.l2_encoder(1, 0, 3750)
        self.nrsc5_l1_am_encoder_ma1_0 = nrsc5.l1_am_encoder(1)
        self.nrsc5_hdc_encoder_0 = nrsc5.hdc_encoder(1, 17900)
        self.low_pass_filter_1 = filter.fir_filter_fff(
            1,
            firdes.low_pass(
                0.5,
                audio_rate,
                4500,
                1000,
                window.WIN_HAMMING,
                6.76))
        self.fft_vxx_0 = fft.fft_vcc(256, False, window.rectangular(256), True, 1)
        self.blocks_wavfile_source_1 = blocks.wavfile_source('sample_mono.wav', True)
        self.blocks_wavfile_source_0 = blocks.wavfile_source('sample_mono.wav', True)
        self.blocks_vector_to_stream_0 = blocks.vector_to_stream(gr.sizeof_gr_complex*1, 256)
        self.blocks_vector_source_x_0 = blocks.vector_source_c([math.sin(math.pi / 2 * i / 14) for i in range(14)] + [1] * (256-14) + [math.cos(math.pi / 2 * i / 14) for i in range(14)], True, 1, [])
        self.blocks_rotator_cc_0 = blocks.rotator_cc(-2 * math.pi * 100000 / samp_rate)
        self.blocks_repeat_0 = blocks.repeat(gr.sizeof_gr_complex*256, 2)
        self.blocks_null_source_0 = blocks.null_source(gr.sizeof_char*24000)
        self.blocks_multiply_xx_0 = blocks.multiply_vcc(1)
        self.blocks_keep_m_in_n_0 = blocks.keep_m_in_n(gr.sizeof_gr_complex, 270, 512, 121)
        self.blocks_float_to_complex_0 = blocks.float_to_complex(1)
        self.blocks_delay_0 = blocks.delay(gr.sizeof_float*1, int(audio_rate * 5.5))
        self.blocks_add_xx_0 = blocks.add_vcc(1)
        self.blocks_add_const_vxx_0 = blocks.add_const_ff(0.5)



        ##################################################
        # Connections
        ##################################################
        self.connect((self.blocks_add_const_vxx_0, 0), (self.blocks_float_to_complex_0, 0))
        self.connect((self.blocks_add_xx_0, 0), (self.blocks_rotator_cc_0, 0))
        self.connect((self.blocks_delay_0, 0), (self.low_pass_filter_1, 0))
        self.connect((self.blocks_float_to_complex_0, 0), (self.rational_resampler_xxx_0, 0))
        self.connect((self.blocks_keep_m_in_n_0, 0), (self.blocks_multiply_xx_0, 1))
        self.connect((self.blocks_multiply_xx_0, 0), (self.rational_resampler_xxx_1, 0))
        self.connect((self.blocks_null_source_0, 0), (self.nrsc5_l1_am_encoder_ma1_0, 1))
        self.connect((self.blocks_repeat_0, 0), (self.blocks_vector_to_stream_0, 0))
        self.connect((self.blocks_rotator_cc_0, 0), (self.osmosdr_sink_0, 0))
        self.connect((self.blocks_vector_source_x_0, 0), (self.blocks_multiply_xx_0, 0))
        self.connect((self.blocks_vector_to_stream_0, 0), (self.blocks_keep_m_in_n_0, 0))
        self.connect((self.blocks_wavfile_source_0, 0), (self.nrsc5_hdc_encoder_0, 0))
        self.connect((self.blocks_wavfile_source_1, 0), (self.blocks_delay_0, 0))
        self.connect((self.fft_vxx_0, 0), (self.blocks_repeat_0, 0))
        self.connect((self.low_pass_filter_1, 0), (self.blocks_add_const_vxx_0, 0))
        self.connect((self.nrsc5_hdc_encoder_0, 0), (self.nrsc5_l2_encoder_0, 0))
        self.connect((self.nrsc5_l1_am_encoder_ma1_0, 0), (self.fft_vxx_0, 0))
        self.connect((self.nrsc5_l2_encoder_0, 0), (self.nrsc5_l1_am_encoder_ma1_0, 0))
        self.connect((self.nrsc5_psd_encoder_0, 0), (self.nrsc5_l2_encoder_0, 1))
        self.connect((self.nrsc5_sis_encoder_0, 0), (self.nrsc5_l1_am_encoder_ma1_0, 2))
        self.connect((self.rational_resampler_xxx_0, 0), (self.rational_resampler_xxx_0_0, 0))
        self.connect((self.rational_resampler_xxx_0_0, 0), (self.blocks_add_xx_0, 1))
        self.connect((self.rational_resampler_xxx_1, 0), (self.rational_resampler_xxx_2, 0))
        self.connect((self.rational_resampler_xxx_2, 0), (self.blocks_add_xx_0, 0))


    def get_samp_rate(self):
        return self.samp_rate

    def set_samp_rate(self, samp_rate):
        self.samp_rate = samp_rate
        self.blocks_rotator_cc_0.set_phase_inc(-2 * math.pi * 100000 / self.samp_rate)
        self.osmosdr_sink_0.set_sample_rate(self.samp_rate)

    def get_freq(self):
        return self.freq

    def set_freq(self, freq):
        self.freq = freq
        self.osmosdr_sink_0.set_center_freq(self.freq + 100000, 0)

    def get_audio_rate(self):
        return self.audio_rate

    def set_audio_rate(self, audio_rate):
        self.audio_rate = audio_rate
        self.blocks_delay_0.set_dly(int(self.audio_rate * 5.5))
        self.low_pass_filter_1.set_taps(firdes.low_pass(0.5, self.audio_rate, 4500, 1000, window.WIN_HAMMING, 6.76))




def main(top_block_cls=hd_tx_am_hackrf, options=None):
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
