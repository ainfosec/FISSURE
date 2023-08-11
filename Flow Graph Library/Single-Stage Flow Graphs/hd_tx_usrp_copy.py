#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#
# SPDX-License-Identifier: GPL-3.0
#
# GNU Radio Python Flow Graph
# Title: Hd Tx Usrp Copy
# GNU Radio version: 3.8.5.0

from gnuradio import analog
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
from gnuradio import uhd
import time
import math
import nrsc5


class hd_tx_usrp_copy(gr.top_block):

    def __init__(self, artist="Test Artist", frequency="90.5e6", gain="70", title="Test Title", wav1_filepath="/home/use2r/FISSURE/Flow Graph Library/Single-Stage Flow Graphs/Attack Files/sample.wav", wav2_filepath="/home/u2ser/FISSURE/Flow Graph Library/Single-Stage Flow Graphs/Attack Files/sample_mono.wav"):
        gr.top_block.__init__(self, "Hd Tx Usrp Copy")

        ##################################################
        # Parameters
        ##################################################
        self.artist = artist
        self.frequency = frequency
        self.gain = gain
        self.title = title
        self.wav1_filepath = wav1_filepath
        self.wav2_filepath = wav2_filepath

        ##################################################
        # Variables
        ##################################################
        self.samp_rate = samp_rate = 2000000
        self.audio_rate = audio_rate = 44100

        ##################################################
        # Blocks
        ##################################################
        self.uhd_usrp_sink_0 = uhd.usrp_sink(
            ",".join(("", '')),
            uhd.stream_args(
                cpu_format="fc32",
                args='peak=0.003906',
                channels=list(range(0,1)),
            ),
            '',
        )
        self.uhd_usrp_sink_0.set_center_freq(float(frequency), 0)
        self.uhd_usrp_sink_0.set_gain(float(gain), 0)
        self.uhd_usrp_sink_0.set_antenna('TX/RX', 0)
        self.uhd_usrp_sink_0.set_samp_rate(samp_rate)
        self.uhd_usrp_sink_0.set_time_unknown_pps(uhd.time_spec())
        self.rational_resampler_xxx_2 = filter.rational_resampler_ccc(
                interpolation=256,
                decimation=243,
                taps=None,
                fractional_bw=0.2)
        self.rational_resampler_xxx_1 = filter.rational_resampler_ccc(
                interpolation=125,
                decimation=49,
                taps=None,
                fractional_bw=0.2)
        self.rational_resampler_xxx_0_0_0 = filter.rational_resampler_ccc(
                interpolation=100,
                decimation=21,
                taps=None,
                fractional_bw=0.2)
        self.rational_resampler_xxx_0_0 = filter.rational_resampler_ccc(
                interpolation=50,
                decimation=21,
                taps=None,
                fractional_bw=0.2)
        self.nrsc5_sis_encoder_0 = nrsc5.sis_encoder('ABCD')
        self.nrsc5_psd_encoder_0 = nrsc5.psd_encoder(0, title, artist)
        self.nrsc5_l2_encoder_0 = nrsc5.l2_encoder(1, 0, 146176)
        self.nrsc5_l1_fm_encoder_mp1_0 = nrsc5.l1_fm_encoder(1)
        self.nrsc5_hdc_encoder_0 = nrsc5.hdc_encoder(2, 64000)
        self.low_pass_filter_0_0 = filter.fir_filter_ccf(
            1,
            firdes.low_pass(
                0.1,
                samp_rate,
                80000,
                20000,
                firdes.WIN_HAMMING,
                6.76))
        self.fft_vxx_0 = fft.fft_vcc(2048, False, window.rectangular(2048), True, 1)
        self.blocks_wavfile_source_1 = blocks.wavfile_source(wav2_filepath, True)
        self.blocks_wavfile_source_0 = blocks.wavfile_source(wav1_filepath, True)
        self.blocks_vector_to_stream_0 = blocks.vector_to_stream(gr.sizeof_gr_complex*1, 2048)
        self.blocks_vector_source_x_0 = blocks.vector_source_c([math.sin(math.pi / 2 * i / 112) for i in range(112)] + [1] * (2048-112) + [math.cos(math.pi / 2 * i / 112) for i in range(112)], True, 1, [])
        self.blocks_repeat_0 = blocks.repeat(gr.sizeof_gr_complex*2048, 2)
        self.blocks_multiply_xx_0 = blocks.multiply_vcc(1)
        self.blocks_multiply_const_vxx_0 = blocks.multiply_const_cc(0.001)
        self.blocks_keep_m_in_n_0 = blocks.keep_m_in_n(gr.sizeof_gr_complex, 2160, 4096, 0)
        self.blocks_delay_0 = blocks.delay(gr.sizeof_float*1, int(audio_rate * 3.5))
        self.blocks_conjugate_cc_0 = blocks.conjugate_cc()
        self.blocks_add_xx_0 = blocks.add_vcc(1)
        self.analog_wfm_tx_0_0 = analog.wfm_tx(
        	audio_rate=audio_rate,
        	quad_rate=audio_rate * 4,
        	tau=75e-6,
        	max_dev=75e3,
        	fh=-1.0,
        )


        ##################################################
        # Connections
        ##################################################
        self.connect((self.analog_wfm_tx_0_0, 0), (self.rational_resampler_xxx_0_0, 0))
        self.connect((self.blocks_add_xx_0, 0), (self.uhd_usrp_sink_0, 0))
        self.connect((self.blocks_conjugate_cc_0, 0), (self.rational_resampler_xxx_1, 0))
        self.connect((self.blocks_delay_0, 0), (self.analog_wfm_tx_0_0, 0))
        self.connect((self.blocks_keep_m_in_n_0, 0), (self.blocks_multiply_xx_0, 1))
        self.connect((self.blocks_multiply_const_vxx_0, 0), (self.blocks_add_xx_0, 0))
        self.connect((self.blocks_multiply_xx_0, 0), (self.blocks_conjugate_cc_0, 0))
        self.connect((self.blocks_repeat_0, 0), (self.blocks_vector_to_stream_0, 0))
        self.connect((self.blocks_vector_source_x_0, 0), (self.blocks_multiply_xx_0, 0))
        self.connect((self.blocks_vector_to_stream_0, 0), (self.blocks_keep_m_in_n_0, 0))
        self.connect((self.blocks_wavfile_source_0, 1), (self.nrsc5_hdc_encoder_0, 1))
        self.connect((self.blocks_wavfile_source_0, 0), (self.nrsc5_hdc_encoder_0, 0))
        self.connect((self.blocks_wavfile_source_1, 0), (self.blocks_delay_0, 0))
        self.connect((self.fft_vxx_0, 0), (self.blocks_repeat_0, 0))
        self.connect((self.low_pass_filter_0_0, 0), (self.blocks_add_xx_0, 1))
        self.connect((self.nrsc5_hdc_encoder_0, 0), (self.nrsc5_l2_encoder_0, 0))
        self.connect((self.nrsc5_l1_fm_encoder_mp1_0, 0), (self.fft_vxx_0, 0))
        self.connect((self.nrsc5_l2_encoder_0, 0), (self.nrsc5_l1_fm_encoder_mp1_0, 0))
        self.connect((self.nrsc5_psd_encoder_0, 0), (self.nrsc5_l2_encoder_0, 1))
        self.connect((self.nrsc5_sis_encoder_0, 0), (self.nrsc5_l1_fm_encoder_mp1_0, 1))
        self.connect((self.rational_resampler_xxx_0_0, 0), (self.rational_resampler_xxx_0_0_0, 0))
        self.connect((self.rational_resampler_xxx_0_0_0, 0), (self.low_pass_filter_0_0, 0))
        self.connect((self.rational_resampler_xxx_1, 0), (self.rational_resampler_xxx_2, 0))
        self.connect((self.rational_resampler_xxx_2, 0), (self.blocks_multiply_const_vxx_0, 0))


    def get_artist(self):
        return self.artist

    def set_artist(self, artist):
        self.artist = artist

    def get_frequency(self):
        return self.frequency

    def set_frequency(self, frequency):
        self.frequency = frequency
        self.uhd_usrp_sink_0.set_center_freq(float(self.frequency), 0)

    def get_gain(self):
        return self.gain

    def set_gain(self, gain):
        self.gain = gain
        self.uhd_usrp_sink_0.set_gain(float(self.gain), 0)

    def get_title(self):
        return self.title

    def set_title(self, title):
        self.title = title

    def get_wav1_filepath(self):
        return self.wav1_filepath

    def set_wav1_filepath(self, wav1_filepath):
        self.wav1_filepath = wav1_filepath

    def get_wav2_filepath(self):
        return self.wav2_filepath

    def set_wav2_filepath(self, wav2_filepath):
        self.wav2_filepath = wav2_filepath

    def get_samp_rate(self):
        return self.samp_rate

    def set_samp_rate(self, samp_rate):
        self.samp_rate = samp_rate
        self.low_pass_filter_0_0.set_taps(firdes.low_pass(0.1, self.samp_rate, 80000, 20000, firdes.WIN_HAMMING, 6.76))
        self.uhd_usrp_sink_0.set_samp_rate(self.samp_rate)

    def get_audio_rate(self):
        return self.audio_rate

    def set_audio_rate(self, audio_rate):
        self.audio_rate = audio_rate
        self.blocks_delay_0.set_dly(int(self.audio_rate * 3.5))




def argument_parser():
    parser = ArgumentParser()
    parser.add_argument(
        "--artist", dest="artist", type=str, default="Test Artist",
        help="Set artist [default=%(default)r]")
    parser.add_argument(
        "--frequency", dest="frequency", type=str, default="90.5e6",
        help="Set frequency [default=%(default)r]")
    parser.add_argument(
        "--gain", dest="gain", type=str, default="70",
        help="Set gain [default=%(default)r]")
    parser.add_argument(
        "--title", dest="title", type=str, default="Test Title",
        help="Set title [default=%(default)r]")
    parser.add_argument(
        "--wav1-filepath", dest="wav1_filepath", type=str, default="/home/use2r/FISSURE/Flow Graph Library/Single-Stage Flow Graphs/Attack Files/sample.wav",
        help="Set wav1_filepath [default=%(default)r]")
    parser.add_argument(
        "--wav2-filepath", dest="wav2_filepath", type=str, default="/home/u2ser/FISSURE/Flow Graph Library/Single-Stage Flow Graphs/Attack Files/sample_mono.wav",
        help="Set wav2_filepath [default=%(default)r]")
    return parser


def main(top_block_cls=hd_tx_usrp_copy, options=None):
    if options is None:
        options = argument_parser().parse_args()
    tb = top_block_cls(artist=options.artist, frequency=options.frequency, gain=options.gain, title=options.title, wav1_filepath=options.wav1_filepath, wav2_filepath=options.wav2_filepath)

    def sig_handler(sig=None, frame=None):
        tb.stop()
        tb.wait()

        sys.exit(0)

    signal.signal(signal.SIGINT, sig_handler)
    signal.signal(signal.SIGTERM, sig_handler)

    tb.start()

    tb.wait()


if __name__ == '__main__':
    main()
