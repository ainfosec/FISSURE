#!/usr/bin/env python2
# -*- coding: utf-8 -*-
##################################################
# GNU Radio Python Flow Graph
# Title: Hd Tx Usrp Copy
# GNU Radio version: 3.7.13.5
##################################################


from gnuradio import analog
from gnuradio import blocks
from gnuradio import digital
from gnuradio import eng_notation
from gnuradio import fft
from gnuradio import filter
from gnuradio import gr
from gnuradio import uhd
from gnuradio.eng_option import eng_option
from gnuradio.fft import window
from gnuradio.filter import firdes
from optparse import OptionParser
import math
import nrsc5
import time


class hd_tx_usrp_copy(gr.top_block):

    def __init__(self, artist="Test Artist", frequency="90.5e6", gain="70", title="Test Title", wav1_filepath="/home/user/FISSURE/Flow Graph Library/Single-Stage Flow Graphs/Attack Files/sample.wav"):
        gr.top_block.__init__(self, "Hd Tx Usrp Copy")

        ##################################################
        # Parameters
        ##################################################
        self.artist = artist
        self.frequency = frequency
        self.gain = gain
        self.title = title
        self.wav1_filepath = wav1_filepath

        ##################################################
        # Variables
        ##################################################
        self.samp_rate = samp_rate = 2000000

        ##################################################
        # Blocks
        ##################################################
        self.uhd_usrp_sink_0 = uhd.usrp_sink(
        	",".join(("", "send_frame_size=65536,num_send_frames=128")),
        	uhd.stream_args(
        		cpu_format="fc32",
        		channels=range(1),
        	),
        )
        self.uhd_usrp_sink_0.set_samp_rate(samp_rate)
        self.uhd_usrp_sink_0.set_center_freq(float(frequency), 0)
        self.uhd_usrp_sink_0.set_gain(float(gain), 0)
        self.uhd_usrp_sink_0.set_antenna('TX/RX', 0)
        self.rational_resampler_xxx_2 = filter.rational_resampler_ccc(
                interpolation=256,
                decimation=243,
                taps=None,
                fractional_bw=None,
        )
        self.rational_resampler_xxx_1 = filter.rational_resampler_ccc(
                interpolation=125,
                decimation=49,
                taps=None,
                fractional_bw=None,
        )
        self.rational_resampler_xxx_0 = filter.rational_resampler_ccc(
                interpolation=samp_rate / 200000,
                decimation=1,
                taps=None,
                fractional_bw=None,
        )
        self.nrsc5_sis_encoder_0 = nrsc5.sis_encoder('ABCD')
        self.nrsc5_psd_encoder_0 = nrsc5.psd_encoder(0, title, artist)
        self.nrsc5_l2_encoder_0 = nrsc5.l2_encoder(1, 0, 146176)
        self.nrsc5_l1_fm_encoder_mp1_0 = nrsc5.l1_fm_encoder(1)
        self.nrsc5_hdc_encoder_0 = nrsc5.hdc_encoder(2, 64000)
        self.low_pass_filter_0 = filter.fir_filter_ccf(1, firdes.low_pass(
        	1, samp_rate, 80000, 20000, firdes.WIN_HAMMING, 6.76))
        self.fft_vxx_0 = fft.fft_vcc(2048, False, (window.rectangular(2048)), True, 1)
        self.digital_chunks_to_symbols_xx_0 = digital.chunks_to_symbols_bc((-1-1j, -1+1j, 1-1j, 1+1j, 0), 1)
        self.blocks_wavfile_source_0 = blocks.wavfile_source(wav1_filepath, True)
        self.blocks_vector_to_stream_1 = blocks.vector_to_stream(gr.sizeof_char*1, 1048576)
        self.blocks_vector_to_stream_0 = blocks.vector_to_stream(gr.sizeof_gr_complex*1, 2048)
        self.blocks_vector_source_x_0 = blocks.vector_source_c([math.sin(math.pi / 2 * i / 112) for i in range(112)] + [1] * (2048-112) + [math.cos(math.pi / 2 * i / 112) for i in range(112)], True, 1, [])
        self.blocks_stream_to_vector_0 = blocks.stream_to_vector(gr.sizeof_gr_complex*1, 2048)
        self.blocks_repeat_0 = blocks.repeat(gr.sizeof_gr_complex*2048, 2)
        self.blocks_multiply_xx_0 = blocks.multiply_vcc(1)
        self.blocks_multiply_const_vxx_1 = blocks.multiply_const_vcc((0.1, ))
        self.blocks_multiply_const_vxx_0 = blocks.multiply_const_vcc((0.001, ))
        self.blocks_keep_m_in_n_0 = blocks.keep_m_in_n(gr.sizeof_gr_complex, 2160, 4096, 0)
        self.blocks_conjugate_cc_0 = blocks.conjugate_cc()
        self.blocks_add_xx_0 = blocks.add_vcc(1)
        self.analog_wfm_tx_0 = analog.wfm_tx(
        	audio_rate=50000,
        	quad_rate=200000,
        	tau=75e-6,
        	max_dev=75e3,
        	fh=-1.0,
        )
        self.analog_sig_source_x_0 = analog.sig_source_f(50000, analog.GR_COS_WAVE, 1000, 0.1, 0)



        ##################################################
        # Connections
        ##################################################
        self.connect((self.analog_sig_source_x_0, 0), (self.analog_wfm_tx_0, 0))
        self.connect((self.analog_wfm_tx_0, 0), (self.rational_resampler_xxx_0, 0))
        self.connect((self.blocks_add_xx_0, 0), (self.uhd_usrp_sink_0, 0))
        self.connect((self.blocks_conjugate_cc_0, 0), (self.rational_resampler_xxx_1, 0))
        self.connect((self.blocks_keep_m_in_n_0, 0), (self.blocks_multiply_xx_0, 1))
        self.connect((self.blocks_multiply_const_vxx_0, 0), (self.blocks_add_xx_0, 0))
        self.connect((self.blocks_multiply_const_vxx_1, 0), (self.blocks_add_xx_0, 1))
        self.connect((self.blocks_multiply_xx_0, 0), (self.blocks_conjugate_cc_0, 0))
        self.connect((self.blocks_repeat_0, 0), (self.blocks_vector_to_stream_0, 0))
        self.connect((self.blocks_stream_to_vector_0, 0), (self.fft_vxx_0, 0))
        self.connect((self.blocks_vector_source_x_0, 0), (self.blocks_multiply_xx_0, 0))
        self.connect((self.blocks_vector_to_stream_0, 0), (self.blocks_keep_m_in_n_0, 0))
        self.connect((self.blocks_vector_to_stream_1, 0), (self.digital_chunks_to_symbols_xx_0, 0))
        self.connect((self.blocks_wavfile_source_0, 0), (self.nrsc5_hdc_encoder_0, 0))
        self.connect((self.blocks_wavfile_source_0, 1), (self.nrsc5_hdc_encoder_0, 1))
        self.connect((self.digital_chunks_to_symbols_xx_0, 0), (self.blocks_stream_to_vector_0, 0))
        self.connect((self.fft_vxx_0, 0), (self.blocks_repeat_0, 0))
        self.connect((self.low_pass_filter_0, 0), (self.blocks_multiply_const_vxx_1, 0))
        self.connect((self.nrsc5_hdc_encoder_0, 0), (self.nrsc5_l2_encoder_0, 0))
        self.connect((self.nrsc5_l1_fm_encoder_mp1_0, 0), (self.blocks_vector_to_stream_1, 0))
        self.connect((self.nrsc5_l2_encoder_0, 0), (self.nrsc5_l1_fm_encoder_mp1_0, 0))
        self.connect((self.nrsc5_psd_encoder_0, 0), (self.nrsc5_l2_encoder_0, 1))
        self.connect((self.nrsc5_sis_encoder_0, 0), (self.nrsc5_l1_fm_encoder_mp1_0, 1))
        self.connect((self.rational_resampler_xxx_0, 0), (self.low_pass_filter_0, 0))
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

    def get_samp_rate(self):
        return self.samp_rate

    def set_samp_rate(self, samp_rate):
        self.samp_rate = samp_rate
        self.uhd_usrp_sink_0.set_samp_rate(self.samp_rate)
        self.low_pass_filter_0.set_taps(firdes.low_pass(1, self.samp_rate, 80000, 20000, firdes.WIN_HAMMING, 6.76))


def argument_parser():
    parser = OptionParser(usage="%prog: [options]", option_class=eng_option)
    parser.add_option(
        "", "--artist", dest="artist", type="string", default="Test Artist",
        help="Set artist [default=%default]")
    parser.add_option(
        "", "--frequency", dest="frequency", type="string", default="90.5e6",
        help="Set frequency [default=%default]")
    parser.add_option(
        "", "--gain", dest="gain", type="string", default="70",
        help="Set gain [default=%default]")
    parser.add_option(
        "", "--title", dest="title", type="string", default="Test Title",
        help="Set title [default=%default]")
    parser.add_option(
        "", "--wav1-filepath", dest="wav1_filepath", type="string", default="/home/user/FISSURE/Flow Graph Library/Single-Stage Flow Graphs/Attack Files/sample.wav",
        help="Set wav1_filepath [default=%default]")
    return parser


def main(top_block_cls=hd_tx_usrp_copy, options=None):
    if options is None:
        options, _ = argument_parser().parse_args()

    tb = top_block_cls(artist=options.artist, frequency=options.frequency, gain=options.gain, title=options.title, wav1_filepath=options.wav1_filepath)
    tb.start()
    try:
        raw_input('Press Enter to quit: ')
    except EOFError:
        pass
    tb.stop()
    tb.wait()


if __name__ == '__main__':
    main()
