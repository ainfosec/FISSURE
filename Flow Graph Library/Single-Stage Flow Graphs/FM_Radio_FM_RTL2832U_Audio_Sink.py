#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#
# SPDX-License-Identifier: GPL-3.0
#
# GNU Radio Python Flow Graph
# Title: Fm Radio Fm Rtl2832U Audio Sink
# GNU Radio version: 3.10.4.0

from gnuradio import analog
from gnuradio import audio
from gnuradio import blocks
from gnuradio import filter
from gnuradio.filter import firdes
from gnuradio import gr
from gnuradio.fft import window
import sys
import signal
from argparse import ArgumentParser
from gnuradio.eng_arg import eng_float, intx
from gnuradio import eng_notation
from gnuradio import soapy




class FM_Radio_FM_RTL2832U_Audio_Sink(gr.top_block):

    def __init__(self):
        gr.top_block.__init__(self, "Fm Radio Fm Rtl2832U Audio Sink", catch_exceptions=True)

        ##################################################
        # Variables
        ##################################################
        self.sample_rate = sample_rate = 2.56e6
        self.rx_gain = rx_gain = 40
        self.notes = notes = "Plays FM radio audio."
        self.frequency_offset = frequency_offset = 0.3e6
        self.frequency = frequency = 104.3e6
        self.audio_gain = audio_gain = 1

        ##################################################
        # Blocks
        ##################################################
        self.soapy_rtlsdr_source_0 = None
        dev = 'driver=rtlsdr'
        stream_args = ''
        tune_args = ['']
        settings = ['']

        self.soapy_rtlsdr_source_0 = soapy.source(dev, "fc32", 1, '',
                                  stream_args, tune_args, settings)
        self.soapy_rtlsdr_source_0.set_sample_rate(0, float(sample_rate))
        self.soapy_rtlsdr_source_0.set_gain_mode(0, False)
        self.soapy_rtlsdr_source_0.set_frequency(0, (float(frequency)+float(frequency_offset)))
        self.soapy_rtlsdr_source_0.set_frequency_correction(0, 0)
        self.soapy_rtlsdr_source_0.set_gain(0, 'TUNER', float(rx_gain))
        self.mmse_resampler_xx_0 = filter.mmse_resampler_cc(0, (sample_rate/4800000))
        self.low_pass_filter_0 = filter.fir_filter_ccf(
            10,
            firdes.low_pass(
                1,
                sample_rate,
                75e3,
                25e3,
                window.WIN_HAMMING,
                6.76))
        self.blocks_multiply_xx_0 = blocks.multiply_vcc(1)
        self.blocks_multiply_const_vxx_0 = blocks.multiply_const_ff(audio_gain)
        self.audio_sink_0 = audio.sink(48000, '', True)
        self.analog_wfm_rcv_0 = analog.wfm_rcv(
        	quad_rate=480e3,
        	audio_decimation=10,
        )
        self.analog_sig_source_x_0 = analog.sig_source_c(sample_rate, analog.GR_COS_WAVE, frequency_offset, 1, 0, 0)


        ##################################################
        # Connections
        ##################################################
        self.connect((self.analog_sig_source_x_0, 0), (self.blocks_multiply_xx_0, 1))
        self.connect((self.analog_wfm_rcv_0, 0), (self.blocks_multiply_const_vxx_0, 0))
        self.connect((self.blocks_multiply_const_vxx_0, 0), (self.audio_sink_0, 0))
        self.connect((self.blocks_multiply_xx_0, 0), (self.low_pass_filter_0, 0))
        self.connect((self.low_pass_filter_0, 0), (self.mmse_resampler_xx_0, 0))
        self.connect((self.mmse_resampler_xx_0, 0), (self.analog_wfm_rcv_0, 0))
        self.connect((self.soapy_rtlsdr_source_0, 0), (self.blocks_multiply_xx_0, 0))


    def get_sample_rate(self):
        return self.sample_rate

    def set_sample_rate(self, sample_rate):
        self.sample_rate = sample_rate
        self.analog_sig_source_x_0.set_sampling_freq(self.sample_rate)
        self.low_pass_filter_0.set_taps(firdes.low_pass(1, self.sample_rate, 75e3, 25e3, window.WIN_HAMMING, 6.76))
        self.mmse_resampler_xx_0.set_resamp_ratio((self.sample_rate/4800000))
        self.soapy_rtlsdr_source_0.set_sample_rate(0, float(self.sample_rate))

    def get_rx_gain(self):
        return self.rx_gain

    def set_rx_gain(self, rx_gain):
        self.rx_gain = rx_gain
        self.soapy_rtlsdr_source_0.set_gain(0, 'TUNER', float(self.rx_gain))

    def get_notes(self):
        return self.notes

    def set_notes(self, notes):
        self.notes = notes

    def get_frequency_offset(self):
        return self.frequency_offset

    def set_frequency_offset(self, frequency_offset):
        self.frequency_offset = frequency_offset
        self.analog_sig_source_x_0.set_frequency(self.frequency_offset)
        self.soapy_rtlsdr_source_0.set_frequency(0, (float(self.frequency)+float(self.frequency_offset)))

    def get_frequency(self):
        return self.frequency

    def set_frequency(self, frequency):
        self.frequency = frequency
        self.soapy_rtlsdr_source_0.set_frequency(0, (float(self.frequency)+float(self.frequency_offset)))

    def get_audio_gain(self):
        return self.audio_gain

    def set_audio_gain(self, audio_gain):
        self.audio_gain = audio_gain
        self.blocks_multiply_const_vxx_0.set_k(self.audio_gain)




def main(top_block_cls=FM_Radio_FM_RTL2832U_Audio_Sink, options=None):
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
