#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#
# SPDX-License-Identifier: GPL-3.0
#
# GNU Radio Python Flow Graph
# Title: Morse Code Ook Usrpb205Mini File
# GNU Radio version: 3.10.1.1

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
import Morse_Code_OOK_USRPB205mini_File_epy_block_0 as epy_block_0  # embedded python block
import foo
import pmt




class Morse_Code_OOK_USRPB205mini_File(gr.top_block):

    def __init__(self):
        gr.top_block.__init__(self, "Morse Code Ook Usrpb205Mini File", catch_exceptions=True)

        ##################################################
        # Variables
        ##################################################
        self.volume = volume = .05
        self.text = text = "Hello World!"
        self.symbol_rate = symbol_rate = 300
        self.speed = speed = 13
        self.serial = serial = "False"
        self.sample_rate = sample_rate = 1e6
        self.repeat = repeat = 4430
        self.notes = notes = "Generates Morse Code for one user-provided message and writes the IQ samples to file. The audio will stop when the message is complete."
        self.freq = freq = 800
        self.filepath = filepath = ""
        self.audio_rate = audio_rate = 48000

        ##################################################
        # Blocks
        ##################################################
        self.root_raised_cosine_filter_0_0 = filter.fir_filter_fff(
            1,
            firdes.root_raised_cosine(
                1,
                audio_rate,
                symbol_rate,
                0.35,
                200))
        self.root_raised_cosine_filter_0 = filter.fir_filter_fff(
            1,
            firdes.root_raised_cosine(
                1,
                audio_rate,
                symbol_rate,
                0.35,
                200))
        self.mmse_resampler_xx_0 = filter.mmse_resampler_cc(0, sample_rate/audio_rate)
        self.foo_periodic_msg_source_0 = foo.periodic_msg_source(pmt.intern(str(text)), 60000, 1, True, False)
        self.epy_block_0 = epy_block_0.mc_sync_block()
        self.blocks_uchar_to_float_0 = blocks.uchar_to_float()
        self.blocks_repeat_0 = blocks.repeat(gr.sizeof_char*1, repeat)
        self.blocks_multiply_xx_0 = blocks.multiply_vff(1)
        self.blocks_multiply_const_vxx_0 = blocks.multiply_const_ff(volume)
        self.blocks_float_to_complex_0 = blocks.float_to_complex(1)
        self.blocks_file_sink_0 = blocks.file_sink(gr.sizeof_gr_complex*1, filepath, False)
        self.blocks_file_sink_0.set_unbuffered(False)
        self.audio_sink_0 = audio.sink(48000, '', True)
        self.analog_sig_source_x_0 = analog.sig_source_f(audio_rate, analog.GR_COS_WAVE, freq, 0.5, 0, 0)


        ##################################################
        # Connections
        ##################################################
        self.msg_connect((self.foo_periodic_msg_source_0, 'out'), (self.epy_block_0, 'msg_in'))
        self.connect((self.analog_sig_source_x_0, 0), (self.blocks_multiply_const_vxx_0, 0))
        self.connect((self.blocks_float_to_complex_0, 0), (self.mmse_resampler_xx_0, 0))
        self.connect((self.blocks_multiply_const_vxx_0, 0), (self.blocks_multiply_xx_0, 1))
        self.connect((self.blocks_multiply_xx_0, 0), (self.audio_sink_0, 0))
        self.connect((self.blocks_repeat_0, 0), (self.blocks_uchar_to_float_0, 0))
        self.connect((self.blocks_uchar_to_float_0, 0), (self.root_raised_cosine_filter_0, 0))
        self.connect((self.epy_block_0, 0), (self.blocks_repeat_0, 0))
        self.connect((self.mmse_resampler_xx_0, 0), (self.blocks_file_sink_0, 0))
        self.connect((self.root_raised_cosine_filter_0, 0), (self.root_raised_cosine_filter_0_0, 0))
        self.connect((self.root_raised_cosine_filter_0_0, 0), (self.blocks_float_to_complex_0, 0))
        self.connect((self.root_raised_cosine_filter_0_0, 0), (self.blocks_multiply_xx_0, 0))


    def get_volume(self):
        return self.volume

    def set_volume(self, volume):
        self.volume = volume
        self.blocks_multiply_const_vxx_0.set_k(self.volume)

    def get_text(self):
        return self.text

    def set_text(self, text):
        self.text = text

    def get_symbol_rate(self):
        return self.symbol_rate

    def set_symbol_rate(self, symbol_rate):
        self.symbol_rate = symbol_rate
        self.root_raised_cosine_filter_0.set_taps(firdes.root_raised_cosine(1, self.audio_rate, self.symbol_rate, 0.35, 200))
        self.root_raised_cosine_filter_0_0.set_taps(firdes.root_raised_cosine(1, self.audio_rate, self.symbol_rate, 0.35, 200))

    def get_speed(self):
        return self.speed

    def set_speed(self, speed):
        self.speed = speed

    def get_serial(self):
        return self.serial

    def set_serial(self, serial):
        self.serial = serial

    def get_sample_rate(self):
        return self.sample_rate

    def set_sample_rate(self, sample_rate):
        self.sample_rate = sample_rate
        self.mmse_resampler_xx_0.set_resamp_ratio(self.sample_rate/self.audio_rate)

    def get_repeat(self):
        return self.repeat

    def set_repeat(self, repeat):
        self.repeat = repeat
        self.blocks_repeat_0.set_interpolation(self.repeat)

    def get_notes(self):
        return self.notes

    def set_notes(self, notes):
        self.notes = notes

    def get_freq(self):
        return self.freq

    def set_freq(self, freq):
        self.freq = freq
        self.analog_sig_source_x_0.set_frequency(self.freq)

    def get_filepath(self):
        return self.filepath

    def set_filepath(self, filepath):
        self.filepath = filepath
        self.blocks_file_sink_0.open(self.filepath)

    def get_audio_rate(self):
        return self.audio_rate

    def set_audio_rate(self, audio_rate):
        self.audio_rate = audio_rate
        self.analog_sig_source_x_0.set_sampling_freq(self.audio_rate)
        self.mmse_resampler_xx_0.set_resamp_ratio(self.sample_rate/self.audio_rate)
        self.root_raised_cosine_filter_0.set_taps(firdes.root_raised_cosine(1, self.audio_rate, self.symbol_rate, 0.35, 200))
        self.root_raised_cosine_filter_0_0.set_taps(firdes.root_raised_cosine(1, self.audio_rate, self.symbol_rate, 0.35, 200))




def main(top_block_cls=Morse_Code_OOK_USRPB205mini_File, options=None):
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
