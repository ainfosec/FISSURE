#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#
# SPDX-License-Identifier: GPL-3.0
#
# GNU Radio Python Flow Graph
# Title: Fm Radio Fm Hackrf From Wav File
# GNU Radio version: 3.8.5.0

from gnuradio import analog
from gnuradio import blocks
from gnuradio import filter
from gnuradio import gr
from gnuradio.filter import firdes
import sys
import signal
from argparse import ArgumentParser
from gnuradio.eng_arg import eng_float, intx
from gnuradio import eng_notation
import osmosdr
import time


class FM_Radio_FM_HackRF_From_Wav_File(gr.top_block):

    def __init__(self):
        gr.top_block.__init__(self, "Fm Radio Fm Hackrf From Wav File")

        ##################################################
        # Variables
        ##################################################
        self.tx_gain = tx_gain = 40
        self.tx_frequency = tx_frequency = 96.9e6
        self.serial = serial = "0"
        self.sample_rate = sample_rate = 1e6
        self.repeat = repeat = "Yes"
        self.notes = notes = "Converts a .wav file to an FM signal."
        self.filepath = filepath = "/home/user/FISSURE/Flow Graph Library/Single-Stage Flow Graphs/Attack Files/tone.wav"
        self.audio_rate = audio_rate = 48000

        ##################################################
        # Blocks
        ##################################################
        self.osmosdr_sink_0 = osmosdr.sink(
            args="numchan=" + str(1) + " " + "hackrf=" + str(serial)
        )
        self.osmosdr_sink_0.set_time_unknown_pps(osmosdr.time_spec_t())
        self.osmosdr_sink_0.set_sample_rate(sample_rate)
        self.osmosdr_sink_0.set_center_freq(tx_frequency, 0)
        self.osmosdr_sink_0.set_freq_corr(0, 0)
        self.osmosdr_sink_0.set_gain(tx_gain, 0)
        self.osmosdr_sink_0.set_if_gain(20, 0)
        self.osmosdr_sink_0.set_bb_gain(20, 0)
        self.osmosdr_sink_0.set_antenna('', 0)
        self.osmosdr_sink_0.set_bandwidth(0, 0)
        self.mmse_resampler_xx_0 = filter.mmse_resampler_ff(0, audio_rate/sample_rate)
        self.blocks_wavfile_source_0 = blocks.wavfile_source(filepath, True)
        self.analog_wfm_tx_0 = analog.wfm_tx(
        	audio_rate=480000,
        	quad_rate=480000,
        	tau=75e-6,
        	max_dev=75e3,
        	fh=-1.0,
        )


        ##################################################
        # Connections
        ##################################################
        self.connect((self.analog_wfm_tx_0, 0), (self.osmosdr_sink_0, 0))
        self.connect((self.blocks_wavfile_source_0, 0), (self.mmse_resampler_xx_0, 0))
        self.connect((self.mmse_resampler_xx_0, 0), (self.analog_wfm_tx_0, 0))


    def get_tx_gain(self):
        return self.tx_gain

    def set_tx_gain(self, tx_gain):
        self.tx_gain = tx_gain
        self.osmosdr_sink_0.set_gain(self.tx_gain, 0)

    def get_tx_frequency(self):
        return self.tx_frequency

    def set_tx_frequency(self, tx_frequency):
        self.tx_frequency = tx_frequency
        self.osmosdr_sink_0.set_center_freq(self.tx_frequency, 0)

    def get_serial(self):
        return self.serial

    def set_serial(self, serial):
        self.serial = serial

    def get_sample_rate(self):
        return self.sample_rate

    def set_sample_rate(self, sample_rate):
        self.sample_rate = sample_rate
        self.mmse_resampler_xx_0.set_resamp_ratio(self.audio_rate/self.sample_rate)
        self.osmosdr_sink_0.set_sample_rate(self.sample_rate)

    def get_repeat(self):
        return self.repeat

    def set_repeat(self, repeat):
        self.repeat = repeat

    def get_notes(self):
        return self.notes

    def set_notes(self, notes):
        self.notes = notes

    def get_filepath(self):
        return self.filepath

    def set_filepath(self, filepath):
        self.filepath = filepath

    def get_audio_rate(self):
        return self.audio_rate

    def set_audio_rate(self, audio_rate):
        self.audio_rate = audio_rate
        self.mmse_resampler_xx_0.set_resamp_ratio(self.audio_rate/self.sample_rate)





def main(top_block_cls=FM_Radio_FM_HackRF_From_Wav_File, options=None):
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
