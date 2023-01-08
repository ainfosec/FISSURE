#!/usr/bin/env python2
# -*- coding: utf-8 -*-
##################################################
# GNU Radio Python Flow Graph
# Title: Fm Radio Fm Usrpb210 From Wav File
# GNU Radio version: 3.7.13.5
##################################################


from gnuradio import analog
from gnuradio import blocks
from gnuradio import eng_notation
from gnuradio import filter
from gnuradio import gr
from gnuradio import uhd
from gnuradio.eng_option import eng_option
from gnuradio.filter import firdes
from optparse import OptionParser
import time


class FM_Radio_FM_USRPB210_From_Wav_File(gr.top_block):

    def __init__(self):
        gr.top_block.__init__(self, "Fm Radio Fm Usrpb210 From Wav File")

        ##################################################
        # Variables
        ##################################################
        self.tx_usrp_gain = tx_usrp_gain = 70
        self.tx_usrp_channel = tx_usrp_channel = "A:A"
        self.tx_usrp_antenna = tx_usrp_antenna = "TX/RX"
        self.tx_frequency = tx_frequency = 96.9e6
        self.serial = serial = "False"
        self.sample_rate = sample_rate = 1e6
        self.repeat = repeat = "Yes"
        self.notes = notes = "Converts a .wav file to an FM signal."
        self.filepath = filepath = "/home/user/FISSURE/Flow Graph Library/Single-Stage Flow Graphs/Attack Files/tone.wav"
        self.audio_rate = audio_rate = 48000

        ##################################################
        # Blocks
        ##################################################
        self.uhd_usrp_sink_0 = uhd.usrp_sink(
        	",".join((serial, "")),
        	uhd.stream_args(
        		cpu_format="fc32",
        		channels=range(1),
        	),
        )
        self.uhd_usrp_sink_0.set_subdev_spec(tx_usrp_channel, 0)
        self.uhd_usrp_sink_0.set_samp_rate(sample_rate)
        self.uhd_usrp_sink_0.set_center_freq(tx_frequency, 0)
        self.uhd_usrp_sink_0.set_gain(tx_usrp_gain, 0)
        self.uhd_usrp_sink_0.set_antenna(tx_usrp_antenna, 0)
        self.fractional_resampler_xx_0 = filter.fractional_resampler_ff(0, audio_rate/sample_rate)
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
        self.connect((self.analog_wfm_tx_0, 0), (self.uhd_usrp_sink_0, 0))
        self.connect((self.blocks_wavfile_source_0, 0), (self.fractional_resampler_xx_0, 0))
        self.connect((self.fractional_resampler_xx_0, 0), (self.analog_wfm_tx_0, 0))

    def get_tx_usrp_gain(self):
        return self.tx_usrp_gain

    def set_tx_usrp_gain(self, tx_usrp_gain):
        self.tx_usrp_gain = tx_usrp_gain
        self.uhd_usrp_sink_0.set_gain(self.tx_usrp_gain, 0)


    def get_tx_usrp_channel(self):
        return self.tx_usrp_channel

    def set_tx_usrp_channel(self, tx_usrp_channel):
        self.tx_usrp_channel = tx_usrp_channel

    def get_tx_usrp_antenna(self):
        return self.tx_usrp_antenna

    def set_tx_usrp_antenna(self, tx_usrp_antenna):
        self.tx_usrp_antenna = tx_usrp_antenna
        self.uhd_usrp_sink_0.set_antenna(self.tx_usrp_antenna, 0)

    def get_tx_frequency(self):
        return self.tx_frequency

    def set_tx_frequency(self, tx_frequency):
        self.tx_frequency = tx_frequency
        self.uhd_usrp_sink_0.set_center_freq(self.tx_frequency, 0)

    def get_serial(self):
        return self.serial

    def set_serial(self, serial):
        self.serial = serial

    def get_sample_rate(self):
        return self.sample_rate

    def set_sample_rate(self, sample_rate):
        self.sample_rate = sample_rate
        self.uhd_usrp_sink_0.set_samp_rate(self.sample_rate)
        self.fractional_resampler_xx_0.set_resamp_ratio(self.audio_rate/self.sample_rate)

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
        self.fractional_resampler_xx_0.set_resamp_ratio(self.audio_rate/self.sample_rate)


def main(top_block_cls=FM_Radio_FM_USRPB210_From_Wav_File, options=None):

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
