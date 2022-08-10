#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#
# SPDX-License-Identifier: GPL-3.0
#
# GNU Radio Python Flow Graph
# Title: Mode S Ppm Usrpb205Mini Stdout
# GNU Radio version: 3.8.1.0

from gnuradio import blocks
import pmt
from gnuradio import digital
from gnuradio import gr
from gnuradio.filter import firdes
import sys
import signal
from argparse import ArgumentParser
from gnuradio.eng_arg import eng_float, intx
from gnuradio import eng_notation
import adsb
import grgsm

class Mode_S_PPM_USRPB205mini_stdout(gr.top_block):

    def __init__(self):
        gr.top_block.__init__(self, "Mode S Ppm Usrpb205Mini Stdout")

        ##################################################
        # Variables
        ##################################################
        self.serial = serial = "False"
        self.samp_rate = samp_rate = 2e6
        self.notes = notes = "Prints ADSB data to stdout."
        self.gain = gain = 70
        self.freq = freq = 1090e6
        self.channel = channel = "A:A"
        self.antenna = antenna = "TX/RX"

        ##################################################
        # Blocks
        ##################################################
        self.gsm_message_file_sink_0 = grgsm.message_file_sink('/dev/stdout')
        self.digital_correlate_access_code_tag_xx_0 = digital.correlate_access_code_tag_bb('1010000101000000', 0, 'adsb_preamble')
        self.blocks_threshold_ff_0 = blocks.threshold_ff(0.1, 0.1, 0)
        self.blocks_float_to_uchar_0 = blocks.float_to_uchar()
        self.blocks_file_source_0 = blocks.file_source(gr.sizeof_gr_complex*1, '/home/user/adsb.iq', False, 0, 0)
        self.blocks_file_source_0.set_begin_tag(pmt.PMT_NIL)
        self.blocks_complex_to_mag_squared_0 = blocks.complex_to_mag_squared(1)
        self.adsb_framer_0 = adsb.framer()
        self.adsb_decoder_0 = adsb.decoder('csv',True)



        ##################################################
        # Connections
        ##################################################
        self.msg_connect((self.adsb_decoder_0, 'out'), (self.gsm_message_file_sink_0, 'in'))
        self.msg_connect((self.adsb_framer_0, 'out'), (self.adsb_decoder_0, 'in'))
        self.connect((self.blocks_complex_to_mag_squared_0, 0), (self.blocks_threshold_ff_0, 0))
        self.connect((self.blocks_file_source_0, 0), (self.blocks_complex_to_mag_squared_0, 0))
        self.connect((self.blocks_float_to_uchar_0, 0), (self.digital_correlate_access_code_tag_xx_0, 0))
        self.connect((self.blocks_threshold_ff_0, 0), (self.blocks_float_to_uchar_0, 0))
        self.connect((self.digital_correlate_access_code_tag_xx_0, 0), (self.adsb_framer_0, 0))

    def get_serial(self):
        return self.serial

    def set_serial(self, serial):
        self.serial = serial

    def get_samp_rate(self):
        return self.samp_rate

    def set_samp_rate(self, samp_rate):
        self.samp_rate = samp_rate

    def get_notes(self):
        return self.notes

    def set_notes(self, notes):
        self.notes = notes

    def get_gain(self):
        return self.gain

    def set_gain(self, gain):
        self.gain = gain

    def get_freq(self):
        return self.freq

    def set_freq(self, freq):
        self.freq = freq

    def get_channel(self):
        return self.channel

    def set_channel(self, channel):
        self.channel = channel

    def get_antenna(self):
        return self.antenna

    def set_antenna(self, antenna):
        self.antenna = antenna



def main(top_block_cls=Mode_S_PPM_USRPB205mini_stdout, options=None):
    tb = top_block_cls()

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
