#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#
# SPDX-License-Identifier: GPL-3.0
#
# GNU Radio Python Flow Graph
# Title: Iq File
# GNU Radio version: 3.10.7.0

from gnuradio import analog
from gnuradio import blocks
import pmt
from gnuradio import fft
from gnuradio.fft import window
from gnuradio import gr
from gnuradio.filter import firdes
import sys
import signal
from argparse import ArgumentParser
from gnuradio.eng_arg import eng_float, intx
from gnuradio import eng_notation
import gnuradio.ainfosec as ainfosec




class iq_file(gr.top_block):

    def __init__(self):
        gr.top_block.__init__(self, "Iq File", catch_exceptions=True)

        ##################################################
        # Variables
        ##################################################
        self.threshold = threshold = -70
        self.sample_rate = sample_rate = 20000000
        self.rx_freq = rx_freq = 1200e6
        self.filepath = filepath = ""
        self.fft_size = fft_size = 512*1

        ##################################################
        # Blocks
        ##################################################

        self.fft_vxx_0 = fft.fft_vcc(fft_size, True, window.blackmanharris(fft_size), True, 1)
        self.blocks_vector_to_stream_0 = blocks.vector_to_stream(gr.sizeof_gr_complex*1, fft_size)
        self.blocks_throttle2_0 = blocks.throttle( gr.sizeof_gr_complex*1, sample_rate, True, 0 if "auto" == "auto" else max( int(float(0.1) * sample_rate) if "auto" == "time" else int(0.1), 1) )
        self.blocks_stream_to_vector_1 = blocks.stream_to_vector(gr.sizeof_gr_complex*1, fft_size)
        self.blocks_nlog10_ff_0 = blocks.nlog10_ff(10, 1, 0)
        self.blocks_file_source_0 = blocks.file_source(gr.sizeof_gr_complex*1, filepath, True, 0, 0)
        self.blocks_file_source_0.set_begin_tag(pmt.PMT_NIL)
        self.blocks_complex_to_mag_squared_0 = blocks.complex_to_mag_squared(1)
        self.analog_pwr_squelch_xx_0 = analog.pwr_squelch_cc((-10), (1e-4), 0, True)
        self.ainfosec_wideband_detector1_0 = ainfosec.wideband_detector1("tcp://127.0.0.1:5060",rx_freq,fft_size,sample_rate)


        ##################################################
        # Connections
        ##################################################
        self.connect((self.analog_pwr_squelch_xx_0, 0), (self.blocks_stream_to_vector_1, 0))
        self.connect((self.blocks_complex_to_mag_squared_0, 0), (self.blocks_nlog10_ff_0, 0))
        self.connect((self.blocks_file_source_0, 0), (self.blocks_throttle2_0, 0))
        self.connect((self.blocks_nlog10_ff_0, 0), (self.ainfosec_wideband_detector1_0, 0))
        self.connect((self.blocks_stream_to_vector_1, 0), (self.fft_vxx_0, 0))
        self.connect((self.blocks_throttle2_0, 0), (self.analog_pwr_squelch_xx_0, 0))
        self.connect((self.blocks_vector_to_stream_0, 0), (self.blocks_complex_to_mag_squared_0, 0))
        self.connect((self.fft_vxx_0, 0), (self.blocks_vector_to_stream_0, 0))


    def get_threshold(self):
        return self.threshold

    def set_threshold(self, threshold):
        self.threshold = threshold

    def get_sample_rate(self):
        return self.sample_rate

    def set_sample_rate(self, sample_rate):
        self.sample_rate = sample_rate
        self.ainfosec_wideband_detector1_0.set_sample_rate(self.sample_rate)
        self.blocks_throttle2_0.set_sample_rate(self.sample_rate)

    def get_rx_freq(self):
        return self.rx_freq

    def set_rx_freq(self, rx_freq):
        self.rx_freq = rx_freq
        self.ainfosec_wideband_detector1_0.set_rx_freq(self.rx_freq)

    def get_filepath(self):
        return self.filepath

    def set_filepath(self, filepath):
        self.filepath = filepath
        self.blocks_file_source_0.open(self.filepath, True)

    def get_fft_size(self):
        return self.fft_size

    def set_fft_size(self, fft_size):
        self.fft_size = fft_size
        self.ainfosec_wideband_detector1_0.set_fft_size(self.fft_size)




def main(top_block_cls=iq_file, options=None):
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
