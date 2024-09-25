#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#
# SPDX-License-Identifier: GPL-3.0
#
# GNU Radio Python Flow Graph
# Title: Iq Recorder Rspdx
# GNU Radio version: 3.10.7.0

from gnuradio import blocks
from gnuradio import gr
from gnuradio.filter import firdes
from gnuradio.fft import window
import sys
import signal
from argparse import ArgumentParser
from gnuradio.eng_arg import eng_float, intx
from gnuradio import eng_notation
from gnuradio import sdrplay3




class iq_recorder_rspdx(gr.top_block):

    def __init__(self):
        gr.top_block.__init__(self, "Iq Recorder Rspdx", catch_exceptions=True)

        ##################################################
        # Variables
        ##################################################
        self.serial = serial = 0
        self.sample_rate = sample_rate = 2.0
        self.rx_gain = rx_gain = 0
        self.rx_frequency = rx_frequency = 102.5
        self.rx_channel = rx_channel = "A:0"
        self.rx_antenna = rx_antenna = "TX/RX"
        self.filepath = filepath = ""
        self.file_length = file_length = 100000

        ##################################################
        # Blocks
        ##################################################

        self.sdrplay3_rspdx_0 = sdrplay3.rspdx(
            str(serial),
            stream_args=sdrplay3.stream_args(
                output_type='fc32',
                channels_size=1
            ),
        )
        self.sdrplay3_rspdx_0.set_sample_rate((float(sample_rate)*1e6), False)
        self.sdrplay3_rspdx_0.set_center_freq((float(rx_frequency)*1e6), False)
        self.sdrplay3_rspdx_0.set_bandwidth(0)
        self.sdrplay3_rspdx_0.set_antenna('Antenna A')
        self.sdrplay3_rspdx_0.set_gain_mode(False)
        self.sdrplay3_rspdx_0.set_gain(-((59-float(rx_gain))), 'IF', False)
        self.sdrplay3_rspdx_0.set_gain(-(0), 'RF', False)
        self.sdrplay3_rspdx_0.set_freq_corr(0)
        self.sdrplay3_rspdx_0.set_dc_offset_mode(False)
        self.sdrplay3_rspdx_0.set_iq_balance_mode(False)
        self.sdrplay3_rspdx_0.set_agc_setpoint((-30))
        self.sdrplay3_rspdx_0.set_hdr_mode(False)
        self.sdrplay3_rspdx_0.set_rf_notch_filter(False)
        self.sdrplay3_rspdx_0.set_dab_notch_filter(False)
        self.sdrplay3_rspdx_0.set_biasT(False)
        self.sdrplay3_rspdx_0.set_debug_mode(False)
        self.sdrplay3_rspdx_0.set_sample_sequence_gaps_check(False)
        self.sdrplay3_rspdx_0.set_show_gain_changes(False)
        self.blocks_skiphead_0 = blocks.skiphead(gr.sizeof_gr_complex*1, 200000)
        self.blocks_head_0 = blocks.head(gr.sizeof_gr_complex*1, file_length)
        self.blocks_file_sink_0 = blocks.file_sink(gr.sizeof_gr_complex*1, filepath, False)
        self.blocks_file_sink_0.set_unbuffered(False)


        ##################################################
        # Connections
        ##################################################
        self.connect((self.blocks_head_0, 0), (self.blocks_file_sink_0, 0))
        self.connect((self.blocks_skiphead_0, 0), (self.blocks_head_0, 0))
        self.connect((self.sdrplay3_rspdx_0, 0), (self.blocks_skiphead_0, 0))


    def get_serial(self):
        return self.serial

    def set_serial(self, serial):
        self.serial = serial

    def get_sample_rate(self):
        return self.sample_rate

    def set_sample_rate(self, sample_rate):
        self.sample_rate = sample_rate
        self.sdrplay3_rspdx_0.set_sample_rate((float(self.sample_rate)*1e6), False)

    def get_rx_gain(self):
        return self.rx_gain

    def set_rx_gain(self, rx_gain):
        self.rx_gain = rx_gain
        self.sdrplay3_rspdx_0.set_gain(-((59-float(self.rx_gain))), 'IF', False)

    def get_rx_frequency(self):
        return self.rx_frequency

    def set_rx_frequency(self, rx_frequency):
        self.rx_frequency = rx_frequency
        self.sdrplay3_rspdx_0.set_center_freq((float(self.rx_frequency)*1e6), False)

    def get_rx_channel(self):
        return self.rx_channel

    def set_rx_channel(self, rx_channel):
        self.rx_channel = rx_channel

    def get_rx_antenna(self):
        return self.rx_antenna

    def set_rx_antenna(self, rx_antenna):
        self.rx_antenna = rx_antenna

    def get_filepath(self):
        return self.filepath

    def set_filepath(self, filepath):
        self.filepath = filepath
        self.blocks_file_sink_0.open(self.filepath)

    def get_file_length(self):
        return self.file_length

    def set_file_length(self, file_length):
        self.file_length = file_length
        self.blocks_head_0.set_length(self.file_length)




def main(top_block_cls=iq_recorder_rspdx, options=None):
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
