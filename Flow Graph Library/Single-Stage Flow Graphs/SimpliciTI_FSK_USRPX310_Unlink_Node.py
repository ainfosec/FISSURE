#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#
# SPDX-License-Identifier: GPL-3.0
#
# GNU Radio Python Flow Graph
# Title: Simpliciti Fsk Usrpx310 Unlink Node
# GNU Radio version: 3.10.1.1

from gnuradio import blocks
import pmt
from gnuradio import digital
from gnuradio import filter
from gnuradio import gr
from gnuradio.filter import firdes
from gnuradio.fft import window
import sys
import signal
from argparse import ArgumentParser
from gnuradio.eng_arg import eng_float, intx
from gnuradio import eng_notation
from gnuradio import uhd
import time




class SimpliciTI_FSK_USRPX310_Unlink_Node(gr.top_block):

    def __init__(self):
        gr.top_block.__init__(self, "Simpliciti Fsk Usrpx310 Unlink Node", catch_exceptions=True)

        ##################################################
        # Variables
        ##################################################
        self.tx_usrp_gain = tx_usrp_gain = 0
        self.tx_usrp_channel = tx_usrp_channel = "A:0"
        self.tx_usrp_antenna = tx_usrp_antenna = "TX/RX"
        self.tx_frequency = tx_frequency = 2425.715e6
        self.sampling_multiple = sampling_multiple = 16
        self.sampling_factor = sampling_factor = 100
        self.sample_rate = sample_rate = 4e6
        self.notes = notes = "Replays an unlink node message supplied from a file."
        self.ip_address = ip_address = "192.168.40.2"
        self.filepath = filepath = "/home/user/FISSURE/Flow Graph Library/Single-Stage Flow Graphs/Attack Files/unlink_bbbbbbbb.bin"
        self.data_rate = data_rate = 2398.9677429

        ##################################################
        # Blocks
        ##################################################
        self.uhd_usrp_sink_0 = uhd.usrp_sink(
            ",".join(("", "addr=" + ip_address)),
            uhd.stream_args(
                cpu_format="fc32",
                args='',
                channels=list(range(0,1)),
            ),
            '',
        )
        self.uhd_usrp_sink_0.set_subdev_spec(tx_usrp_channel, 0)
        self.uhd_usrp_sink_0.set_samp_rate(sample_rate)
        self.uhd_usrp_sink_0.set_time_unknown_pps(uhd.time_spec(0))

        self.uhd_usrp_sink_0.set_center_freq(tx_frequency, 0)
        self.uhd_usrp_sink_0.set_antenna(tx_usrp_antenna, 0)
        self.uhd_usrp_sink_0.set_gain(tx_usrp_gain, 0)
        self.mmse_resampler_xx_0 = filter.mmse_resampler_cc(0, sampling_factor*data_rate*sampling_multiple/sample_rate)
        self.digital_gfsk_mod_0 = digital.gfsk_mod(
            samples_per_symbol=200,
            sensitivity=0.1,
            bt=0.5,
            verbose=False,
            log=False,
            do_unpack=True)
        self.blocks_unpack_k_bits_bb_0 = blocks.unpack_k_bits_bb(8)
        self.blocks_multiply_const_vxx_1 = blocks.multiply_const_cc(0.1)
        self.blocks_multiply_const_vxx_0 = blocks.multiply_const_ff(-1)
        self.blocks_float_to_char_0 = blocks.float_to_char(1, 1)
        self.blocks_file_source_0 = blocks.file_source(gr.sizeof_char*1, filepath, True, 0, 0)
        self.blocks_file_source_0.set_begin_tag(pmt.PMT_NIL)
        self.blocks_char_to_float_0 = blocks.char_to_float(1, 1)


        ##################################################
        # Connections
        ##################################################
        self.connect((self.blocks_char_to_float_0, 0), (self.blocks_multiply_const_vxx_0, 0))
        self.connect((self.blocks_file_source_0, 0), (self.blocks_unpack_k_bits_bb_0, 0))
        self.connect((self.blocks_float_to_char_0, 0), (self.digital_gfsk_mod_0, 0))
        self.connect((self.blocks_multiply_const_vxx_0, 0), (self.blocks_float_to_char_0, 0))
        self.connect((self.blocks_multiply_const_vxx_1, 0), (self.uhd_usrp_sink_0, 0))
        self.connect((self.blocks_unpack_k_bits_bb_0, 0), (self.blocks_char_to_float_0, 0))
        self.connect((self.digital_gfsk_mod_0, 0), (self.mmse_resampler_xx_0, 0))
        self.connect((self.mmse_resampler_xx_0, 0), (self.blocks_multiply_const_vxx_1, 0))


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

    def get_sampling_multiple(self):
        return self.sampling_multiple

    def set_sampling_multiple(self, sampling_multiple):
        self.sampling_multiple = sampling_multiple
        self.mmse_resampler_xx_0.set_resamp_ratio(self.sampling_factor*self.data_rate*self.sampling_multiple/self.sample_rate)

    def get_sampling_factor(self):
        return self.sampling_factor

    def set_sampling_factor(self, sampling_factor):
        self.sampling_factor = sampling_factor
        self.mmse_resampler_xx_0.set_resamp_ratio(self.sampling_factor*self.data_rate*self.sampling_multiple/self.sample_rate)

    def get_sample_rate(self):
        return self.sample_rate

    def set_sample_rate(self, sample_rate):
        self.sample_rate = sample_rate
        self.mmse_resampler_xx_0.set_resamp_ratio(self.sampling_factor*self.data_rate*self.sampling_multiple/self.sample_rate)
        self.uhd_usrp_sink_0.set_samp_rate(self.sample_rate)

    def get_notes(self):
        return self.notes

    def set_notes(self, notes):
        self.notes = notes

    def get_ip_address(self):
        return self.ip_address

    def set_ip_address(self, ip_address):
        self.ip_address = ip_address

    def get_filepath(self):
        return self.filepath

    def set_filepath(self, filepath):
        self.filepath = filepath
        self.blocks_file_source_0.open(self.filepath, True)

    def get_data_rate(self):
        return self.data_rate

    def set_data_rate(self, data_rate):
        self.data_rate = data_rate
        self.mmse_resampler_xx_0.set_resamp_ratio(self.sampling_factor*self.data_rate*self.sampling_multiple/self.sample_rate)




def main(top_block_cls=SimpliciTI_FSK_USRPX310_Unlink_Node, options=None):
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
