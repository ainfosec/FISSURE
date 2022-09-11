#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#
# SPDX-License-Identifier: GPL-3.0
#
# GNU Radio Python Flow Graph
# Title: Mode S Ppm Limesdr From File
# GNU Radio version: 3.10.1.1

from gnuradio import blocks
from gnuradio import gr
from gnuradio.filter import firdes
from gnuradio.fft import window
import sys
import signal
from argparse import ArgumentParser
from gnuradio.eng_arg import eng_float, intx
from gnuradio import eng_notation
import fuzzer
import gnuradio.ainfosec as ainfosec
import gnuradio.limesdr as limesdr




class Mode_S_PPM_LimeSDR_From_File(gr.top_block):

    def __init__(self):
        gr.top_block.__init__(self, "Mode S Ppm Limesdr From File", catch_exceptions=True)

        ##################################################
        # Variables
        ##################################################
        self.tx_gain = tx_gain = 60
        self.tx_frequency = tx_frequency = 915e6
        self.tx_channel = tx_channel = 0
        self.transmit_interval = transmit_interval = .1
        self.sample_rate = sample_rate = 2e6
        self.notes = notes = "Transmits ADSB binary data supplied from a file."
        self.filepath = filepath = "/home/user/FISSURE/Crafted Packets/adsb_airborne_position_odd1.bin"

        ##################################################
        # Blocks
        ##################################################
        self.limesdr_sink_0 = limesdr.sink('', int(tx_channel), '', '')

        self.fuzzer_packet_insert_0 = fuzzer.packet_insert([0],int(sample_rate*transmit_interval/8),0)
        self.blocks_unpack_k_bits_bb_0 = blocks.unpack_k_bits_bb(8)
        self.blocks_null_source_0 = blocks.null_source(gr.sizeof_char*1)
        self.blocks_multiply_const_vxx_0 = blocks.multiply_const_ff(.3)
        self.blocks_float_to_complex_0 = blocks.float_to_complex(1)
        self.blocks_char_to_float_0 = blocks.char_to_float(1, 1)
        self.ainfosec_adsb_encode_0 = ainfosec.adsb_encode(filepath)


        ##################################################
        # Connections
        ##################################################
        self.msg_connect((self.ainfosec_adsb_encode_0, 'out'), (self.fuzzer_packet_insert_0, 'packet_in'))
        self.connect((self.blocks_char_to_float_0, 0), (self.blocks_multiply_const_vxx_0, 0))
        self.connect((self.blocks_float_to_complex_0, 0), (self.limesdr_sink_0, 0))
        self.connect((self.blocks_multiply_const_vxx_0, 0), (self.blocks_float_to_complex_0, 0))
        self.connect((self.blocks_null_source_0, 0), (self.fuzzer_packet_insert_0, 0))
        self.connect((self.blocks_unpack_k_bits_bb_0, 0), (self.blocks_char_to_float_0, 0))
        self.connect((self.fuzzer_packet_insert_0, 0), (self.blocks_unpack_k_bits_bb_0, 0))


    def get_tx_gain(self):
        return self.tx_gain

    def set_tx_gain(self, tx_gain):
        self.tx_gain = tx_gain
        self.limesdr_sink_0.set_gain(int(self.tx_gain),0)
        self.limesdr_sink_0.set_gain(int(self.tx_gain),1)

    def get_tx_frequency(self):
        return self.tx_frequency

    def set_tx_frequency(self, tx_frequency):
        self.tx_frequency = tx_frequency
        self.limesdr_sink_0.set_center_freq(self.tx_frequency, 0)

    def get_tx_channel(self):
        return self.tx_channel

    def set_tx_channel(self, tx_channel):
        self.tx_channel = tx_channel

    def get_transmit_interval(self):
        return self.transmit_interval

    def set_transmit_interval(self, transmit_interval):
        self.transmit_interval = transmit_interval

    def get_sample_rate(self):
        return self.sample_rate

    def set_sample_rate(self, sample_rate):
        self.sample_rate = sample_rate

    def get_notes(self):
        return self.notes

    def set_notes(self, notes):
        self.notes = notes

    def get_filepath(self):
        return self.filepath

    def set_filepath(self, filepath):
        self.filepath = filepath




def main(top_block_cls=Mode_S_PPM_LimeSDR_From_File, options=None):
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
