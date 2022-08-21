#!/usr/bin/env python2
# -*- coding: utf-8 -*-
##################################################
# GNU Radio Python Flow Graph
# Title: Mode S Ppm Hackrf From File
# Generated: Sun Aug 21 14:50:37 2022
##################################################


from gnuradio import blocks
from gnuradio import eng_notation
from gnuradio import gr
from gnuradio.eng_option import eng_option
from gnuradio.filter import firdes
from optparse import OptionParser
import ainfosec
import fuzzer
import osmosdr
import time


class Mode_S_PPM_HackRF_From_File(gr.top_block):

    def __init__(self):
        gr.top_block.__init__(self, "Mode S Ppm Hackrf From File")

        ##################################################
        # Variables
        ##################################################
        self.tx_freq = tx_freq = 915e6
        self.transmit_interval = transmit_interval = .1
        self.serial = serial = "0"
        self.samp_rate = samp_rate = 2e6
        self.notes = notes = "Transmits ADSB binary data supplied from a file."
        self.filepath = filepath = "/home/user/FISSURE/Crafted Packets/adsb_airborne_position_odd1.bin"

        ##################################################
        # Blocks
        ##################################################
        self.osmosdr_sink_0 = osmosdr.sink( args="numchan=" + str(1) + " " + "hackrf=" + str(serial) )
        self.osmosdr_sink_0.set_sample_rate(samp_rate)
        self.osmosdr_sink_0.set_center_freq(tx_freq, 0)
        self.osmosdr_sink_0.set_freq_corr(0, 0)
        self.osmosdr_sink_0.set_gain(10, 0)
        self.osmosdr_sink_0.set_if_gain(20, 0)
        self.osmosdr_sink_0.set_bb_gain(20, 0)
        self.osmosdr_sink_0.set_antenna('', 0)
        self.osmosdr_sink_0.set_bandwidth(0, 0)

        self.fuzzer_packet_insert_0 = fuzzer.packet_insert((0, ), int(samp_rate*transmit_interval/8), 0)
        self.blocks_unpack_k_bits_bb_0 = blocks.unpack_k_bits_bb(8)
        self.blocks_null_source_0 = blocks.null_source(gr.sizeof_char*1)
        self.blocks_multiply_const_vxx_0 = blocks.multiply_const_vff((.3, ))
        self.blocks_float_to_complex_0 = blocks.float_to_complex(1)
        self.blocks_char_to_float_0 = blocks.char_to_float(1, 1)
        self.ainfosec_adsb_encode_0 = ainfosec.adsb_encode(filepath)

        ##################################################
        # Connections
        ##################################################
        self.msg_connect((self.ainfosec_adsb_encode_0, 'out'), (self.fuzzer_packet_insert_0, 'packet_in'))
        self.connect((self.blocks_char_to_float_0, 0), (self.blocks_multiply_const_vxx_0, 0))
        self.connect((self.blocks_float_to_complex_0, 0), (self.osmosdr_sink_0, 0))
        self.connect((self.blocks_multiply_const_vxx_0, 0), (self.blocks_float_to_complex_0, 0))
        self.connect((self.blocks_null_source_0, 0), (self.fuzzer_packet_insert_0, 0))
        self.connect((self.blocks_unpack_k_bits_bb_0, 0), (self.blocks_char_to_float_0, 0))
        self.connect((self.fuzzer_packet_insert_0, 0), (self.blocks_unpack_k_bits_bb_0, 0))

    def get_tx_freq(self):
        return self.tx_freq

    def set_tx_freq(self, tx_freq):
        self.tx_freq = tx_freq
        self.osmosdr_sink_0.set_center_freq(self.tx_freq, 0)

    def get_transmit_interval(self):
        return self.transmit_interval

    def set_transmit_interval(self, transmit_interval):
        self.transmit_interval = transmit_interval

    def get_serial(self):
        return self.serial

    def set_serial(self, serial):
        self.serial = serial

    def get_samp_rate(self):
        return self.samp_rate

    def set_samp_rate(self, samp_rate):
        self.samp_rate = samp_rate
        self.osmosdr_sink_0.set_sample_rate(self.samp_rate)

    def get_notes(self):
        return self.notes

    def set_notes(self, notes):
        self.notes = notes

    def get_filepath(self):
        return self.filepath

    def set_filepath(self, filepath):
        self.filepath = filepath


def main(top_block_cls=Mode_S_PPM_HackRF_From_File, options=None):

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
