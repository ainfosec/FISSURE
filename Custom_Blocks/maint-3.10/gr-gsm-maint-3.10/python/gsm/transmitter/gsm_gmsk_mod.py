# -*- coding: utf-8 -*-
##################################################
# GNU Radio Python Flow Graph
# Title: GMSK Modulator for GSM
# Author: Piotr Krysik
# Description: GMSK Modulator for GSM
# Generated: Wed Sep 20 21:12:04 2017
##################################################

from gnuradio import blocks
from gnuradio import digital
from gnuradio import gr
from gnuradio.analog import cpm
from gnuradio.filter import firdes
from gnuradio import gsm

class gsm_gmsk_mod(gr.hier_block2):

    def __init__(self, BT=4, pulse_duration=4, sps=4):
        gr.hier_block2.__init__(
            self, "GMSK Modulator for GSM",
            gr.io_signature(1, 1, gr.sizeof_char*1),
            gr.io_signature(1, 1, gr.sizeof_gr_complex*1),
        )

        ##################################################
        # Parameters
        ##################################################
        self.BT = BT
        self.pulse_duration = pulse_duration
        self.sps = sps

        ##################################################
        # Blocks
        ##################################################
        self.digital_gmskmod_bc_0 = digital.gmskmod_bc(sps, pulse_duration, BT)
        self.digital_diff_decoder_bb_0 = digital.diff_decoder_bb(2)
        self.digital_chunks_to_symbols_xx_0 = digital.chunks_to_symbols_bf(([1,-1]), 1)
        self.blocks_tagged_stream_multiply_length_0 = blocks.tagged_stream_multiply_length(gr.sizeof_gr_complex*1, "packet_len", sps)
        self.blocks_float_to_char_0 = blocks.float_to_char(1, 1)

        ##################################################
        # Connections
        ##################################################
        self.connect((self.blocks_float_to_char_0, 0), (self.digital_gmskmod_bc_0, 0))    
        self.connect((self.blocks_tagged_stream_multiply_length_0, 0), (self, 0))    
        self.connect((self.digital_chunks_to_symbols_xx_0, 0), (self.blocks_float_to_char_0, 0))    
        self.connect((self.digital_diff_decoder_bb_0, 0), (self.digital_chunks_to_symbols_xx_0, 0))    
        self.connect((self.digital_gmskmod_bc_0, 0), (self.blocks_tagged_stream_multiply_length_0, 0))    
        self.connect((self, 0), (self.digital_diff_decoder_bb_0, 0))    

    def get_BT(self):
        return self.BT

    def set_BT(self, BT):
        self.BT = BT

    def get_pulse_duration(self):
        return self.pulse_duration

    def set_pulse_duration(self, pulse_duration):
        self.pulse_duration = pulse_duration

    def get_sps(self):
        return self.sps

    def set_sps(self, sps):
        self.sps = sps
        self.blocks_tagged_stream_multiply_length_0.set_scalar(self.sps)
