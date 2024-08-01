# -*- coding: utf-8 -*-

#
# SPDX-License-Identifier: GPL-3.0
#
# GNU Radio Python Flow Graph
# Title: AIS receiver core
# Author: Nick Foster
# GNU Radio version: v3.11.0.0git-55-g8526e6f8

from gnuradio import analog
import math
from gnuradio import blocks
from gnuradio import digital
from gnuradio import filter
from gnuradio import gr
from gnuradio.filter import firdes
from gnuradio.fft import window
import sys
import signal
from gnuradio.ais import square_and_fft_sync_cc
from gnuradio.filter import pfb







class ais_rx_core(gr.hier_block2):
    def __init__(self, bb_sps=4, bt=0.4, loopbw=0.05, samp_rate=200e3, threshold=0.83):
        gr.hier_block2.__init__(
            self, "AIS receiver core",
                gr.io_signature(1, 1, gr.sizeof_gr_complex*1),
                gr.io_signature.makev(5, 5, [gr.sizeof_gr_complex*1, gr.sizeof_gr_complex*1, gr.sizeof_float*1, gr.sizeof_gr_complex*1, gr.sizeof_gr_complex*1]),
        )
        self.message_port_register_hier_out("out")

        ##################################################
        # Parameters
        ##################################################
        self.bb_sps = bb_sps
        self.bt = bt
        self.loopbw = loopbw
        self.samp_rate = samp_rate
        self.threshold = threshold

        ##################################################
        # Variables
        ##################################################
        self.preamble = preamble = [1,1,255,255]*7
        self.data_rate = data_rate = 9600
        self.sps = sps = samp_rate/data_rate
        self.nfilts = nfilts = 64
        self.modulated_preamble = modulated_preamble = digital.modulate_vector_bc(digital.cpmmod_bc(analog.cpm.GAUSSIAN, 0.5, bb_sps, int(1/bt)+2,bt).to_basic_block().to_basic_block(), preamble, [1])
        self.marking_delay = marking_delay = [5,2,6,2,9,4,5][round(bb_sps-2)]
        self.bb_rate = bb_rate = data_rate*bb_sps

        ##################################################
        # Blocks
        ##################################################
        self.pfb_arb_resampler_xxx_0 = pfb.arb_resampler_ccf(
            (bb_sps*data_rate)/samp_rate,
            taps=firdes.low_pass(nfilts, samp_rate*nfilts, data_rate*0.6, data_rate*0.1, window.WIN_HANN),
            flt_size=nfilts)
        self.pfb_arb_resampler_xxx_0.declare_sample_delay(0)
        self.digital_symbol_sync_xx_0 = digital.symbol_sync_cc(
            digital.TED_DANDREA_AND_MENGALI_GEN_MSK,
            bb_sps,
            loopbw,
            1.0,
            0.45,
            0.1,
            1,
            digital.constellation_bpsk().base(),
            digital.IR_MMSE_8TAP,
            128,
            [])
        self.digital_hdlc_deframer_bp_0 = digital.hdlc_deframer_bp(11, 64)
        self.digital_diff_decoder_bb_0 = digital.diff_decoder_bb(2, digital.DIFF_DIFFERENTIAL)
        self.digital_corr_est_cc_0 = digital.corr_est_cc(modulated_preamble, bb_sps, marking_delay, threshold, digital.THRESHOLD_ABSOLUTE)
        self.digital_binary_slicer_fb_0 = digital.binary_slicer_fb()
        self.blocks_not_xx_0 = blocks.not_bb()
        self.blocks_add_const_vxx_0 = blocks.add_const_bb(2)
        self.analog_quadrature_demod_cf_0 = analog.quadrature_demod_cf(math.pi/2)
        self.analog_agc3_xx_0 = analog.agc3_cc(1e-1, 1e-2, 1.0, 1.0, 1)
        self.analog_agc3_xx_0.set_max_gain(65536)


        ##################################################
        # Connections
        ##################################################
        self.msg_connect((self.digital_hdlc_deframer_bp_0, 'out'), (self, 'out'))
        self.connect((self.analog_agc3_xx_0, 0), (self.digital_corr_est_cc_0, 0))
        self.connect((self.analog_agc3_xx_0, 0), (self, 4))
        self.connect((self.analog_quadrature_demod_cf_0, 0), (self.digital_binary_slicer_fb_0, 0))
        self.connect((self.blocks_add_const_vxx_0, 0), (self.digital_hdlc_deframer_bp_0, 0))
        self.connect((self.blocks_not_xx_0, 0), (self.blocks_add_const_vxx_0, 0))
        self.connect((self.digital_binary_slicer_fb_0, 0), (self.digital_diff_decoder_bb_0, 0))
        self.connect((self.digital_corr_est_cc_0, 0), (self.digital_symbol_sync_xx_0, 0))
        self.connect((self.digital_corr_est_cc_0, 0), (self, 0))
        self.connect((self.digital_corr_est_cc_0, 1), (self, 3))
        self.connect((self.digital_diff_decoder_bb_0, 0), (self.blocks_not_xx_0, 0))
        self.connect((self.digital_symbol_sync_xx_0, 0), (self.analog_quadrature_demod_cf_0, 0))
        self.connect((self.digital_symbol_sync_xx_0, 0), (self, 1))
        self.connect((self.digital_symbol_sync_xx_0, 1), (self, 2))
        self.connect((self, 0), (self.pfb_arb_resampler_xxx_0, 0))
        self.connect((self.pfb_arb_resampler_xxx_0, 0), (self.analog_agc3_xx_0, 0))


    def get_bb_sps(self):
        return self.bb_sps

    def set_bb_sps(self, bb_sps):
        self.bb_sps = bb_sps
        self.set_bb_rate(self.data_rate*self.bb_sps)
        self.set_marking_delay([5,2,6,2,9,4,5][round(self.bb_sps-2)])
        self.pfb_arb_resampler_xxx_0.set_rate((self.bb_sps*self.data_rate)/self.samp_rate)

    def get_bt(self):
        return self.bt

    def set_bt(self, bt):
        self.bt = bt

    def get_loopbw(self):
        return self.loopbw

    def set_loopbw(self, loopbw):
        self.loopbw = loopbw
        self.digital_symbol_sync_xx_0.set_loop_bandwidth(self.loopbw)

    def get_samp_rate(self):
        return self.samp_rate

    def set_samp_rate(self, samp_rate):
        self.samp_rate = samp_rate
        self.set_sps(self.samp_rate/self.data_rate)
        self.pfb_arb_resampler_xxx_0.set_taps(firdes.low_pass(self.nfilts, self.samp_rate*self.nfilts, self.data_rate*0.6, self.data_rate*0.1, window.WIN_HANN))
        self.pfb_arb_resampler_xxx_0.set_rate((self.bb_sps*self.data_rate)/self.samp_rate)

    def get_threshold(self):
        return self.threshold

    def set_threshold(self, threshold):
        self.threshold = threshold
        self.digital_corr_est_cc_0.set_threshold(self.threshold)

    def get_preamble(self):
        return self.preamble

    def set_preamble(self, preamble):
        self.preamble = preamble

    def get_data_rate(self):
        return self.data_rate

    def set_data_rate(self, data_rate):
        self.data_rate = data_rate
        self.set_bb_rate(self.data_rate*self.bb_sps)
        self.set_sps(self.samp_rate/self.data_rate)
        self.pfb_arb_resampler_xxx_0.set_taps(firdes.low_pass(self.nfilts, self.samp_rate*self.nfilts, self.data_rate*0.6, self.data_rate*0.1, window.WIN_HANN))
        self.pfb_arb_resampler_xxx_0.set_rate((self.bb_sps*self.data_rate)/self.samp_rate)

    def get_sps(self):
        return self.sps

    def set_sps(self, sps):
        self.sps = sps

    def get_nfilts(self):
        return self.nfilts

    def set_nfilts(self, nfilts):
        self.nfilts = nfilts
        self.pfb_arb_resampler_xxx_0.set_taps(firdes.low_pass(self.nfilts, self.samp_rate*self.nfilts, self.data_rate*0.6, self.data_rate*0.1, window.WIN_HANN))

    def get_modulated_preamble(self):
        return self.modulated_preamble

    def set_modulated_preamble(self, modulated_preamble):
        self.modulated_preamble = modulated_preamble

    def get_marking_delay(self):
        return self.marking_delay

    def set_marking_delay(self, marking_delay):
        self.marking_delay = marking_delay
        self.digital_corr_est_cc_0.set_mark_delay(self.marking_delay)

    def get_bb_rate(self):
        return self.bb_rate

    def set_bb_rate(self, bb_rate):
        self.bb_rate = bb_rate

