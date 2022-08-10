#!/usr/bin/env python2
# -*- coding: utf-8 -*-
# @file
# @author (C) 2014 by Piotr Krysik <ptrkrysik@gmail.com>
# @section LICENSE
#
# Gr-gsm is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3, or (at your option)
# any later version.
#
# Gr-gsm is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with gr-gsm; see the file COPYING.  If not, write to
# the Free Software Foundation, Inc., 51 Franklin Street,
# Boston, MA 02110-1301, USA.
#
##################################################
# GNU Radio Python Flow Graph
# Title: GSM input adaptor
# Author: Piotr Krysik
# Description: Adaptor of input stream for the GSM receiver. Contains frequency ofset corrector doing also resampling to integer multiplies of GSM sample rate and LP filter filtering GSM channel.
# Generated: Sun Jul 17 17:36:46 2016
##################################################

from gnuradio import filter
from gnuradio import gr
from gnuradio.filter import firdes
import grgsm


class gsm_input(grgsm.hier_block):

    def __init__(self, fc=940e6, osr=4, ppm=0, samp_rate_in=1e6):
        gr.hier_block2.__init__(
            self, "GSM input adaptor",
            gr.io_signature(1, 1, gr.sizeof_gr_complex*1),
            gr.io_signature(1, 1, gr.sizeof_gr_complex*1),
        )
        self.message_port_register_hier_in("ctrl_in")

        ##################################################
        # Parameters
        ##################################################
        self.fc = fc
        self.osr = osr
        self.ppm = ppm
        self.samp_rate_in = samp_rate_in

        ##################################################
        # Variables
        ##################################################
        self.gsm_symb_rate = gsm_symb_rate = 1625000.0/6.0
        self.samp_rate_out = samp_rate_out = gsm_symb_rate*osr

        ##################################################
        # Blocks
        ##################################################
        self.low_pass_filter_0_0 = filter.fir_filter_ccf(1, firdes.low_pass(
        	1, samp_rate_out, 125e3, 5e3, firdes.WIN_HAMMING, 6.76))
        self.gsm_clock_offset_corrector_tagged_0 = grgsm.clock_offset_corrector_tagged(
            fc=fc,
            samp_rate_in=samp_rate_in,
            ppm=ppm,
            osr=osr,
        )

        ##################################################
        # Connections
        ##################################################
        self.msg_connect((self, 'ctrl_in'), (self.gsm_clock_offset_corrector_tagged_0, 'ctrl'))    
        self.connect((self.gsm_clock_offset_corrector_tagged_0, 0), (self.low_pass_filter_0_0, 0))    
        self.connect((self.low_pass_filter_0_0, 0), (self, 0))    
        self.connect((self, 0), (self.gsm_clock_offset_corrector_tagged_0, 0))    

    def get_fc(self):
        return self.fc

    def set_fc(self, fc):
        self.fc = fc
        self.gsm_clock_offset_corrector_tagged_0.set_fc(self.fc)

    def get_osr(self):
        return self.osr

    def set_osr(self, osr):
        self.osr = osr
        self.set_samp_rate_out(self.gsm_symb_rate*self.osr)
        self.gsm_clock_offset_corrector_tagged_0.set_osr(self.osr)

    def get_ppm(self):
        return self.ppm

    def set_ppm(self, ppm):
        self.ppm = ppm
        self.gsm_clock_offset_corrector_tagged_0.set_ppm(self.ppm)

    def get_samp_rate_in(self):
        return self.samp_rate_in

    def set_samp_rate_in(self, samp_rate_in):
        self.samp_rate_in = samp_rate_in
        self.gsm_clock_offset_corrector_tagged_0.set_samp_rate_in(self.samp_rate_in)

    def get_gsm_symb_rate(self):
        return self.gsm_symb_rate

    def set_gsm_symb_rate(self, gsm_symb_rate):
        self.gsm_symb_rate = gsm_symb_rate
        self.set_samp_rate_out(self.gsm_symb_rate*self.osr)

    def get_samp_rate_out(self):
        return self.samp_rate_out

    def set_samp_rate_out(self, samp_rate_out):
        self.samp_rate_out = samp_rate_out
        self.low_pass_filter_0_0.set_taps(firdes.low_pass(1, self.samp_rate_out, 125e3, 5e3, firdes.WIN_HAMMING, 6.76))
