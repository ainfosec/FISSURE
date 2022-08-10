#!/usr/bin/env python2
# -*- coding: utf-8 -*-
# @file
# @author (C) 2016 by Piotr Krysik <ptrkrysik@gmail.com>
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
# Title: Clock Offset Corrector Tagged
# Author: Piotr Krysik
# Description: Clock offset corrector with blocks that use tags to switch offsets
# Generated: Wed Jul 20 20:07:11 2016
##################################################

from gnuradio import gr
from gnuradio.filter import firdes
import grgsm
import math


class clock_offset_corrector_tagged(grgsm.hier_block):

    def __init__(self, fc=936.6e6, osr=4, ppm=0, samp_rate_in=1625000.0/6.0*4.0):
        gr.hier_block2.__init__(
            self, "Clock Offset Corrector Tagged",
            gr.io_signature(1, 1, gr.sizeof_gr_complex*1),
            gr.io_signature(1, 1, gr.sizeof_gr_complex*1),
        )
        self.message_port_register_hier_in("ctrl")

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
        self.samp_rate_out = samp_rate_out = osr*gsm_symb_rate

        ##################################################
        # Blocks
        ##################################################
        self.gsm_msg_to_tag_0 = grgsm.msg_to_tag()
        self.gsm_controlled_rotator_cc_0 = grgsm.controlled_rotator_cc(ppm/1.0e6*2*math.pi*fc/samp_rate_out)
        self.gsm_controlled_fractional_resampler_cc_0 = grgsm.controlled_fractional_resampler_cc(0, (1-ppm/1.0e6)*(samp_rate_in/samp_rate_out))

        ##################################################
        # Connections
        ##################################################
        self.msg_connect((self, 'ctrl'), (self.gsm_msg_to_tag_0, 'msg'))    
        self.connect((self.gsm_controlled_fractional_resampler_cc_0, 0), (self.gsm_controlled_rotator_cc_0, 0))    
        self.connect((self.gsm_controlled_rotator_cc_0, 0), (self, 0))    
        self.connect((self.gsm_msg_to_tag_0, 0), (self.gsm_controlled_fractional_resampler_cc_0, 0))    
        self.connect((self, 0), (self.gsm_msg_to_tag_0, 0))    

    def get_fc(self):
        return self.fc

    def set_fc(self, fc):
        self.fc = fc
        self.gsm_controlled_rotator_cc_0.set_phase_inc(self.ppm/1.0e6*2*math.pi*self.fc/self.samp_rate_out)

    def get_osr(self):
        return self.osr

    def set_osr(self, osr):
        self.osr = osr
        self.set_samp_rate_out(self.osr*self.gsm_symb_rate)

    def get_ppm(self):
        return self.ppm

    def set_ppm(self, ppm):
        self.ppm = ppm
        self.gsm_controlled_rotator_cc_0.set_phase_inc(self.ppm/1.0e6*2*math.pi*self.fc/self.samp_rate_out)
        self.gsm_controlled_fractional_resampler_cc_0.set_resamp_ratio((1-self.ppm/1.0e6)*(self.samp_rate_in/self.samp_rate_out))

    def get_samp_rate_in(self):
        return self.samp_rate_in

    def set_samp_rate_in(self, samp_rate_in):
        self.samp_rate_in = samp_rate_in
        self.gsm_controlled_fractional_resampler_cc_0.set_resamp_ratio((1-self.ppm/1.0e6)*(self.samp_rate_in/self.samp_rate_out))

    def get_gsm_symb_rate(self):
        return self.gsm_symb_rate

    def set_gsm_symb_rate(self, gsm_symb_rate):
        self.gsm_symb_rate = gsm_symb_rate
        self.set_samp_rate_out(self.osr*self.gsm_symb_rate)

    def get_samp_rate_out(self):
        return self.samp_rate_out

    def set_samp_rate_out(self, samp_rate_out):
        self.samp_rate_out = samp_rate_out
        self.gsm_controlled_rotator_cc_0.set_phase_inc(self.ppm/1.0e6*2*math.pi*self.fc/self.samp_rate_out)
        self.gsm_controlled_fractional_resampler_cc_0.set_resamp_ratio((1-self.ppm/1.0e6)*(self.samp_rate_in/self.samp_rate_out))
