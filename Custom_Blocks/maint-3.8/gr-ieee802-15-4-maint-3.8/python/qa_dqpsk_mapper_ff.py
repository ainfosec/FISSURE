#!/usr/bin/env python
# -*- coding: utf-8 -*-
# 
# Copyright 2015 Felix Wunsch, Communications Engineering Lab (CEL) / Karlsruhe Institute of Technology (KIT) <wunsch.felix@googlemail.com>.
# 
# This is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3, or (at your option)
# any later version.
# 
# This software is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this software; see the file COPYING.  If not, write to
# the Free Software Foundation, Inc., 51 Franklin Street,
# Boston, MA 02110-1301, USA.
# 

from gnuradio import gr, gr_unittest
from gnuradio import blocks
import ieee802_15_4_swig as ieee802_15_4
import numpy as np

class qa_dqpsk_mapper_ff (gr_unittest.TestCase):

    def setUp (self):
        self.tb = gr.top_block ()

    def tearDown (self):
        self.tb = None

    def test_001_t (self):
        # set up fg
        pi=np.pi
        data_in = [0, pi/2, pi, -pi/2, pi/2, pi, -pi/2, 0, 0, pi, 0, pi/2]
        self.src = blocks.vector_source_f(data_in)
        self.dqpsk = ieee802_15_4.dqpsk_mapper_ff(framelen=6, forward=True)
        self.snk = blocks.vector_sink_f(1)
        self.tb.connect(self.src, self.dqpsk, self.snk)
        self.tb.run ()
        # check data
        data_out = self.snk.data()
        ref = [0, pi/2, pi, -pi/2, pi/2, -pi/2, -pi/2, 0, 0, pi, pi/2, pi/2]
        ref = [i + pi/4 for i in ref]
        ref = [np.exp(1j*i) for i in ref]
        ref2 = [45, 135, -135, -45, 135, -45, -45, 45, 45, -135, -45, 135]
        ref2 = [np.exp(1j*i/180*pi) for i in ref2]
        data_out = [np.exp(1j*i) for i in data_out]

        self.assertComplexTuplesAlmostEqual(ref2, data_out, 5)

    def test_002_t (self):
        # set up fg
        pi=np.pi
        data_in = [0, pi/2, pi, -pi/2, pi/2, -pi/2, -pi/2, 0, 0, pi, pi/2, pi/2]
        data_in = [i + pi/4 for i in data_in]
        self.src = blocks.vector_source_f(data_in)
        self.dqpsk = ieee802_15_4.dqpsk_mapper_ff(framelen=6, forward=False)
        self.snk = blocks.vector_sink_f(1)
        self.tb.connect(self.src, self.dqpsk, self.snk)
        self.tb.run ()
        # check data
        data_out = self.snk.data()
        data_out = [np.exp(1j*i) for i in data_out]
        ref = [0, pi/2, pi, -pi/2, pi/2, pi, -pi/2, 0, 0, pi, pi, pi/2]
        ref = [np.exp(1j*i) for i in ref]
        # print "in:", data_in
        # print "out:", data_out
        # print "ref:", ref
        self.assertComplexTuplesAlmostEqual(ref, data_out, 5)       

if __name__ == '__main__':
    gr_unittest.run(qa_dqpsk_mapper_ff)
