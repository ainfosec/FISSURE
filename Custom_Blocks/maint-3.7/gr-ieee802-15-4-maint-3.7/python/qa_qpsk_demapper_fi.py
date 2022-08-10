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

class qa_qpsk_demapper_fi (gr_unittest.TestCase):

    def setUp (self):
        self.tb = gr.top_block ()

    def tearDown (self):
        self.tb = None

    def test_001_t (self):
        # set up fg
        data_in = [0, np.pi/2, -np.pi/2, np.pi]
        self.src = blocks.vector_source_f(data_in)
        self.qpsk_demapper = ieee802_15_4.qpsk_demapper_fi()
        self.snk_I = blocks.vector_sink_i(1)
        self.snk_Q = blocks.vector_sink_i(1)
        self.tb.connect(self.src, self.qpsk_demapper)
        self.tb.connect((self.qpsk_demapper,0), self.snk_I)
        self.tb.connect((self.qpsk_demapper,1), self.snk_Q)
        self.tb.run ()
        # check data
        ref_I = [1,-1,1,-1]
        ref_Q = [1,1,-1,-1]  
        print "data in:", data_in   
        print "ref I:", ref_I
        print "data I:", self.snk_I.data()
        print "ref Q:", ref_Q
        print "data Q:", self.snk_Q.data()

        self.assertFloatTuplesAlmostEqual(ref_I, self.snk_I.data())
        self.assertFloatTuplesAlmostEqual(ref_Q, self.snk_Q.data())

if __name__ == '__main__':
    gr_unittest.run(qa_qpsk_demapper_fi)
