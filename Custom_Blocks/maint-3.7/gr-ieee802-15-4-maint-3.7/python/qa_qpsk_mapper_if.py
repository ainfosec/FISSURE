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
import numpy as np
import ieee802_15_4_swig as ieee802_15_4

class qa_qpsk_mapper_if (gr_unittest.TestCase):

    def setUp (self):
        self.tb = gr.top_block ()

    def tearDown (self):
        self.tb = None

    def test_001_t (self):
        # set up fg
        self.src_I = blocks.vector_source_i([1,-1,1,-1])
        self.src_Q = blocks.vector_source_i([1,1,-1,-1])
        self.qpsk_mapper = ieee802_15_4.qpsk_mapper_if()
        self.snk = blocks.vector_sink_f(1)
        self.tb.connect(self.src_I, (self.qpsk_mapper,0))
        self.tb.connect(self.src_Q, (self.qpsk_mapper,1))
        self.tb.connect(self.qpsk_mapper, self.snk)
        self.tb.run ()
        # check data
        ref = [0, np.pi/2, -np.pi/2, np.pi]
        data = self.snk.data()
        self.assertFloatTuplesAlmostEqual(data, ref, 5)

if __name__ == '__main__':
    gr_unittest.run(qa_qpsk_mapper_if)
