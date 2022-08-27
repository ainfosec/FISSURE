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

class qa_chips_to_bits_fb (gr_unittest.TestCase):

    def setUp (self):
        self.tb = gr.top_block ()

    def tearDown (self):
        self.tb = None

    def test_001_t (self):
        # set up fg
        chips_in = (3,2,-2,-3, 4,-3,3,-4, -2,2,-1,1.5, -1.5,-1.2,2,1)
        self.src = blocks.vector_source_f(chips_in)
        self.c2b = ieee802_15_4.chips_to_bits_fb([[1,1,0,0],[1,0,1,0],[0,1,0,1],[0,0,1,1]])
        self.snk = blocks.vector_sink_b(1)
        self.tb.connect(self.src, self.c2b, self.snk)
        self.tb.run ()
        # check data
        bits_out = self.snk.data()
        ref = (0,0,1,0,0,1,1,1)
        self.assertFloatTuplesAlmostEqual(bits_out, ref)

if __name__ == '__main__':
    gr_unittest.run(qa_chips_to_bits_fb, "qa_chips_to_bits_fb.xml")
