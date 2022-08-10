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
from css_phy import physical_layer as phy

class qa_codeword_demapper_ib (gr_unittest.TestCase):

    def setUp (self):
        self.tb = gr.top_block ()

    def tearDown (self):
        self.tb = None

    def test_001_t (self):
        # set up fg
        cfg = phy()
        cw = cfg.codewords
        data_in = np.concatenate((cw[0], cw[1], cw[2], cw[3], cw[4], cw[5], cw[6], cw[7]))
        self.src = blocks.vector_source_i(data_in)
        self.enc = ieee802_15_4.codeword_demapper_ib(bits_per_cw=cfg.bits_per_symbol,codewords=cw)
        self.snk = blocks.vector_sink_b(1)
        self.tb.connect(self.src, self.enc, self.snk)
        self.tb.run()
        # check data
        bits = (0,0,0, 0,0,1, 0,1,0, 0,1,1, 1,0,0, 1,0,1, 1,1,0, 1,1,1)
        data_out = self.snk.data()
        print "data_out:", data_out
        print "ref:", bits
        self.assertFloatTuplesAlmostEqual(data_out, bits)

if __name__ == '__main__':
    gr_unittest.run(qa_codeword_demapper_ib, "qa_codeword_demapper_ib.xml")
