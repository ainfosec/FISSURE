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
from css_phy import physical_layer as phy

class qa_interleaver_ii (gr_unittest.TestCase):

    def setUp (self):
        self.tb = gr.top_block ()

    def tearDown (self):
        self.tb = None

    def test_001_t (self):
        # set up fg
        cfg = phy(slow_rate=False)
        data_in = range(541) # some random prime number
        self.src = blocks.vector_source_i(data_in)
        self.intlv = ieee802_15_4.interleaver_ii(intlv_seq=(),forward=True)
        self.snk = blocks.vector_sink_i(1)
        self.tb.connect(self.src, self.intlv, self.snk)
        self.tb.run ()

        # check data
        data_out = self.snk.data()
        self.assertFloatTuplesAlmostEqual(data_in, data_out)

    def test_002_t (self):
        # set up fg
        cfg = phy(slow_rate=False)
        data_in = range(541) # some random prime number
        self.src = blocks.vector_source_i(data_in)
        self.intlv = ieee802_15_4.interleaver_ii(intlv_seq=(),forward=False)
        self.snk = blocks.vector_sink_i(1)
        self.tb.connect(self.src, self.intlv, self.snk)
        self.tb.run ()

        # check data
        data_out = self.snk.data()
        self.assertFloatTuplesAlmostEqual(data_in, data_out)       

    def test_003_t (self):
        # set up fg
        cfg = phy(slow_rate=True)
        data_in = range(3*len(cfg.intlv_seq)) # some random prime number
        self.src = blocks.vector_source_i(data_in)
        self.intlv = ieee802_15_4.interleaver_ii(intlv_seq=cfg.intlv_seq,forward=True)
        self.snk = blocks.vector_sink_i(1)
        self.tb.connect(self.src, self.intlv, self.snk)
        self.tb.run ()

        # check data
        data_out = self.snk.data()
        ref = []
        for n in range(3):
			for i in range(len(cfg.intlv_seq)):
				ref.append(data_in[n*len(cfg.intlv_seq)+cfg.intlv_seq[i]])
        self.assertFloatTuplesAlmostEqual(ref, data_out)

    def test_004_t (self):
        # set up fg
        cfg = phy(slow_rate=True)
        data_in = range(3*len(cfg.intlv_seq)) # some random prime number
        self.src = blocks.vector_source_i(data_in)
        self.intlv = ieee802_15_4.interleaver_ii(intlv_seq=cfg.intlv_seq,forward=True)
        self.deintlv = ieee802_15_4.interleaver_ii(intlv_seq=cfg.intlv_seq,forward=False)
        self.snk = blocks.vector_sink_i(1)
        self.tb.connect(self.src, self.intlv, self.deintlv, self.snk)
        self.tb.run ()

        # check data
        data_out = self.snk.data()
        self.assertFloatTuplesAlmostEqual(data_in, data_out)         

if __name__ == '__main__':
    gr_unittest.run(qa_interleaver_ii, "qa_interleaver_ii.xml")
