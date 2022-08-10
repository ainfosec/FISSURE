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
import numpy as np

class qa_preamble_sfd_prefixer_ii (gr_unittest.TestCase):

    def setUp (self):
        self.tb = gr.top_block ()

    def tearDown (self):
        self.tb = None

    def test_001_t (self):
        # set up fg
        cfg = phy()
        data1 = range(cfg.nsym_frame-len(cfg.preamble)-len(cfg.SFD))
        data2 = range(cfg.nsym_frame-len(cfg.preamble)-len(cfg.SFD), 2*(cfg.nsym_frame-len(cfg.preamble)-len(cfg.SFD)))
        data_in = np.concatenate((data1, data2))
        self.src = blocks.vector_source_i(data_in)
        self.prefixer = ieee802_15_4.preamble_sfd_prefixer_ii(cfg.preamble, cfg.SFD, cfg.nsym_frame)
        self.snk = blocks.vector_sink_i(1)
        self.tb.connect(self.src, self.prefixer, self.snk)
        self.tb.run ()
        # check data
        data_out = self.snk.data()
        ref = np.concatenate((cfg.preamble, cfg.SFD, data1, cfg.preamble, cfg.SFD, data2))
        self.assertFloatTuplesAlmostEqual(data_out, ref)

if __name__ == '__main__':		
	gr_unittest.run(qa_preamble_sfd_prefixer_ii)
