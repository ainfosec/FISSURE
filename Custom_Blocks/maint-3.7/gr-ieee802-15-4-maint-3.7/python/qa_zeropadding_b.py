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
import time
import ieee802_15_4_swig as ieee802_15_4

class qa_zeropadding_b (gr_unittest.TestCase):

    def setUp (self):
        self.tb = gr.top_block ()

    def tearDown (self):
        self.tb = None

    def test_001_t (self):
        # set up fg
        self.src = blocks.vector_source_b(range(12), False, 1, [])
        self.s2ts = blocks.stream_to_tagged_stream(gr.sizeof_char, 1, 4, "packet_len")
        self.ts2pdu = blocks.tagged_stream_to_pdu(blocks.byte_t, "packet_len")
        self.zeropadding = ieee802_15_4.zeropadding_b(2)
        self.snk = blocks.vector_sink_b(1)
        self.tb.connect(self.src, self.s2ts, self.ts2pdu)
        self.tb.msg_connect(self.ts2pdu, "pdus", self.zeropadding, "in")
        self.tb.connect(self.zeropadding, self.snk)
        self.tb.start()
        time.sleep(1)
        self.tb.stop()
        # check data
        data = self.snk.data()
        self.assertFloatTuplesAlmostEqual(data, (0,1,2,3,0,0,4,5,6,7,0,0,8,9,10,11,0,0))


if __name__ == '__main__':
    gr_unittest.run(qa_zeropadding_b, "qa_zeropadding_b.xml")
