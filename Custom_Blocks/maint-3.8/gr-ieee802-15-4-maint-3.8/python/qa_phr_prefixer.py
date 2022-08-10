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
import time
import ieee802_15_4_swig as ieee802_15_4

class qa_phr_prefixer (gr_unittest.TestCase):

    def setUp (self):
        self.tb = gr.top_block ()

    def tearDown (self):
        self.tb = None

    def test_001_t (self):
        # set up fg
        phr = np.random.randint(0,2,size=(12,))
        data = np.array(np.random.randint(0,256, size=(6*3,)))
        data_bin = np.unpackbits(np.array(data,dtype=np.uint8))
        self.src = blocks.vector_source_b(data, False, 1, [])
        self.s2ts = blocks.stream_to_tagged_stream(gr.sizeof_char, 1, 6, "packet_len")
        self.ts2pdu = blocks.tagged_stream_to_pdu(blocks.byte_t, "packet_len")
        self.pref = ieee802_15_4.phr_prefixer(phr)
        self.pdu2ts = blocks.pdu_to_tagged_stream(blocks.byte_t, "packet_len")
        self.snk = blocks.vector_sink_b(1)
        self.tb.connect(self.src, self.s2ts, self.ts2pdu)
        self.tb.msg_connect(self.ts2pdu, "pdus", self.pref, "in")
        self.tb.msg_connect(self.pref, "out", self.pdu2ts, "pdus")
        self.tb.connect(self.pdu2ts, self.snk)
        self.tb.start()
        time.sleep(1)
        self.tb.stop()
        # check data
        data_out = self.snk.data()
        # print "input:"
        # for i in data:
        # 	print i
        # print "output:"
        # for i in data_out:
        # 	print data_out
        expected_output = np.concatenate((phr,data_bin[0:6*8], phr, data_bin[6*8:12*8], phr, data_bin[12*8:18*8]))
        self.assertFloatTuplesAlmostEqual(data_out, expected_output)

if __name__ == '__main__':
    gr_unittest.run(qa_phr_prefixer)
