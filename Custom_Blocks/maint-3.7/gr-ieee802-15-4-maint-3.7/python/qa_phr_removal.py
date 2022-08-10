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
import pmt
import time

class qa_phr_removal (gr_unittest.TestCase):

    def setUp (self):
        self.tb = gr.top_block ()

    def tearDown (self):
        self.tb = None

    def test_001_t (self):
        # set up fg
        phr = np.zeros((12,),dtype=int)
        data1 = np.array([7, 128], dtype=int)
        data2 = np.array([8, 129], dtype=int)
        data1_unp = np.unpackbits(np.array(data1,dtype=np.uint8))
        data2_unp = np.unpackbits(np.array(data2,dtype=np.uint8))
        data_in = np.concatenate((phr, data1_unp, phr, data2_unp))
        # blob = pmt.make_blob(data_in, len(data_in))
        self.src = blocks.vector_source_b(data_in, False, 1, [])
        self.s2ts = blocks.stream_to_tagged_stream(gr.sizeof_char, 1, 2*8+len(phr), "packet_len")
        self.ts2pdu = blocks.tagged_stream_to_pdu(blocks.byte_t, "packet_len")
        self.phr_removal = ieee802_15_4.phr_removal(phr)
        self.msg_sink = blocks.message_debug()
        # self.pdu2ts = blocks.pdu_to_tagged_stream(blocks.byte_t, "packet_len")
        # self.snk = blocks.vector_sink_b(1)
        self.tb.connect(self.src, self.s2ts, self.ts2pdu)
        self.tb.msg_connect(self.ts2pdu, "pdus", self.phr_removal, "in")
        self.tb.msg_connect(self.phr_removal, "out", self.msg_sink, "store")
        # self.tb.msg_connect(self.phr_removal, "out", self.pdu2ts, "pdus")
        # self.tb.connect(self.pdu2ts, self.snk)
        self.tb.start()
        time.sleep(0.5)
        self.tb.stop()
        num_msgs = self.msg_sink.num_messages()
        self.assertTrue(num_msgs == 2)
        data_out = []
        for i in range(num_msgs):
            tmp = pmt.to_python(self.msg_sink.get_message(i))
            data_out = np.concatenate((data_out, tmp[1]))
        # check data
        # data_out = self.snk.data()
        # print "input:"
        # for i in data:
        # 	print i
        # print "output:"
        # for i in data_out:
        # 	print data_out
        ref = np.concatenate((data1,data2))
        print "ref:", ref
        # print "data_out:", data_out
        self.assertFloatTuplesAlmostEqual(data_out, ref)

if __name__ == '__main__':
    gr_unittest.run(qa_phr_removal)
