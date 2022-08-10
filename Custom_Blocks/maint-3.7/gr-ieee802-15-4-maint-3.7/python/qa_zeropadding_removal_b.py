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
import time
import numpy as np
import pmt

class qa_zeropadding_removal_b (gr_unittest.TestCase):

    def setUp (self):
        self.tb = gr.top_block ()

    def tearDown (self):
        self.tb = None

    def test_001_t (self):
        # set up fg
        data_in = (0,1,2,3,0,0,4,5,6,7,0,0,8,9,10,11,0,0)
        self.src = blocks.vector_source_b(data_in)
        self.zeropadding_removal = ieee802_15_4.zeropadding_removal_b(phr_payload_len=4, nzeros=2)
        self.msgsink = blocks.message_debug()

        self.tb.connect(self.src, self.zeropadding_removal)
        self.tb.msg_connect(self.zeropadding_removal, "out", self.msgsink, "store")
        self.tb.start()
        time.sleep(2)
        self.tb.stop()
        # check data
        num_messages = self.msgsink.num_messages()
        self.assertTrue(num_messages == 3)
        data_out = []
        for i in range(num_messages):
            tmp = pmt.to_python(self.msgsink.get_message(i))
            data_out = np.concatenate((data_out,tmp[1]))

        ref = range(12)
        print "num messages:", self.msgsink.num_messages()
        print "ref:", ref
        print "data_out:", data_out
        self.assertFloatTuplesAlmostEqual(data_out, ref)


if __name__ == '__main__':
    gr_unittest.run(qa_zeropadding_removal_b)
