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
import pmt
import ieee802_15_4_swig as ieee802_15_4
import time
import numpy as np

class qa_access_code_removal_b (gr_unittest.TestCase):

    def setUp (self):
        self.tb = gr.top_block ()

    def tearDown (self):
        self.tb = None

    def test_001_t (self):
        # set up fg
        SHR = np.array([0x00, 0x00, 0x00, 0x00, 0xA7])
        PHR1 = np.array([2])
        PHR2 = np.array([3])
        data1 = np.array([34, 87])
        data2 = np.array([23, 76])
        bytes_in = np.concatenate((SHR, PHR1, data1, SHR, PHR2, data2))
        self.src = blocks.vector_source_b(bytes_in)
        self.deframer = ieee802_15_4.access_code_removal_b(2)
        self.snk = blocks.message_debug()
        self.tb.connect(self.src, self.deframer)
        self.tb.msg_connect(self.deframer, "out", self.snk, "store")
        self.tb.start ()
        time.sleep(.5)
        self.tb.stop()
        # check data
        num_msgs = self.snk.num_messages()
        print(num_msgs)
        self.assertTrue(num_msgs == 2)
        msg1 = self.snk.get_message(0)
        self.assertFloatTuplesAlmostEqual(data1, pmt.to_python(msg1)[1])
        msg2 = self.snk.get_message(1)
        self.assertFloatTuplesAlmostEqual(data2, pmt.to_python(msg2)[1])

    def test_002_t (self):
        # set up fg
        SHR = np.array([0x00, 0x00, 0x00, 0x00, 0xA7])
        PHR1 = np.array([2])
        PHR2 = np.array([3])
        data1 = np.array([34, 87])
        data2 = np.array([23, 76, 45])
        bytes_in = np.concatenate((SHR, PHR1, data1, SHR, PHR2, data2))
        self.src = blocks.vector_source_b(bytes_in)
        self.deframer = ieee802_15_4.access_code_removal_b(-1)
        self.snk = blocks.message_debug()
        self.tb.connect(self.src, self.deframer)
        self.tb.msg_connect(self.deframer, "out", self.snk, "store")
        self.tb.start ()
        time.sleep(.5)
        self.tb.stop()
        # check data
        num_msgs = self.snk.num_messages()
        print(num_msgs)
        self.assertTrue(num_msgs == 2)
        msg1 = self.snk.get_message(0)
        self.assertFloatTuplesAlmostEqual(data1, pmt.to_python(msg1)[1])
        msg2 = self.snk.get_message(1)
        self.assertFloatTuplesAlmostEqual(data2, pmt.to_python(msg2)[1])

if __name__ == '__main__':
    gr_unittest.run(qa_access_code_removal_b)
