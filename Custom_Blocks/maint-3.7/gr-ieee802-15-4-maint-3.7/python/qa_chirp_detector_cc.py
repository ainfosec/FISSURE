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
import ieee802_15_4 as ieee802_15_4_installed # css_phy is not found in the just compiled swig version...
import ieee802_15_4_swig as ieee802_15_4
import numpy as np

class qa_multiuser_chirp_detector_cc (gr_unittest.TestCase):

    def setUp (self):
    	print "NOTE: THIS TEST USES THE INSTALLED VERSION OF THE LIBRARY ieee802_15_4!"
        self.tb = gr.top_block ()
        self.p = ieee802_15_4_installed.css_phy()

    def tearDown (self):
        self.tb = None

    def test_001_t (self): # two chirp sequences with alternating time gaps
        # set up fg
        print "test_001_t"
        data_in = np.concatenate((self.p.chirp_seq, self.p.time_gap_1, self.p.chirp_seq, self.p.time_gap_2))
        src = blocks.vector_source_c(data_in)
        det = ieee802_15_4.multiuser_chirp_detector_cc(self.p.chirp_seq, len(self.p.time_gap_1), len(self.p.time_gap_2), 38, 0.99)
        snk = blocks.vector_sink_c()
        self.tb.connect(src, det, snk)
        self.tb.run ()
        # check data
        ref = np.ones((8,))
        data_out = snk.data()
        self.assertComplexTuplesAlmostEqual(ref, data_out, 5)

    def test_002_t (self): # 4 chirp sequences with zeros in the middle
        # set up fg
        print "test_002_t"
        data = np.concatenate((self.p.chirp_seq, self.p.time_gap_1, self.p.chirp_seq, self.p.time_gap_2))
        zeros = np.zeros((10,))
        data_in = np.concatenate((data,zeros,data))
        src = blocks.vector_source_c(data_in)
        det = ieee802_15_4.multiuser_chirp_detector_cc(self.p.chirp_seq, len(self.p.time_gap_1), len(self.p.time_gap_2), 38, 0.99)
        snk = blocks.vector_sink_c()
        self.tb.connect(src, det, snk)
        self.tb.run ()
        # check data
        ref = np.ones((16,))
        data_out = snk.data()
        self.assertComplexTuplesAlmostEqual(ref, data_out, 5)

    def test_003_t (self): # 4 chirp sequences in reversed order (late-entry)
        # set up fg
        print "test_003_t"
        data1 = np.concatenate((self.p.chirp_seq, self.p.time_gap_1))
        data2 = np.concatenate((self.p.chirp_seq, self.p.time_gap_2))
        zeros100 = np.zeros((100,))
        data_in = np.concatenate((data2, data1, data2, data1, zeros100))
        src = blocks.vector_source_c(data_in)
        det = ieee802_15_4.multiuser_chirp_detector_cc(self.p.chirp_seq, len(self.p.time_gap_1), len(self.p.time_gap_2), 38, 0.99)
        snk = blocks.vector_sink_c()
        self.tb.connect(src, det, snk)
        self.tb.run ()
        # check data
        ref = np.ones((16,))
        data_out = snk.data()
        self.assertComplexTuplesAlmostEqual(ref, data_out, 5)


if __name__ == '__main__':
    gr_unittest.run(qa_multiuser_chirp_detector_cc)
