#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @file
# @author (C) 2019 by Vasil Velichkov <vvvelichkov@gmail.com>
# @section LICENSE
#
# Gr-gsm is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3, or (at your option)
# any later version.
#
# Gr-gsm is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with gr-gsm; see the file COPYING.  If not, write to
# the Free Software Foundation, Inc., 51 Franklin Street,
# Boston, MA 02110-1301, USA.
#
#

import unittest
import numpy as np
from gnuradio import gr, gr_unittest, blocks
from gnuradio import gsm
import pmt
import qa_gsm_demapper_data as test_data

class qa_gsm_bcch_ccch_demapper (gr_unittest.TestCase):

    def setUp (self):
        self.tb = gr.top_block ()
        self.maxDiff = None

    def tearDown (self):
        self.tb = None

    def test_downlink (self):
        """
           BCCH_CCCH demapper downlink test
        """
        src = gsm.burst_source(test_data.frames, test_data.timeslots, test_data.bursts)
        src.set_arfcn(0); # downlink
        demapper = gsm.gsm_bcch_ccch_demapper(timeslot_nr=0)
        dst = gsm.burst_sink()

        self.tb.msg_connect(src, "out", demapper, "bursts")
        self.tb.msg_connect(demapper, "bursts", dst, "in")
        self.tb.run ()

        b = test_data.bursts
        self.assertEqual([
            b[  2], b[  3], b[  4], b[  5], #BCCH
            b[  6], b[  7], b[  8], b[  9], #CCCH skip 10-11
            b[ 12], b[ 13], b[ 14], b[ 15],
            b[ 16], b[ 17], b[ 18], b[ 19], #skip 20-21
            b[ 22], b[ 23], b[ 24], b[ 25],
            b[ 26], b[ 27], b[ 28], b[ 29], #skip 30-31
            b[ 32], b[ 33], b[ 34], b[ 35],
            b[ 36], b[ 37], b[ 38], b[ 39], #skip 40-41
            b[ 42], b[ 43], b[ 44], b[ 45],
            b[ 46], b[ 47], b[ 48], b[ 49], #skip 50-52
            b[ 53], b[ 54], b[ 55], b[ 56], #BCCH
            b[ 57], b[ 58], b[ 59], b[ 60], #CCCH skip 61-62
            b[ 63], b[ 64], b[ 65], b[ 66],
            b[ 67], b[ 68], b[ 69], b[ 70], #skip 71-72
            b[ 73], b[ 74], b[ 75], b[ 76],
            b[ 77], b[ 78], b[ 79], b[ 80], #skip 81-82
            b[ 83], b[ 84], b[ 85], b[ 86],
            b[ 87], b[ 88], b[ 89], b[ 90], #skip 91-92
            b[ 93], b[ 94], b[ 95], b[ 96],
            b[ 97], b[ 98], b[ 99], b[100], #skip 101-103
            b[104], b[105], b[106], b[107]  #BCCH
            ], list(dst.get_burst_data()))

        self.assertEqual([
              1,   1,   1,   1, #BCCH
              2,   2,   2,   2, #CCCH
              2,   2,   2,   2,
              2,   2,   2,   2,
              2,   2,   2,   2,
              2,   2,   2,   2,
              2,   2,   2,   2,
              2,   2,   2,   2,
              2,   2,   2,   2,
              2,   2,   2,   2,
              1,   1,   1,   1, #BCCH
              2,   2,   2,   2, #CCCH
              2,   2,   2,   2,
              2,   2,   2,   2,
              2,   2,   2,   2,
              2,   2,   2,   2,
              2,   2,   2,   2,
              2,   2,   2,   2,
              2,   2,   2,   2,
              2,   2,   2,   2,
              1,   1,   1,   1, #BCCH
            ], list(dst.get_sub_types()))

        self.assertEqual([
            0, 0, 0, 0, #BCCH
            0, 0, 0, 0, #CCCH 0
            1, 1, 1, 1,
            2, 2, 2, 2,
            3, 3, 3, 3,
            4, 4, 4, 4,
            5, 5, 5, 5,
            6, 6, 6, 6,
            7, 7, 7, 7,
            8, 8, 8, 8, #CCCH 8
            0, 0, 0, 0, #BCCH
            0, 0, 0, 0, #CCCH 0
            1, 1, 1, 1,
            2, 2, 2, 2,
            3, 3, 3, 3,
            4, 4, 4, 4,
            5, 5, 5, 5,
            6, 6, 6, 6,
            7, 7, 7, 7,
            8, 8, 8, 8, #CCCH 8
            0, 0, 0, 0, #BCCH
            ], list(dst.get_sub_slots()))

    def test_uplink (self):
        """
           BCCH_CCCH demapper uplink test
        """
        src = gsm.burst_source(test_data.frames, test_data.timeslots, test_data.bursts)
        src.set_arfcn(0x2240); #uplink flag is 40
        demapper = gsm.gsm_bcch_ccch_demapper(timeslot_nr=0)
        dst = gsm.burst_sink()

        self.tb.msg_connect(src, "out", demapper, "bursts")
        self.tb.msg_connect(demapper, "bursts", dst, "in")
        self.tb.run ()

        b = test_data.bursts
        self.assertEqual(b, list(dst.get_burst_data()))
        self.assertEqual([3]*len(b), list(dst.get_sub_types()))
        self.assertEqual([0]*len(b), list(dst.get_sub_slots()))

if __name__ == '__main__':
    gr_unittest.run(qa_gsm_bcch_ccch_demapper, "qa_gsm_bcch_ccch_demapper.xml")
