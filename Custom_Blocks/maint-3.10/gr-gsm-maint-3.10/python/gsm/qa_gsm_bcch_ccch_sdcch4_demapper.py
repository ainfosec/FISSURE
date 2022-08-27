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

class qa_bcch_ccch_sdcch4_demapper (gr_unittest.TestCase):

    def setUp (self):
        self.tb = gr.top_block ()
        self.maxDiff = None

    def tearDown (self):
        self.tb = None

    def test_downlink (self):
        """
           BCCH_CCCH_SDCCH4 demapper downlink test
        """
        src = gsm.burst_source(test_data.frames, test_data.timeslots, test_data.bursts)
        src.set_arfcn(0); # downlink
        demapper = gsm.gsm_bcch_ccch_sdcch4_demapper(timeslot_nr=0)
        dst = gsm.burst_sink()

        self.tb.msg_connect(src, "out", demapper, "bursts")
        self.tb.msg_connect(demapper, "bursts", dst, "in")
        self.tb.run ()

        b = test_data.bursts
        self.assertEqual([
            b[  2], b[  3], b[  4], b[  5], #BCCH
            b[  6], b[  7], b[  8], b[  9], #CCCH    skip 2
            b[ 12], b[ 13], b[ 14], b[ 15], #CCCH
            b[ 16], b[ 17], b[ 18], b[ 19], #CCCH    skip 2
            b[ 22], b[ 23], b[ 24], b[ 25], #SDCCH 0
            b[ 26], b[ 27], b[ 28], b[ 29], #SDCCH 1 skip 2
            b[ 32], b[ 33], b[ 34], b[ 35], #SDCCH 2
            b[ 36], b[ 37], b[ 38], b[ 39], #SDCCH 3 skip 2
            b[ 42], b[ 43], b[ 44], b[ 45], #SACCH 0
            b[ 46], b[ 47], b[ 48], b[ 49], #SACCH 1 skip 3
            b[ 53], b[ 54], b[ 55], b[ 56], #BCCH
            b[ 57], b[ 58], b[ 59], b[ 60], #CCCH    skip 2
            b[ 63], b[ 64], b[ 65], b[ 66], #CCCH
            b[ 67], b[ 68], b[ 69], b[ 70], #CCCH    skip 2
            b[ 73], b[ 74], b[ 75], b[ 76], #SDCCH 0
            b[ 77], b[ 78], b[ 79], b[ 80], #SDCCH 1 skip 2
            b[ 83], b[ 84], b[ 85], b[ 86], #SDCCH 2
            b[ 87], b[ 88], b[ 89], b[ 90], #SDCCH 3 skip 2
            b[ 93], b[ 94], b[ 95], b[ 96], #SACCH 1
            b[ 97], b[ 98], b[ 99], b[100], #SACCH 2 skip 3
            b[104], b[105], b[106], b[107]  #BCCH
            ], list(dst.get_burst_data()))

        self.assertEqual([
              1,   1,   1,   1, #BCCH
              2,   2,   2,   2, #CCCH
              2,   2,   2,   2, #CCCH
              2,   2,   2,   2, #CCCH
              7,   7,   7,   7, #SDCCH 0
              7,   7,   7,   7, #SDCCH 1
              7,   7,   7,   7, #SDCCH 2
              7,   7,   7,   7, #SDCCH 3
            135, 135, 135, 135, #SACCH 0
            135, 135, 135, 135, #SACCH 1
              1,   1,   1,   1, #BCCH
              2,   2,   2,   2, #CCCH
              2,   2,   2,   2, #CCCH
              2,   2,   2,   2, #CCCH
              7,   7,   7,   7, #SDCCH 0
              7,   7,   7,   7, #SDCCH 1
              7,   7,   7,   7, #SDCCH 2
              7,   7,   7,   7, #SDCCH 3
            135, 135, 135, 135, #SACCH 2
            135, 135, 135, 135, #SACCH 3
              1,   1,   1,   1, #BCCH
            ], list(dst.get_sub_types()))

        self.assertEqual([
            0, 0, 0, 0, #BCCH
            0, 0, 0, 0, #CCCH
            1, 1, 1, 1, #CCCH
            2, 2, 2, 2, #CCCH
            0, 0, 0, 0, #SDCCH 0
            1, 1, 1, 1, #SDCCH 1
            2, 2, 2, 2, #SDCCH 2
            3, 3, 3, 3, #SDCCH 3
            0, 0, 0, 0, #SACCH 0
            1, 1, 1, 1, #SACCH 1
            0, 0, 0, 0, #BCCH
            0, 0, 0, 0, #CCCH
            1, 1, 1, 1, #CCCH
            2, 2, 2, 2, #CCCH
            0, 0, 0, 0, #SDCCH 0
            1, 1, 1, 1, #SDCCH 1
            2, 2, 2, 2, #SDCCH 2
            3, 3, 3, 3, #SDCCH 3
            2, 2, 2, 2, #SACCH 2
            3, 3, 3, 3, #SACCH 3
            0, 0, 0, 0, #BCCH
            ], list(dst.get_sub_slots()))

    def test_uplink (self):
        """
           BCCH_CCCH_SDCCH4 demapper uplink test
        """
        src = gsm.burst_source(test_data.frames, test_data.timeslots, test_data.bursts)
        src.set_arfcn(0x2240); #uplink flag is 40
        demapper = gsm.gsm_bcch_ccch_sdcch4_demapper(timeslot_nr=0)
        dst = gsm.burst_sink()

        self.tb.msg_connect(src, "out", demapper, "bursts")
        self.tb.msg_connect(demapper, "bursts", dst, "in")
        self.tb.run ()

        b = test_data.bursts
        self.assertEqual(b, list(dst.get_burst_data()))

        self.assertEqual([
              7,   7,   7,   7, #SDCCH 3
              3,   3,           #RACCH
            135, 135, 135, 135, #SACCH 2
            135, 135, 135, 135, #SACCH 3
              3,   3,   3,   3, #RACCH
              3,   3,   3,   3, #RACCH
              3,   3,   3,   3, #RACCH
              3,   3,   3,   3, #RACCH
              3,   3,   3,   3, #RACCH
              3,   3,   3,      #RACCH
              7,   7,   7,   7, #SDCCH 0
              7,   7,   7,   7, #SDCCH 1
              3,   3,           #RACCH
              7,   7,   7,   7, #SDCCH 2
              7,   7,   7,   7, #SDCCH 3
              3,   3,           #RACCH
            135, 135, 135, 135, #SACCH 0
            135, 135, 135, 135, #SACCH 1
              3,   3,   3,   3, #RACCH
              3,   3,   3,   3, #RACCH
              3,   3,   3,   3, #RACCH
              3,   3,   3,   3, #RACCH
              3,   3,   3,   3, #RACCH
              3,   3,   3,      #RACCH
              7,   7,   7,   7, #SDCCH 0
              7,   7,   7,   7, #SDCCH 1
              3,   3,           #RACCH
              7,   7,   7,   7, #SDCCH 2
              7,   7,   7,   7, #SDCCH 3
              3,   3,           #RACCH
            ], list(dst.get_sub_types()))

        self.assertEqual([
            3, 3, 3, 3, #SDCCH 3
            0, 0,       #RACCH
            2, 2, 2, 2, #SACCH 2
            3, 3, 3, 3, #SACCH 3
            0, 0, 0, 0, #RACCH
            0, 0, 0, 0, #RACCH
            0, 0, 0, 0, #RACCH
            0, 0, 0, 0, #RACCH
            0, 0, 0, 0, #RACCH
            0, 0, 0,    #RACCH
            0, 0, 0, 0, #SDCCH 0
            1, 1, 1, 1, #SDCCH 1
            0, 0,       #RACCH
            2, 2, 2, 2, #SDCCH 2
            3, 3, 3, 3, #SDCCH 3
            0, 0,       #RACCH
            0, 0, 0, 0, #SACCH 0
            1, 1, 1, 1, #SACCH 1
            0, 0, 0, 0, #RACCH
            0, 0, 0, 0, #RACCH
            0, 0, 0, 0, #RACCH
            0, 0, 0, 0, #RACCH
            0, 0, 0, 0, #RACCH
            0, 0, 0,    #RACCH
            0, 0, 0, 0, #SDCCH 0
            1, 1, 1, 1, #SDCCH 1
            0, 0,       #RACCH
            2, 2, 2, 2, #SDCCH 2
            3, 3, 3, 3, #SDCCH 3
            0, 0,       #RACCH
            ], list(dst.get_sub_slots()))

if __name__ == '__main__':
    gr_unittest.run(qa_bcch_ccch_sdcch4_demapper, "qa_bcch_ccch_sdcch4_demapper.xml")
