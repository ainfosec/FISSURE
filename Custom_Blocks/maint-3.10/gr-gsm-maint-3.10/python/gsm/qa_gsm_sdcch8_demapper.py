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

class qa_gsm_sdcch8_demapper (gr_unittest.TestCase):

    def setUp (self):
        self.tb = gr.top_block ()
        self.maxDiff = None

    def tearDown (self):
        self.tb = None

    def test_downlink (self):
        """
           SDCCH8 demapper downlink test
        """
        src = gsm.burst_source(test_data.frames, test_data.timeslots, test_data.bursts)
        src.set_arfcn(0); # downlink
        demapper = gsm.gsm_sdcch8_demapper(timeslot_nr=0)
        dst = gsm.burst_sink()

        self.tb.msg_connect(src, "out", demapper, "bursts")
        self.tb.msg_connect(demapper, "bursts", dst, "in")
        self.tb.run ()

        b = test_data.bursts
        self.assertEqual([
            b[  0], b[  1], b[  2], b[  3], #SDCCH 0
            b[  4], b[  5], b[  6], b[  7], #SDCCH 1
            b[  8], b[  9], b[ 10], b[ 11], #SDCCH 2
            b[ 12], b[ 13], b[ 14], b[ 15], #SDCCH 3
            b[ 16], b[ 17], b[ 18], b[ 19], #SDCCH 4
            b[ 20], b[ 21], b[ 22], b[ 23], #SDCCH 5
            b[ 24], b[ 25], b[ 26], b[ 27], #SDCCH 6
            b[ 28], b[ 29], b[ 30], b[ 31], #SDCCH 7
            b[ 32], b[ 33], b[ 34], b[ 35], #SACCH 0
            b[ 36], b[ 37], b[ 38], b[ 39], #SACCH 1
            b[ 40], b[ 41], b[ 42], b[ 43], #SACCH 2
            b[ 44], b[ 45], b[ 46], b[ 47], #SACCH 3 #skip 48-50
            b[ 51], b[ 52], b[ 53], b[ 54], #SDCCH 0
            b[ 55], b[ 56], b[ 57], b[ 58], #SDCCH 1
            b[ 59], b[ 60], b[ 61], b[ 62], #SDCCH 2
            b[ 63], b[ 64], b[ 65], b[ 66], #SDCCH 3
            b[ 67], b[ 68], b[ 69], b[ 70], #SDCCH 4
            b[ 71], b[ 72], b[ 73], b[ 74], #SDCCH 5
            b[ 75], b[ 76], b[ 77], b[ 78], #SDCCH 6
            b[ 79], b[ 80], b[ 81], b[ 82], #SDCCH 7
            b[ 83], b[ 84], b[ 85], b[ 86], #SACCH 4
            b[ 87], b[ 88], b[ 89], b[ 90], #SACCH 5
            b[ 91], b[ 92], b[ 93], b[ 94], #SACCH 6
            b[ 95], b[ 96], b[ 97], b[ 98], #SACCH 7 #skip 99-101
            b[102], b[103], b[104], b[105], #SDCCH
            ], list(dst.get_burst_data()))

        self.assertEqual([
              8,   8,   8,   8,
              8,   8,   8,   8,
              8,   8,   8,   8,
              8,   8,   8,   8,
              8,   8,   8,   8,
              8,   8,   8,   8,
              8,   8,   8,   8,
              8,   8,   8,   8,
            136, 136, 136, 136,
            136, 136, 136, 136,
            136, 136, 136, 136,
            136, 136, 136, 136,
              8,   8,   8,   8,
              8,   8,   8,   8,
              8,   8,   8,   8,
              8,   8,   8,   8,
              8,   8,   8,   8,
              8,   8,   8,   8,
              8,   8,   8,   8,
              8,   8,   8,   8,
            136, 136, 136, 136,
            136, 136, 136, 136,
            136, 136, 136, 136,
            136, 136, 136, 136,
              8,   8,   8,   8,
            ], list(dst.get_sub_types()))

        self.assertEqual([
            0, 0, 0, 0,
            1, 1, 1, 1,
            2, 2, 2, 2,
            3, 3, 3, 3,
            4, 4, 4, 4,
            5, 5, 5, 5,
            6, 6, 6, 6,
            7, 7, 7, 7,
            0, 0, 0, 0, #SACCH 0
            1, 1, 1, 1, #SACCH 1
            2, 2, 2, 2, #SACCH 2
            3, 3, 3, 3, #SACCH 3
            0, 0, 0, 0,
            1, 1, 1, 1,
            2, 2, 2, 2,
            3, 3, 3, 3,
            4, 4, 4, 4,
            5, 5, 5, 5,
            6, 6, 6, 6,
            7, 7, 7, 7,
            4, 4, 4, 4, #SACCH 4
            5, 5, 5, 5, #SACCH 5
            6, 6, 6, 6, #SACCH 6
            7, 7, 7, 7, #SACCH 7
            0, 0, 0, 0,
            ], list(dst.get_sub_slots()))

    def test_uplink (self):
        """
           BCCH_CCCH_SDCCH4 demapper uplink test
        """
        src = gsm.burst_source(test_data.frames, test_data.timeslots, test_data.bursts)
        src.set_arfcn(0x2240); #uplink flag is 40
        demapper = gsm.gsm_sdcch8_demapper(timeslot_nr=0)
        dst = gsm.burst_sink()

        self.tb.msg_connect(src, "out", demapper, "bursts")
        self.tb.msg_connect(demapper, "bursts", dst, "in")
        self.tb.run ()

        b = test_data.bursts
        self.assertEqual([
            b[  0], b[  1], b[  2], b[  3], #SACCH 5
            b[  4], b[  5], b[  6], b[  7], #SACCH 6
            b[  8], b[  9], b[ 10], b[ 11], #SACCH 7 #skip 12-14
            b[ 15], b[ 16], b[ 17], b[ 18], #SDCCH 0
            b[ 19], b[ 20], b[ 21], b[ 22], #SDCCH 1
            b[ 23], b[ 24], b[ 25], b[ 26], #SDCCH 2
            b[ 27], b[ 28], b[ 29], b[ 30], #SDCCH 3
            b[ 31], b[ 32], b[ 33], b[ 34], #SDCCH 4
            b[ 35], b[ 36], b[ 37], b[ 38], #SDCCH 5
            b[ 39], b[ 40], b[ 41], b[ 42], #SDCCH 6
            b[ 43], b[ 44], b[ 45], b[ 46], #SDCCH 7
            b[ 47], b[ 48], b[ 49], b[ 50], #SACCH 0
            b[ 51], b[ 52], b[ 53], b[ 54], #SACCH 1
            b[ 55], b[ 56], b[ 57], b[ 58], #SACCH 2
            b[ 59], b[ 60], b[ 61], b[ 62], #SACCH 3 #skip 63-65
            b[ 66], b[ 67], b[ 68], b[ 69], #SDCCH 0
            b[ 70], b[ 71], b[ 72], b[ 73], #SDCCH 1
            b[ 74], b[ 75], b[ 76], b[ 77], #SDCCH 2
            b[ 78], b[ 79], b[ 80], b[ 81], #SDCCH 3
            b[ 82], b[ 83], b[ 84], b[ 85], #SDCCH 4
            b[ 86], b[ 87], b[ 88], b[ 89], #SDCCH 5
            b[ 90], b[ 91], b[ 92], b[ 93], #SDCCH 6
            b[ 94], b[ 95], b[ 96], b[ 97], #SDCCH 7
            b[ 98], b[ 99], b[100], b[101], #SACCH 4
            b[102], b[103], b[104], b[105], #SACCH 5
            ], list(dst.get_burst_data()))

        self.assertEqual([
            136, 136, 136, 136,
            136, 136, 136, 136,
            136, 136, 136, 136,
              8,   8,   8,   8,
              8,   8,   8,   8,
              8,   8,   8,   8,
              8,   8,   8,   8,
              8,   8,   8,   8,
              8,   8,   8,   8,
              8,   8,   8,   8,
              8,   8,   8,   8,
            136, 136, 136, 136,
            136, 136, 136, 136,
            136, 136, 136, 136,
            136, 136, 136, 136,
              8,   8,   8,   8,
              8,   8,   8,   8,
              8,   8,   8,   8,
              8,   8,   8,   8,
              8,   8,   8,   8,
              8,   8,   8,   8,
              8,   8,   8,   8,
              8,   8,   8,   8,
            136, 136, 136, 136,
            136, 136, 136, 136,
            ], list(dst.get_sub_types()))

        self.assertEqual([
            5, 5, 5, 5, #SACCH 5
            6, 6, 6, 6, #SACCH 6
            7, 7, 7, 7, #SACCH 7
            0, 0, 0, 0,
            1, 1, 1, 1,
            2, 2, 2, 2,
            3, 3, 3, 3,
            4, 4, 4, 4,
            5, 5, 5, 5,
            6, 6, 6, 6,
            7, 7, 7, 7,
            0, 0, 0, 0, #SACCH 0
            1, 1, 1, 1, #SACCH 1
            2, 2, 2, 2, #SACCH 2
            3, 3, 3, 3, #SACCH 3
            0, 0, 0, 0,
            1, 1, 1, 1,
            2, 2, 2, 2,
            3, 3, 3, 3,
            4, 4, 4, 4,
            5, 5, 5, 5,
            6, 6, 6, 6,
            7, 7, 7, 7,
            4, 4, 4, 4, #SACCH 4
            5, 5, 5, 5,
            ], list(dst.get_sub_slots()))

if __name__ == '__main__':
    gr_unittest.run(qa_gsm_sdcch8_demapper, "qa_gsm_sdcch8_demapper.xml")
