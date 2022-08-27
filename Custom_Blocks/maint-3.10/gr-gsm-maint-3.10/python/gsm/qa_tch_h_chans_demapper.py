#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @file
# @author (C) 2018 by Vasil Velichkov <vvvelichkov@gmail.com>
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

import numpy as np
from gnuradio import gr, gr_unittest, blocks
from gnuradio import gsm
import pmt

class qa_tch_h_chans_demapper (gr_unittest.TestCase):

    def setUp (self):
        self.tb = gr.top_block ()

        self.bursts = [
            "1000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "0100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "0010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "0001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "0000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "0000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "0000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "0000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "0000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "0000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "0000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "0000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "0000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "0000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "0000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "0000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "0000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"]

    def tearDown (self):
        self.tb = None

    def test_hr_demapper_sub0 (self):
        """
            TCH/F Half Rate demapper sub-channel 0
        """
        frames = [
                 0,  1,  2,  3,  4,  5,  6,  7,
                 8,  9, 10, 11, 12, 13, 14, 15,
                16, 17, 18, 19, 20, 21, 22, 23,
                24, 25, 26, 27, 28, 29]
        timeslots = [
                3, 3, 3, 3, 3, 3, 3, 3,
                3, 3, 3, 3, 3, 3, 3, 3,
                3, 3, 3, 3, 3, 3, 3, 3,
                3, 3, 3, 3, 3, 3
                ]
        b = self.bursts
        bursts = [
                b[ 0], b[ 1], b[ 2], b[ 3], b[ 4], b[ 5], b[ 6], b[ 7],
                b[ 8], b[ 9], b[10], b[11], b[12], #12 - sacch
                b[13], b[14], b[15], b[16], b[17], b[18], b[19], b[20],
                b[21], b[22], b[23], b[24], b[25], #25 - idle
                b[26], b[27], b[28], b[29], b[30]
        ]

        src = gsm.burst_source(frames, timeslots, bursts)
        demapper = gsm.tch_h_chans_demapper(3, 0)
        tch = gsm.burst_sink()
        acch = gsm.burst_sink()

        self.tb.msg_connect(src, "out", demapper, "bursts")
        self.tb.msg_connect(demapper, "tch_bursts", tch, "in")
        self.tb.msg_connect(demapper, "acch_bursts", acch, "in")

        self.tb.run ()

        self.assertEqual([
            b[ 0], b[ 2], b[ 4], b[ 6],
            b[ 4], b[ 6], b[ 8], b[10],
            b[ 8], b[10],
            b[13], b[15],
            b[13], b[15], b[17], b[19],
            b[17], b[19], b[21], b[23],
            b[21], b[23],
            b[26], b[28],
            ], list(tch.get_burst_data()))

        self.assertEqual([], list(acch.get_burst_data()))

    def test_hr_demapper_sub1 (self):
        """
            TCH/F Half Rate demapper sub-channel 1
        """
        frames = [
                 0,  1,  2,  3,  4,  5,  6,  7,
                 8,  9, 10, 11, 12, 13, 14, 15,
                16, 17, 18, 19, 20, 21, 22, 23,
                24, 25, 26, 27, 28, 29]
        timeslots = [
                3, 3, 3, 3, 3, 3, 3, 3,
                3, 3, 3, 3, 3, 3, 3, 3,
                3, 3, 3, 3, 3, 3, 3, 3,
                3, 3, 3, 3, 3, 3
                ]
        b = self.bursts
        bursts = [
                b[ 0], b[ 1], b[ 2], b[ 3], b[ 4], b[ 5], b[ 6], b[ 7],
                b[ 8], b[ 9], b[10], b[11], b[12], #12 - sacch
                b[13], b[14], b[15], b[16], b[17], b[18], b[19], b[20],
                b[21], b[22], b[23], b[24], b[25], #25 - idle
                b[26], b[27], b[28], b[29], b[30]
        ]
        src = gsm.burst_source(frames, timeslots, bursts)
        demapper = gsm.tch_h_chans_demapper(3, 1)
        tch = gsm.burst_sink()
        acch = gsm.burst_sink()

        self.tb.msg_connect(src, "out", demapper, "bursts")
        self.tb.msg_connect(demapper, "tch_bursts", tch, "in")
        self.tb.msg_connect(demapper, "acch_bursts", acch, "in")

        self.tb.run ()

        self.assertEqual([
            b[ 1], b[ 3], b[ 5], b[ 7],
            b[ 5], b[ 7], b[ 9], b[11],
            b[ 9], b[11],
            b[14], b[16],
            b[14], b[16], b[18], b[20],
            b[18], b[20], b[22], b[24],
            b[22], b[24],
            b[27], b[29],
           ], list(tch.get_burst_data()))

        self.assertEqual([], list(acch.get_burst_data()))

    def sacch_hr_test (self, ts, sub, frames, bursts):
        timeslots = [ts, ts, ts, ts, ts, ts, ts, ts]

        src = gsm.burst_source(frames, timeslots, bursts)
        demapper = gsm.tch_h_chans_demapper(ts, sub)
        tch = gsm.burst_sink()
        acch = gsm.burst_sink()

        self.tb.msg_connect(src, "out", demapper, "bursts")
        self.tb.msg_connect(demapper, "tch_bursts", tch, "in")
        self.tb.msg_connect(demapper, "acch_bursts", acch, "in")

        self.tb.run ()

        self.assertEqual([], list(tch.get_burst_data()))

        return list(acch.get_burst_data())

    def test_sacch_th (self):
        """
            SACCH/TH tests
        """
        b = self.bursts
        bursts=[b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]
        even = [b[0], b[2], b[4], b[6]]
        odd =  [b[1], b[3], b[5], b[7]]
        self.assertEqual(even, self.sacch_hr_test(ts=0, sub=0, frames=[12, 25, 38, 51, 64, 77, 90, 103], bursts=bursts))
        self.assertEqual(odd,  self.sacch_hr_test(ts=0, sub=1, frames=[12, 25, 38, 51, 64, 77, 90, 103], bursts=bursts))
        self.assertEqual(even, self.sacch_hr_test(ts=1, sub=0, frames=[12, 25, 38, 51, 64, 77, 90, 103], bursts=bursts))
        self.assertEqual(odd,  self.sacch_hr_test(ts=1, sub=1, frames=[12, 25, 38, 51, 64, 77, 90, 103], bursts=bursts))
        self.assertEqual(even, self.sacch_hr_test(ts=2, sub=0, frames=[38, 51, 64, 77, 90, 103, 116, 129], bursts=bursts))
        self.assertEqual(odd,  self.sacch_hr_test(ts=2, sub=1, frames=[38, 51, 64, 77, 90, 103, 116, 129], bursts=bursts))
        self.assertEqual(even, self.sacch_hr_test(ts=3, sub=0, frames=[38, 51, 64, 77, 90, 103, 116, 129], bursts=bursts))
        self.assertEqual(odd,  self.sacch_hr_test(ts=3, sub=1, frames=[38, 51, 64, 77, 90, 103, 116, 129], bursts=bursts))
        self.assertEqual(even, self.sacch_hr_test(ts=4, sub=0, frames=[64, 77, 90, 103, 116, 129, 142, 155], bursts=bursts))
        self.assertEqual(odd,  self.sacch_hr_test(ts=4, sub=1, frames=[64, 77, 90, 103, 116, 129, 142, 155], bursts=bursts))
        self.assertEqual(even, self.sacch_hr_test(ts=5, sub=0, frames=[64, 77, 90, 103, 116, 129, 142, 155], bursts=bursts))
        self.assertEqual(odd,  self.sacch_hr_test(ts=5, sub=1, frames=[64, 77, 90, 103, 116, 129, 142, 155], bursts=bursts))
        self.assertEqual(even, self.sacch_hr_test(ts=6, sub=0, frames=[90, 103, 116, 129, 142, 155, 168, 181], bursts=bursts))
        self.assertEqual(odd,  self.sacch_hr_test(ts=6, sub=1, frames=[90, 103, 116, 129, 142, 155, 168, 181], bursts=bursts))
        self.assertEqual(even, self.sacch_hr_test(ts=7, sub=0, frames=[90, 103, 116, 129, 142, 155, 168, 181], bursts=bursts))
        self.assertEqual(odd,  self.sacch_hr_test(ts=7, sub=1, frames=[90, 103, 116, 129, 142, 155, 168, 181], bursts=bursts))

if __name__ == '__main__':
    gr_unittest.run(qa_tch_h_chans_demapper)
