#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2014 Jared Boone <jared@sharebrained.com>.
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

from gnuradio import gr, gr_unittest
from gnuradio import blocks
import tmps_python as tpms

class qa_ask_env (gr_unittest.TestCase):

    def setUp (self):
        self.tb = gr.top_block ()

    def tearDown (self):
        self.tb = None

    def test_001_t (self):
        src_data = (0, 1, 0.5, 0.25, -1, 1)
        expected_result = (0, 1, 0, -0.5, -1, 1)
        src = blocks.vector_source_f(src_data)
        dut = tpms.ask_env(0.0)
        dut.set_alpha(0.001)
        dst = blocks.vector_sink_f()
        self.tb.connect(src, dut)
        self.tb.connect(dut, dst)
        self.tb.run ()
        result_data = dst.data()
        self.assertFloatTuplesAlmostEqual(expected_result, result_data, 2)

if __name__ == '__main__':
    gr_unittest.run(qa_ask_env, "qa_ask_env.xml")
