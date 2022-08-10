#!/usr/bin/env python
# -*- coding: utf-8 -*-
# 
# Copyright 2016 Free Software Foundation, Inc
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
from gnuradio import blocks, analog
import iridium_swig as iridium
import numpy

class qa_fft_burst_tagger (gr_unittest.TestCase):

    def setUp (self):
        self.tb = gr.top_block ()

    def tearDown (self):
        self.tb = None

    def test_001_t (self):
        # set up fg
        source = blocks.vector_source_c(data=[0+0j]*10000)
        #source = blocks.file_source(itemsize=gr.sizeof_gr_complex, filename='/tmp/cut-7000.f32', repeat=False)
        fft_burst_tagger = iridium.fft_burst_tagger(fft_size=4096, sample_rate=1000000, center_frequency=1626000000,
                                burst_pre_len=4096, burst_post_len=8*4096, burst_width=40)
        vector_sink = blocks.vector_sink_c()
        self.tb.connect(source, fft_burst_tagger, vector_sink)
        self.tb.run ()
        # check data


if __name__ == '__main__':
    gr_unittest.run(qa_fft_burst_tagger, "qa_fft_burst_tagger.xml")
