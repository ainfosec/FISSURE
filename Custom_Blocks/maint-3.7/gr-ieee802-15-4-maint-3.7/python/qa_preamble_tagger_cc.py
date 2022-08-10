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
import matplotlib.pyplot as plt

class qa_preamble_tagger_cc (gr_unittest.TestCase):

    def setUp (self):
        self.tb = gr.top_block ()

    def tearDown (self):
        self.tb = None

    def test_001_t (self):
        # set up fg
        len_preamble = 7
        len_payload = 2
        len_frame = len_preamble + len_payload
        preamble = np.ones((len_preamble,))
        payload = np.zeros((len_payload,))
        payload[0] = -1
        frame0 = np.concatenate((preamble, payload))
        frame1 = np.concatenate((preamble, payload))
        frame2 = np.concatenate((preamble, payload))
        frames = np.concatenate((frame0, frame1, frame2))
        data_in = np.concatenate((frames, frames))
        src = blocks.vector_source_c(data_in)
        tagger = ieee802_15_4.preamble_tagger_cc(len_preamble)
        framer = ieee802_15_4.frame_buffer_cc(len_frame)
        snk = blocks.vector_sink_c()
        self.tb.connect(src, tagger, framer, snk)
        self.tb.run ()
        # check data
        data_out = snk.data()
        # plt.plot(data_in, 'b')
        # plt.plot(np.real(data_out), 'g')
        # plt.grid()
        # plt.ylim([-1.5, 1.5])
        # plt.show()
        self.assertComplexTuplesAlmostEqual(data_in[:len(data_out)], data_out)


if __name__ == '__main__':
    gr_unittest.run(qa_preamble_tagger_cc)
