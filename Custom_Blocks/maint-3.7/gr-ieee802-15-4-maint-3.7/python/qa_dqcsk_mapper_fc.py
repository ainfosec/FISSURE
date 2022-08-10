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
from css_phy import physical_layer as phy
import css_constants as c
import numpy as np
import matplotlib.pyplot as plt

class qa_dqcsk_mapper_fc (gr_unittest.TestCase):

    def setUp (self):
        self.tb = gr.top_block ()

    def tearDown (self):
        self.tb = None

    def test_001_t (self):
        # set up fg
        cfg = phy()
        data_in = [0 for i in range(12)]
        self.src = blocks.vector_source_f(data_in)
        self.dqcsk = ieee802_15_4.dqcsk_mapper_fc(cfg.chirp_seq, cfg.time_gap_1, cfg.time_gap_2, c.n_sub, cfg.n_subchirps, 120)
        self.snk = blocks.vector_sink_c(1)
        self.tb.connect(self.src, self.dqcsk, self.snk)
        self.tb.run ()
        # check data
        data_out = self.snk.data()
        ref = np.concatenate((cfg.chirp_seq, cfg.time_gap_1, cfg.chirp_seq, cfg.time_gap_2, cfg.chirp_seq, cfg.time_gap_1))
        # print "ref:", ref[:10]
        # print "data:", data_out[:10]
        f,axarr = plt.subplots(2)
        # axarr[0].plot(np.real(ref))
        # axarr[1].plot(np.real(data_out))
        # plt.show()
        self.assertComplexTuplesAlmostEqual(data_out, ref)

    def test_002_t (self):
        # set up fg
        cfg = phy()
        data_in = [0, np.pi/2, np.pi, -np.pi/2]
        self.src = blocks.vector_source_f(data_in)
        self.dqcsk = ieee802_15_4.dqcsk_mapper_fc(cfg.chirp_seq, cfg.time_gap_1, cfg.time_gap_2, c.n_sub, cfg.n_subchirps, 4)
        self.snk = blocks.vector_sink_c(1)
        self.tb.connect(self.src, self.dqcsk, self.snk)
        self.tb.run ()
        # check data
        data_out = self.snk.data()
        ref = np.concatenate((cfg.chirp_seq.copy(), cfg.time_gap_1))
        for i in range(4):
        	ref[i*c.n_sub:(i+1)*c.n_sub] = ref[i*c.n_sub:(i+1)*c.n_sub]*np.exp(1j*data_in[i])
        # print "ref:", ref[:10]
        # print "data:", data_out[:10]
        self.assertComplexTuplesAlmostEqual(data_out, ref, 5)

    def test_003_t (self):
        # set up fg
        cfg = phy()
        data_in = np.pi/2*np.random.randint(-1,3,(1000,))
        self.src = blocks.vector_source_f(data_in)
        self.dqcsk = ieee802_15_4.dqcsk_mapper_fc(cfg.chirp_seq, cfg.time_gap_1, cfg.time_gap_2, c.n_sub, cfg.n_subchirps, 1000)
        self.snk = blocks.vector_sink_c(1)
        self.tb.connect(self.src, self.dqcsk, self.snk)
        self.tb.run ()
        # check data
        data_out = self.snk.data()
        
        ref = np.array([])
        seq = cfg.chirp_seq.copy()
        lensub = c.n_sub
        nseq = len(data_in)/cfg.n_subchirps
        len_t1 = len(cfg.time_gap_1)
        len_t2 = len(cfg.time_gap_2)
        seq_ctr = 0
        for i in range(nseq):
            for k in range(cfg.n_subchirps):
                ref = np.concatenate((ref, seq[k*lensub:(k+1)*lensub]*np.exp(1j*data_in[i*cfg.n_subchirps+k])))
            if seq_ctr % 2 == 0:
                ref = np.concatenate((ref, cfg.time_gap_1))
            else:
                ref = np.concatenate((ref, cfg.time_gap_2))
            seq_ctr = (seq_ctr+1) % 2
        # print "ref:", ref[:10]
        # print "data:", data_out[:10]
        self.assertComplexTuplesAlmostEqual(data_out, ref, 5)

if __name__ == '__main__':
    gr_unittest.run(qa_dqcsk_mapper_fc)
