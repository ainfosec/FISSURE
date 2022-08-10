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
import time
import ieee802_15_4_swig as ieee802_15_4
from css_phy import physical_layer as phy
import css_constants as c
import numpy as np

class qa_css_txrx (gr_unittest.TestCase):

    def setUp (self):
        self.tb = gr.top_block ()
        self.c = phy(slow_rate=True)
        self.dqcsk_mapper = ieee802_15_4.dqcsk_mapper_fc(self.c.chirp_seq, self.c.time_gap_1, self.c.time_gap_2, c.n_sub, self.c.n_subchirps)
        self.dqcsk_demapper = ieee802_15_4.dqcsk_demapper_cc(self.c.chirp_seq, self.c.time_gap_1, self.c.time_gap_2, c.n_sub, self.c.n_subchirps)
        self.dqpsk_mapper = ieee802_15_4.dqpsk_mapper_ff(framelen=self.c.nsym_frame, forward=True)
        self.dqpsk_demapper = ieee802_15_4.dqpsk_soft_demapper_cc(framelen=self.c.nsym_frame)
        self.qpsk_mapper = ieee802_15_4.qpsk_mapper_if() 
        self.qpsk_demapper = ieee802_15_4.qpsk_demapper_fi() 
        self.preamble_sfd_prefixer_I = ieee802_15_4.preamble_sfd_prefixer_ii(self.c.preamble, self.c.SFD, self.c.nsym_frame)
        self.preamble_sfd_removal_I = blocks.keep_m_in_n(gr.sizeof_int, self.c.nsym_frame - len(self.c.preamble) - len(self.c.SFD), self.c.nsym_frame, len(self.c.preamble)+len(self.c.SFD))
        self.preamble_sfd_prefixer_Q = ieee802_15_4.preamble_sfd_prefixer_ii(self.c.preamble, self.c.SFD, self.c.nsym_frame)
        self.preamble_sfd_removal_Q = blocks.keep_m_in_n(gr.sizeof_int, self.c.nsym_frame - len(self.c.preamble) - len(self.c.SFD), self.c.nsym_frame, len(self.c.preamble)+len(self.c.SFD))
        self.interleaver_I = ieee802_15_4.interleaver_ii(self.c.intlv_seq, forward=True)
        self.interleaver_Q = ieee802_15_4.interleaver_ii(self.c.intlv_seq, forward=True)
        self.deinterleaver_I = ieee802_15_4.interleaver_ii(self.c.intlv_seq, forward=False)
        self.deinterleaver_Q = ieee802_15_4.interleaver_ii(self.c.intlv_seq, forward=False)
        self.codeword_mapper_I = ieee802_15_4.codeword_mapper_bi(self.c.bits_per_symbol, self.c.codewords)
        self.codeword_mapper_Q = ieee802_15_4.codeword_mapper_bi(self.c.bits_per_symbol, self.c.codewords)
        self.codeword_demapper_I = ieee802_15_4.codeword_demapper_ib(self.c.bits_per_symbol, self.c.codewords)
        self.codeword_demapper_Q = ieee802_15_4.codeword_demapper_ib(self.c.bits_per_symbol, self.c.codewords)
        self.demux = blocks.deinterleave(gr.sizeof_char*1,1)
        self.mux = blocks.interleave(gr.sizeof_char*1,1)
        self.zeropadding = ieee802_15_4.zeropadding_b(self.c.padded_zeros)
        self.zeropadding_removal = ieee802_15_4.zeropadding_removal_b(self.c.phy_packetsize_bytes*8+len(self.c.PHR), self.c.padded_zeros)
        self.phr_prefixer = ieee802_15_4.phr_prefixer(self.c.PHR)
        self.phr_removal = ieee802_15_4.phr_removal(self.c.PHR)
        self.fragmentation = ieee802_15_4.fragmentation(self.c.phy_packetsize_bytes)

    def tearDown (self):
        self.tb = None

    # tests start at the point where tx and rx path connect and then expand towards the source/sink

    # def test_001_t (self):
    #     # DQCSK mapper to demapper
    #     data_in = (np.pi/4, np.pi/4*3, -np.pi/4, -np.pi/4*3)
    #     self.src = blocks.vector_source_f(data_in)
    #     self.snk = blocks.vector_sink_f(1)
    #
    #     self.tb.connect(self.src, self.dqcsk_mapper, self.dqcsk_demapper, self.snk)
    #     self.tb.run()
    #
    #     data_out = self.snk.data()
    #     self.assertFloatTuplesAlmostEqual(data_in, data_out)
    #
    # def test_002_t (self):
    #     # DQPSK mapper to demapper
    #     data_in = (0, np.pi/2, np.pi, -np.pi/2)
    #     self.src = blocks.vector_source_f(data_in)
    #     self.snk = blocks.vector_sink_f(1)
    #
    #     self.tb.connect(self.src, self.dqpsk_mapper, self.dqcsk_mapper, self.dqcsk_demapper, self.dqpsk_demapper, self.snk)
    #     self.tb.run()
    #
    #     data_out = self.snk.data()
    #     data_in = [np.fmod(i+np.pi+1e-6, np.pi) for i in data_in]
    #     data_out = [np.fmod(i+np.pi+1e-6, np.pi) for i in data_out] # 1e-6 is needed to force the wrap-around...
    #     self.assertFloatTuplesAlmostEqual(data_in, data_out, 5)
    #
    # def test_003_t (self):
    #     # QPSK mapper to demapper
    #     data_in_I = [1,-1,1,-1]
    #     data_in_Q = [1,1,-1,-1]
    #     self.src_I = blocks.vector_source_i(data_in_I)
    #     self.snk_I = blocks.vector_sink_i(1)
    #     self.src_Q = blocks.vector_source_i(data_in_Q)
    #     self.snk_Q = blocks.vector_sink_i(1)
    #
    #     self.tb.connect(self.src_I, (self.qpsk_mapper,0))
    #     self.tb.connect(self.src_Q, (self.qpsk_mapper,1))
    #     self.tb.connect(self.qpsk_mapper, self.dqpsk_mapper, self.dqcsk_mapper, self.dqcsk_demapper, self.dqpsk_demapper, self.qpsk_demapper)
    #     self.tb.connect((self.qpsk_demapper,0), self.snk_I)
    #     self.tb.connect((self.qpsk_demapper,1), self.snk_Q)
    #     self.tb.run()
    #
    #     data_out_I = self.snk_I.data()
    #     data_out_Q = self.snk_Q.data()
    #     self.assertFloatTuplesAlmostEqual(data_in_I, data_out_I)
    #     self.assertFloatTuplesAlmostEqual(data_in_Q, data_out_Q)
    #
    # def test_004_t (self):
    #     # Preamble and SFD prefixer to removal
    #     data_in_I = [i*2-1 for i in np.random.randint(0,2,(2*(self.c.nsym_frame-len(self.c.preamble)-len(self.c.SFD)),))]
    #     data_in_Q = [i*2-1 for i in np.random.randint(0,2,(2*(self.c.nsym_frame-len(self.c.preamble)-len(self.c.SFD)),))]
    #     self.src_I = blocks.vector_source_i(data_in_I)
    #     self.snk_I = blocks.vector_sink_i(1)
    #     self.src_Q = blocks.vector_source_i(data_in_Q)
    #     self.snk_Q = blocks.vector_sink_i(1)
    #
    #     # self.dbg_sink1 = blocks.vector_sink_i(1)
    #     # self.dbg_sink2 = blocks.vector_sink_i(1)
    #     # self.dbg_sink3 = blocks.vector_sink_f(1)
    #     # self.dbg_sink4 = blocks.vector_sink_f(1)
    #     # self.dbg_sink5 = blocks.vector_sink_c(1)
    #     # self.dbg_sink6 = blocks.vector_sink_f(1)
    #     # self.dbg_sink7 = blocks.vector_sink_f(1)
    #
    #     self.tb.connect(self.src_I, self.preamble_sfd_prefixer_I, (self.qpsk_mapper,0))
    #     self.tb.connect(self.src_Q, self.preamble_sfd_prefixer_Q, (self.qpsk_mapper,1))
    #     self.tb.connect(self.qpsk_mapper, self.dqpsk_mapper, self.dqcsk_mapper, self.dqcsk_demapper, self.dqpsk_demapper, self.qpsk_demapper)
    #     self.tb.connect((self.qpsk_demapper,0), self.preamble_sfd_removal_I, self.snk_I)
    #     self.tb.connect((self.qpsk_demapper,1), self.preamble_sfd_removal_Q, self.snk_Q)
    #
    #     # self.tb.connect((self.qpsk_mapper,0), self.dbg_sink3)
    #     # self.tb.connect(self.preamble_sfd_prefixer_I, self.dbg_sink2)
    #     # self.tb.connect(self.dqpsk_mapper, self.dbg_sink4)
    #     # self.tb.connect(self.dqcsk_mapper, self.dbg_sink5)
    #     # self.tb.connect(self.dqcsk_demapper, self.dbg_sink6)
    #     # self.tb.connect(self.dqcsk_demapper, self.dbg_sink7)
    #
    #     self.tb.run()
    #
    #     # print "sfd prefixer output len:", len(self.dbg_sink2.data())
    #     # print "qpsk mapper output len:", len(self.dbg_sink3.data())
    #     # print "dqpsk mapper output len:", len(self.dbg_sink4.data())
    #     # print "dqcsk mapper output len:", len(self.dbg_sink5.data())
    #     # print "dqcsk demapper output len:", len(self.dbg_sink6.data())
    #     # print "dqpsk demapper output len:", len(self.dbg_sink7.data())
    #
    #     data_out_I = self.snk_I.data()
    #     data_out_Q = self.snk_Q.data()
    #     self.assertFloatTuplesAlmostEqual(data_in_I, data_out_I)
    #     self.assertFloatTuplesAlmostEqual(data_in_Q, data_out_Q)
    #
    # def test_005_t (self):
    #     # Interleaver to deinterleaver
    #     data_in_I = [i*2-1 for i in np.random.randint(0,2,(2*len(self.c.codewords[0])*(self.c.nsym_frame-len(self.c.preamble)-len(self.c.SFD)),))]
    #     data_in_Q = [i*2-1 for i in np.random.randint(0,2,(2*len(self.c.codewords[0])*(self.c.nsym_frame-len(self.c.preamble)-len(self.c.SFD)),))]
    #     self.src_I = blocks.vector_source_i(data_in_I)
    #     self.snk_I = blocks.vector_sink_i(1)
    #     self.src_Q = blocks.vector_source_i(data_in_Q)
    #     self.snk_Q = blocks.vector_sink_i(1)
    #
    #     self.tb.connect(self.src_I, self.interleaver_I, self.preamble_sfd_prefixer_I, (self.qpsk_mapper,0))
    #     self.tb.connect(self.src_Q, self.interleaver_Q, self.preamble_sfd_prefixer_Q, (self.qpsk_mapper,1))
    #     self.tb.connect(self.qpsk_mapper, self.dqpsk_mapper, self.dqcsk_mapper, self.dqcsk_demapper, self.dqpsk_demapper, self.qpsk_demapper)
    #     self.tb.connect((self.qpsk_demapper,0), self.preamble_sfd_removal_I, self.deinterleaver_I, self.snk_I)
    #     self.tb.connect((self.qpsk_demapper,1), self.preamble_sfd_removal_Q, self.deinterleaver_Q, self.snk_Q)
    #
    #     self.tb.run()
    #
    #     data_out_I = self.snk_I.data()
    #     data_out_Q = self.snk_Q.data()
    #     self.assertFloatTuplesAlmostEqual(data_out_I, data_in_I)
    #     self.assertFloatTuplesAlmostEqual(data_out_I, data_in_I)
    #
    # def test_006_t (self):
    #     # codeword mapper to demapper
    #     data_in_I = np.random.randint(0,2,(len(self.c.codewords[0])*(self.c.nsym_frame-len(self.c.preamble)-len(self.c.SFD)),))
    #     data_in_Q = np.random.randint(0,2,(len(self.c.codewords[0])*(self.c.nsym_frame-len(self.c.preamble)-len(self.c.SFD)),))
    #     self.src_I = blocks.vector_source_b(data_in_I)
    #     self.snk_I = blocks.vector_sink_b(1)
    #     self.src_Q = blocks.vector_source_b(data_in_Q)
    #     self.snk_Q = blocks.vector_sink_b(1)
    #
    #     self.tb.connect(self.src_I, self.codeword_mapper_I, self.interleaver_I, self.preamble_sfd_prefixer_I, (self.qpsk_mapper,0))
    #     self.tb.connect(self.src_Q, self.codeword_mapper_Q, self.interleaver_Q, self.preamble_sfd_prefixer_Q, (self.qpsk_mapper,1))
    #     self.tb.connect(self.qpsk_mapper, self.dqpsk_mapper, self.dqcsk_mapper, self.dqcsk_demapper, self.dqpsk_demapper, self.qpsk_demapper)
    #     self.tb.connect((self.qpsk_demapper,0), self.preamble_sfd_removal_I, self.deinterleaver_I, self.codeword_demapper_I, self.snk_I)
    #     self.tb.connect((self.qpsk_demapper,1), self.preamble_sfd_removal_Q, self.deinterleaver_Q, self.codeword_demapper_Q, self.snk_Q)
    #
    #     self.tb.run()
    #
    #     data_out_I = self.snk_I.data()
    #     data_out_Q = self.snk_Q.data()
    #     self.assertFloatTuplesAlmostEqual(data_out_I, data_in_I[:len(data_out_I)])
    #     self.assertFloatTuplesAlmostEqual(data_out_I, data_in_I[:len(data_out_Q)])
    #
    # def test_007_t (self):
    #     # demux to mux
    #     data_in = np.random.randint(0,2,(2*len(self.c.codewords[0])*(self.c.nsym_frame-len(self.c.preamble)-len(self.c.SFD)),))
    #     self.src = blocks.vector_source_b(data_in)
    #     self.snk = blocks.vector_sink_b(1)
    #
    #     self.tb.connect(self.src, self.demux)
    #     self.tb.connect((self.demux,0), self.codeword_mapper_I, self.interleaver_I, self.preamble_sfd_prefixer_I, (self.qpsk_mapper,0))
    #     self.tb.connect((self.demux,1), self.codeword_mapper_Q, self.interleaver_Q, self.preamble_sfd_prefixer_Q, (self.qpsk_mapper,1))
    #     self.tb.connect(self.qpsk_mapper, self.dqpsk_mapper, self.dqcsk_mapper, self.dqcsk_demapper, self.dqpsk_demapper, self.qpsk_demapper)
    #     self.tb.connect((self.qpsk_demapper,0), self.preamble_sfd_removal_I, self.deinterleaver_I, self.codeword_demapper_I, (self.mux,0))
    #     self.tb.connect((self.qpsk_demapper,1), self.preamble_sfd_removal_Q, self.deinterleaver_Q, self.codeword_demapper_Q, (self.mux,1))
    #     self.tb.connect(self.mux, self.snk)
    #
    #     self.tb.run()
    #
    #     data_out = self.snk.data()
    #     self.assertFloatTuplesAlmostEqual(data_out, data_in[:len(data_out)])
    #
    # def test_008_t (self):
    #     # zeropadding to zeropadding removal
    #     data_in = pmt.cons(pmt.PMT_NIL, pmt.make_u8vector(len(self.c.PHR)+8*self.c.phy_packetsize_bytes,1))
    #     self.src = blocks.message_strobe(data_in,100)
    #     self.snk = blocks.message_debug()
    #
    #     self.tb.msg_connect(self.src, "strobe", self.zeropadding, "in")
    #     self.tb.connect(self.zeropadding, self.demux)
    #     self.tb.connect((self.demux,0), self.codeword_mapper_I, self.interleaver_I, self.preamble_sfd_prefixer_I, (self.qpsk_mapper,0))
    #     self.tb.connect((self.demux,1), self.codeword_mapper_Q, self.interleaver_Q, self.preamble_sfd_prefixer_Q, (self.qpsk_mapper,1))
    #     self.tb.connect(self.qpsk_mapper, self.dqpsk_mapper, self.dqcsk_mapper, self.dqcsk_demapper, self.dqpsk_demapper, self.qpsk_demapper)
    #     self.tb.connect((self.qpsk_demapper,0), self.preamble_sfd_removal_I, self.deinterleaver_I, self.codeword_demapper_I, (self.mux,0))
    #     self.tb.connect((self.qpsk_demapper,1), self.preamble_sfd_removal_Q, self.deinterleaver_Q, self.codeword_demapper_Q, (self.mux,1))
    #     self.tb.connect(self.mux, self.zeropadding_removal)
    #     self.tb.msg_connect(self.zeropadding_removal, "out", self.snk, "store")
    #
    #     self.tb.start()
    #     time.sleep(0.3)
    #     self.tb.stop()
    #
    #     msg_out = self.snk.get_message(0)
    #     data_out = pmt.to_python(msg_out)[1]
    #     ref = pmt.to_python(data_in)[1]
    #     self.assertTrue((data_out==ref[:len(data_out)]).all())
    #
    # def test_009_t (self):
    #     # PHR prefixer to removal
    #     data_in = pmt.cons(pmt.PMT_NIL, pmt.make_u8vector(self.c.phy_packetsize_bytes,170))
    #     self.src = blocks.message_strobe(data_in,100)
    #     self.snk = blocks.message_debug()
    #
    #     self.tb.msg_connect(self.src, "strobe", self.phr_prefixer, "in")
    #     self.tb.msg_connect(self.phr_prefixer, "out", self.zeropadding, "in")
    #     self.tb.connect(self.zeropadding, self.demux)
    #     self.tb.connect((self.demux,0), self.codeword_mapper_I, self.interleaver_I, self.preamble_sfd_prefixer_I, (self.qpsk_mapper,0))
    #     self.tb.connect((self.demux,1), self.codeword_mapper_Q, self.interleaver_Q, self.preamble_sfd_prefixer_Q, (self.qpsk_mapper,1))
    #     self.tb.connect(self.qpsk_mapper, self.dqpsk_mapper, self.dqcsk_mapper, self.dqcsk_demapper, self.dqpsk_demapper, self.qpsk_demapper)
    #     self.tb.connect((self.qpsk_demapper,0), self.preamble_sfd_removal_I, self.deinterleaver_I, self.codeword_demapper_I, (self.mux,0))
    #     self.tb.connect((self.qpsk_demapper,1), self.preamble_sfd_removal_Q, self.deinterleaver_Q, self.codeword_demapper_Q, (self.mux,1))
    #     self.tb.connect(self.mux, self.zeropadding_removal)
    #     self.tb.msg_connect(self.zeropadding_removal, "out", self.phr_removal, "in")
    #     self.tb.msg_connect(self.phr_removal, "out", self.snk, "store")
    #
    #     self.tb.start()
    #     time.sleep(0.3)
    #     self.tb.stop()
    #
    #     msg_out = self.snk.get_message(0)
    #     data_out = pmt.to_python(msg_out)[1]
    #     ref = pmt.to_python(data_in)[1]
    #     self.assertTrue((data_out==ref[:len(data_out)]).all())
    #
    # def test_010_t (self):
    #     # PHR prefixer to removal
    #     data_in = pmt.cons(pmt.PMT_NIL, pmt.make_u8vector(2*self.c.phy_packetsize_bytes,170))
    #     self.src = blocks.message_strobe(data_in,100)
    #     self.snk = blocks.message_debug()
    #
    #     self.tb.msg_connect(self.src, "strobe", self.fragmentation, "in")
    #     self.tb.msg_connect(self.fragmentation, "out", self.phr_prefixer, "in")
    #     self.tb.msg_connect(self.phr_prefixer, "out", self.zeropadding, "in")
    #     self.tb.connect(self.zeropadding, self.demux)
    #     self.tb.connect((self.demux,0), self.codeword_mapper_I, self.interleaver_I, self.preamble_sfd_prefixer_I, (self.qpsk_mapper,0))
    #     self.tb.connect((self.demux,1), self.codeword_mapper_Q, self.interleaver_Q, self.preamble_sfd_prefixer_Q, (self.qpsk_mapper,1))
    #     self.tb.connect(self.qpsk_mapper, self.dqpsk_mapper, self.dqcsk_mapper, self.dqcsk_demapper, self.dqpsk_demapper, self.qpsk_demapper)
    #     self.tb.connect((self.qpsk_demapper,0), self.preamble_sfd_removal_I, self.deinterleaver_I, self.codeword_demapper_I, (self.mux,0))
    #     self.tb.connect((self.qpsk_demapper,1), self.preamble_sfd_removal_Q, self.deinterleaver_Q, self.codeword_demapper_Q, (self.mux,1))
    #     self.tb.connect(self.mux, self.zeropadding_removal)
    #     self.tb.msg_connect(self.zeropadding_removal, "out", self.phr_removal, "in")
    #     self.tb.msg_connect(self.phr_removal, "out", self.snk, "store")
    #
    #     self.tb.start()
    #     time.sleep(0.3)
    #     self.tb.stop()
    #
    #     msg_out1 = self.snk.get_message(0)
    #     msg_out2 = self.snk.get_message(1)
    #     data_out1 = pmt.to_python(msg_out1)[1]
    #     data_out2 = pmt.to_python(msg_out2)[1]
    #     ref = pmt.to_python(data_in)[1]
    #     self.assertTrue((data_out1==ref[:len(data_out1)]).all() and (data_out2==ref[:len(data_out2)]).all())

if __name__ == '__main__':
    gr_unittest.run(qa_css_txrx)