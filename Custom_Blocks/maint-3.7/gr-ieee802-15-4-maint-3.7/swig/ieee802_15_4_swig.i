/*
 * Copyright 2013 Free Software Foundation, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#define IEEE802_15_4_API

%include <gnuradio.i>

%include "ieee802_15_4_swig_doc.i"

%{
#include "ieee802_15_4/access_code_prefixer.h"
#include "ieee802_15_4/access_code_removal_b.h"
#include "ieee802_15_4/chips_to_bits_fb.h"
#include "ieee802_15_4/codeword_demapper_ib.h"
#include "ieee802_15_4/codeword_mapper_bi.h"
#include "ieee802_15_4/codeword_soft_demapper_fb.h"
#include "ieee802_15_4/deinterleaver_ff.h"
#include "ieee802_15_4/dqcsk_demapper_cc.h"
#include "ieee802_15_4/dqcsk_mapper_fc.h"
#include "ieee802_15_4/dqpsk_mapper_ff.h"
#include "ieee802_15_4/dqpsk_soft_demapper_cc.h"
#include "ieee802_15_4/frame_buffer_cc.h"
#include "ieee802_15_4/interleaver_ii.h"
#include "ieee802_15_4/mac.h"
#include "ieee802_15_4/multiuser_chirp_detector_cc.h"
#include "ieee802_15_4/packet_sink.h"
#include "ieee802_15_4/phr_prefixer.h"
#include "ieee802_15_4/phr_removal.h"
#include "ieee802_15_4/preamble_sfd_prefixer_ii.h"
#include "ieee802_15_4/preamble_tagger_cc.h"
#include "ieee802_15_4/qpsk_demapper_fi.h"
#include "ieee802_15_4/qpsk_mapper_if.h"
#include "ieee802_15_4/rime_stack.h"
#include "ieee802_15_4/zeropadding_b.h"
#include "ieee802_15_4/zeropadding_removal_b.h"
%}

%include "ieee802_15_4/access_code_prefixer.h"
GR_SWIG_BLOCK_MAGIC2(ieee802_15_4, access_code_prefixer);
%include "ieee802_15_4/access_code_removal_b.h"
GR_SWIG_BLOCK_MAGIC2(ieee802_15_4, access_code_removal_b);
%include "ieee802_15_4/chips_to_bits_fb.h"
GR_SWIG_BLOCK_MAGIC2(ieee802_15_4, chips_to_bits_fb);
%include "ieee802_15_4/codeword_demapper_ib.h"
GR_SWIG_BLOCK_MAGIC2(ieee802_15_4, codeword_demapper_ib);
%include "ieee802_15_4/codeword_mapper_bi.h"
GR_SWIG_BLOCK_MAGIC2(ieee802_15_4, codeword_mapper_bi);
%include "ieee802_15_4/codeword_soft_demapper_fb.h"
GR_SWIG_BLOCK_MAGIC2(ieee802_15_4, codeword_soft_demapper_fb);
%include "ieee802_15_4/deinterleaver_ff.h"
GR_SWIG_BLOCK_MAGIC2(ieee802_15_4, deinterleaver_ff);
%include "ieee802_15_4/dqcsk_demapper_cc.h"
GR_SWIG_BLOCK_MAGIC2(ieee802_15_4, dqcsk_demapper_cc);
%include "ieee802_15_4/dqcsk_mapper_fc.h"
GR_SWIG_BLOCK_MAGIC2(ieee802_15_4, dqcsk_mapper_fc);
%include "ieee802_15_4/dqpsk_mapper_ff.h"
GR_SWIG_BLOCK_MAGIC2(ieee802_15_4, dqpsk_mapper_ff);
%include "ieee802_15_4/dqpsk_soft_demapper_cc.h"
GR_SWIG_BLOCK_MAGIC2(ieee802_15_4, dqpsk_soft_demapper_cc);
%include "ieee802_15_4/frame_buffer_cc.h"
GR_SWIG_BLOCK_MAGIC2(ieee802_15_4, frame_buffer_cc);
%include "ieee802_15_4/interleaver_ii.h"
GR_SWIG_BLOCK_MAGIC2(ieee802_15_4, interleaver_ii);
%include "ieee802_15_4/mac.h"
GR_SWIG_BLOCK_MAGIC2(ieee802_15_4, mac);
%include "ieee802_15_4/multiuser_chirp_detector_cc.h"
GR_SWIG_BLOCK_MAGIC2(ieee802_15_4, multiuser_chirp_detector_cc);
%include "ieee802_15_4/packet_sink.h"
GR_SWIG_BLOCK_MAGIC2(ieee802_15_4, packet_sink);
%include "ieee802_15_4/phr_prefixer.h"
GR_SWIG_BLOCK_MAGIC2(ieee802_15_4, phr_prefixer);
%include "ieee802_15_4/phr_removal.h"
GR_SWIG_BLOCK_MAGIC2(ieee802_15_4, phr_removal);
%include "ieee802_15_4/preamble_sfd_prefixer_ii.h"
GR_SWIG_BLOCK_MAGIC2(ieee802_15_4, preamble_sfd_prefixer_ii);
%include "ieee802_15_4/preamble_tagger_cc.h"
GR_SWIG_BLOCK_MAGIC2(ieee802_15_4, preamble_tagger_cc);
%include "ieee802_15_4/qpsk_demapper_fi.h"
GR_SWIG_BLOCK_MAGIC2(ieee802_15_4, qpsk_demapper_fi);
%include "ieee802_15_4/qpsk_mapper_if.h"
GR_SWIG_BLOCK_MAGIC2(ieee802_15_4, qpsk_mapper_if);
%include "ieee802_15_4/rime_stack.h"
GR_SWIG_BLOCK_MAGIC2(ieee802_15_4, rime_stack);
%include "ieee802_15_4/zeropadding_b.h"
GR_SWIG_BLOCK_MAGIC2(ieee802_15_4, zeropadding_b);
%include "ieee802_15_4/zeropadding_removal_b.h"
GR_SWIG_BLOCK_MAGIC2(ieee802_15_4, zeropadding_removal_b);
