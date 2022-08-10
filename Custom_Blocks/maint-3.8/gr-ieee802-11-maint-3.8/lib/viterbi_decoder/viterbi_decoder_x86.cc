/*
 * Copyright 1995 Phil Karn, KA9Q
 * Copyright 2008 Free Software Foundation, Inc.
 * 2014 Added SSE2 implementation Bogdan Diaconescu
 *
 * This file is part of GNU Radio
 *
 * GNU Radio is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3, or (at your option)
 * any later version.
 *

 * GNU Radio is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GNU Radio; see the file COPYING.  If not, write to
 * the Free Software Foundation, Inc., 51 Franklin Street,
 * Boston, MA 02110-1301, USA.
 */

/*
 * Viterbi decoder for K=7 rate=1/2 convolutional code
 * Some modifications from original Karn code by Matt Ettus
 * Major modifications by adding SSE2 code by Bogdan Diaconescu
 */
#include "viterbi_decoder_x86.h"
#include <cstring>
#include <iostream>

/* The basic Viterbi decoder operation, called a "butterfly"
 * operation because of the way it looks on a trellis diagram. Each
 * butterfly involves an Add-Compare-Select (ACS) operation on the two nodes
 * where the 0 and 1 paths from the current node merge at the next step of
 * the trellis.
 *
 * The code polynomials are assumed to have 1's on both ends. Given a
 * function encode_state() that returns the two symbols for a given
 * encoder state in the low two bits, such a code will have the following
 * identities for even 'n' < 64:
 *
 * 	encode_state(n) = encode_state(n+65)
 *	encode_state(n+1) = encode_state(n+64) = (3 ^ encode_state(n))
 *
 * Any convolutional code you would actually want to use will have
 * these properties, so these assumptions aren't too limiting.
 *
 * Doing this as a macro lets the compiler evaluate at compile time the
 * many expressions that depend on the loop index and encoder state and
 * emit them as immediate arguments.
 * This makes an enormous difference on register-starved machines such
 * as the Intel x86 family where evaluating these expressions at runtime
 * would spill over into memory.
 */

#define BUTTERFLY(i,sym) {											\
		int m0,m1,m2,m3;											\
		/* ACS for 0 branch */										\
		m0 = state[i].metric + mets[sym];	/* 2*i */				\
		m1 = state[i+32].metric + mets[3 ^ sym];	/* 2*i + 64 */	\
		if(m0 > m1){												\
			next[2*i].metric = m0;									\
			next[2*i].path = state[i].path << 1;					\
		} else {													\
			next[2*i].metric = m1;									\
			next[2*i].path = (state[i+32].path << 1)|1;				\
		}															\
		/* ACS for 1 branch */										\
		m2 = state[i].metric + mets[3 ^ sym];	/* 2*i + 1 */		\
		m3 = state[i+32].metric + mets[sym];	/* 2*i + 65 */		\
		if(m2 > m3){												\
			next[2*i+1].metric = m2;								\
			next[2*i+1].path = state[i].path << 1;					\
		} else {													\
			next[2*i+1].metric = m3;								\
			next[2*i+1].path = (state[i+32].path << 1)|1;			\
		}															\
	}

using namespace gr::ieee802_11;

void
viterbi_decoder::viterbi_butterfly2_sse2(unsigned char *symbols,
		__m128i *mm0, __m128i *mm1, __m128i *pp0, __m128i *pp1) {
	int i;

	__m128i *metric0, *metric1;
	__m128i *path0, *path1;

	metric0 = mm0;
	path0 = pp0;
	metric1 = mm1;
	path1 = pp1;

	// Operate on 4 symbols (2 bits) at a time

	__m128i m0, m1, m2, m3, decision0, decision1, survivor0, survivor1;
	__m128i metsv, metsvm;
	__m128i shift0, shift1;
	__m128i tmp0, tmp1;
	__m128i sym0v, sym1v;

	sym0v = _mm_set1_epi8(symbols[0]);
	sym1v = _mm_set1_epi8(symbols[1]);

	for (i = 0; i < 2; i++) {
		if (symbols[0] == 2) {
			metsvm = _mm_xor_si128(d_branchtab27_sse2[1].v[i],sym1v);
			metsv = _mm_sub_epi8(_mm_set1_epi8(1),metsvm);
		} else if (symbols[1] == 2) {
			metsvm = _mm_xor_si128(d_branchtab27_sse2[0].v[i],sym0v);
			metsv = _mm_sub_epi8(_mm_set1_epi8(1),metsvm);
		} else {
			metsvm = _mm_add_epi8(_mm_xor_si128(d_branchtab27_sse2[0].v[i],sym0v),_mm_xor_si128(d_branchtab27_sse2[1].v[i],sym1v));
			metsv = _mm_sub_epi8(_mm_set1_epi8(2),metsvm);
		}

		m0 = _mm_add_epi8(metric0[i], metsv);
		m1 = _mm_add_epi8(metric0[i+2], metsvm);
		m2 = _mm_add_epi8(metric0[i], metsvm);
		m3 = _mm_add_epi8(metric0[i+2], metsv);

		decision0 = _mm_cmpgt_epi8(_mm_sub_epi8(m0,m1),_mm_setzero_si128());
		decision1 = _mm_cmpgt_epi8(_mm_sub_epi8(m2,m3),_mm_setzero_si128());
		survivor0 = _mm_or_si128(_mm_and_si128(decision0,m0),_mm_andnot_si128(decision0,m1));
		survivor1 = _mm_or_si128(_mm_and_si128(decision1,m2),_mm_andnot_si128(decision1,m3));

		shift0 = _mm_slli_epi16(path0[i], 1);
		shift1 = _mm_slli_epi16(path0[2+i], 1);
		shift1 = _mm_add_epi8(shift1, _mm_set1_epi8(1));

		metric1[2*i] = _mm_unpacklo_epi8(survivor0,survivor1);
		tmp0 = _mm_or_si128(_mm_and_si128(decision0,shift0),_mm_andnot_si128(decision0,shift1));

		metric1[2*i+1] = _mm_unpackhi_epi8(survivor0,survivor1);
		tmp1 = _mm_or_si128(_mm_and_si128(decision1,shift0),_mm_andnot_si128(decision1,shift1));

		path1[2*i] = _mm_unpacklo_epi8(tmp0, tmp1);
		path1[2*i+1] = _mm_unpackhi_epi8(tmp0, tmp1);
	}

	metric0 = mm1;
	path0 = pp1;
	metric1 = mm0;
	path1 = pp0;

	sym0v = _mm_set1_epi8(symbols[2]);
	sym1v = _mm_set1_epi8(symbols[3]);

	for (i = 0; i < 2; i++) {
		if (symbols[2] == 2) {
			metsvm = _mm_xor_si128(d_branchtab27_sse2[1].v[i],sym1v);
			metsv = _mm_sub_epi8(_mm_set1_epi8(1),metsvm);

		} else if (symbols[3] == 2) {
			metsvm = _mm_xor_si128(d_branchtab27_sse2[0].v[i],sym0v);
			metsv = _mm_sub_epi8(_mm_set1_epi8(1),metsvm);

		} else {
			metsvm = _mm_add_epi8(_mm_xor_si128(d_branchtab27_sse2[0].v[i],sym0v),_mm_xor_si128(d_branchtab27_sse2[1].v[i],sym1v));
			metsv = _mm_sub_epi8(_mm_set1_epi8(2),metsvm);
		}

		m0 = _mm_add_epi8(metric0[i], metsv);
		m1 = _mm_add_epi8(metric0[i+2], metsvm);
		m2 = _mm_add_epi8(metric0[i], metsvm);
		m3 = _mm_add_epi8(metric0[i+2], metsv);

		decision0 = _mm_cmpgt_epi8(_mm_sub_epi8(m0,m1),_mm_setzero_si128());
		decision1 = _mm_cmpgt_epi8(_mm_sub_epi8(m2,m3),_mm_setzero_si128());
		survivor0 = _mm_or_si128(_mm_and_si128(decision0,m0),_mm_andnot_si128(decision0,m1));
		survivor1 = _mm_or_si128(_mm_and_si128(decision1,m2),_mm_andnot_si128(decision1,m3));

		shift0 = _mm_slli_epi16(path0[i], 1);
		shift1 = _mm_slli_epi16(path0[2+i], 1);
		shift1 = _mm_add_epi8(shift1, _mm_set1_epi8(1));

		metric1[2*i] = _mm_unpacklo_epi8(survivor0,survivor1);
		tmp0 = _mm_or_si128(_mm_and_si128(decision0,shift0),_mm_andnot_si128(decision0,shift1));

		metric1[2*i+1] = _mm_unpackhi_epi8(survivor0,survivor1);
		tmp1 = _mm_or_si128(_mm_and_si128(decision1,shift0),_mm_andnot_si128(decision1,shift1));

		path1[2*i] = _mm_unpacklo_epi8(tmp0, tmp1);
		path1[2*i+1] = _mm_unpackhi_epi8(tmp0, tmp1);
	}
}

//  Find current best path
unsigned char
viterbi_decoder::viterbi_get_output_sse2(__m128i *mm0, __m128i *pp0,
		int ntraceback, unsigned char *outbuf) {
	int i;
	int bestmetric, minmetric;
	int beststate = 0;
	int pos = 0;

	// circular buffer with the last ntraceback paths
	d_store_pos = (d_store_pos + 1) % ntraceback;

	for (i = 0; i < 4; i++) {
		_mm_store_si128((__m128i *) &d_mmresult[i*16], mm0[i]);
		_mm_store_si128((__m128i *) &d_ppresult[d_store_pos][i*16], pp0[i]);
	}

	// Find out the best final state
	bestmetric = d_mmresult[beststate];
	minmetric = d_mmresult[beststate];

	for (i = 1; i < 64; i++) {
		if (d_mmresult[i] > bestmetric) {
			bestmetric = d_mmresult[i];
			beststate = i;
		}
		if (d_mmresult[i] < minmetric) {
			minmetric = d_mmresult[i];
		}
	}

	// Trace back
	for (i = 0, pos = d_store_pos; i < (ntraceback - 1); i++) {
		// Obtain the state from the output bits
		// by clocking in the output bits in reverse order.
		// The state has only 6 bits
		beststate = d_ppresult[pos][beststate] >> 2;
		pos = (pos - 1 + ntraceback) % ntraceback;
	}

	// Store output byte
	*outbuf = d_ppresult[pos][beststate];

	// Zero out the path variable
	// and prevent metric overflow
	for (i = 0; i < 4; i++) {
		pp0[i] = _mm_setzero_si128();
		mm0[i] = _mm_sub_epi8(mm0[i], _mm_set1_epi8(minmetric));
	}

	return bestmetric;
}


uint8_t*
viterbi_decoder::decode(ofdm_param *ofdm, frame_param *frame, uint8_t *in) {

	d_ofdm = ofdm;
	d_frame = frame;

	reset();
	uint8_t *depunctured = depuncture(in);

	int in_count = 0;
	int out_count = 0;
	int n_decoded = 0;

	while(n_decoded < d_frame->n_data_bits) {

		if ((in_count % 4) == 0) { //0 or 3
			viterbi_butterfly2_sse2(&depunctured[in_count & 0xfffffffc], d_metric0, d_metric1, d_path0, d_path1);

			if ((in_count > 0) && (in_count % 16) == 8) { // 8 or 11
				unsigned char c;

				viterbi_get_output_sse2(d_metric0, d_path0, d_ntraceback, &c);

				if (out_count >= d_ntraceback) {
					for (int i= 0; i < 8; i++) {
						d_decoded[(out_count - d_ntraceback) * 8 + i] = (c >> (7 - i)) & 0x1;
						n_decoded++;
					}
				}
				out_count++;
			}
		}
		in_count++;
	}

	return d_decoded;
}

void
viterbi_decoder::reset() {

	viterbi_chunks_init_sse2();

	switch(d_ofdm->encoding) {
	case BPSK_1_2:
	case QPSK_1_2:
	case QAM16_1_2:
		d_ntraceback = 5;
		d_depuncture_pattern = PUNCTURE_1_2;
		d_k = 1;
		break;
	case QAM64_2_3:
		d_ntraceback = 9;
		d_depuncture_pattern = PUNCTURE_2_3;
		d_k = 2;
		break;
	case BPSK_3_4:
	case QPSK_3_4:
	case QAM16_3_4:
	case QAM64_3_4:
		d_ntraceback = 10;
		d_depuncture_pattern = PUNCTURE_3_4;
		d_k = 3;
		break;
	}
}

// Initialize starting metrics to prefer 0 state
void
viterbi_decoder::viterbi_chunks_init_sse2() {
	int i, j;

	for (i = 0; i < 4; i++) {
		d_metric0[i] = _mm_setzero_si128();
		d_path0[i] = _mm_setzero_si128();
	}

	int polys[2] = { 0x6d, 0x4f };
	for(i=0; i < 32; i++) {
		d_branchtab27_sse2[0].c[i] = (polys[0] < 0) ^ PARTAB[(2*i) & abs(polys[0])] ? 1 : 0;
		d_branchtab27_sse2[1].c[i] = (polys[1] < 0) ^ PARTAB[(2*i) & abs(polys[1])] ? 1 : 0;
	}

	for (i = 0; i < 64; i++) {
		d_mmresult[i] = 0;
		for (j = 0; j < TRACEBACK_MAX; j++) {
			d_ppresult[j][i] = 0;
		}
	}
}
