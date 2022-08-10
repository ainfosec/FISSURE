/*
 * Copyright (C) 2016 Bastian Bloessl <bloessl@ccs-labs.org>
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
#ifndef INCLUDED_IEEE802_11_VITERBI_DECODER_X86_H
#define INCLUDED_IEEE802_11_VITERBI_DECODER_X86_H

#include <xmmintrin.h>
#include "base.h"

namespace gr {
namespace ieee802_11 {

/* This Viterbi decoder was taken from the gr-dvbt module of
 * GNU Radio. It is an SSE2 version of the Viterbi Decoder
 * created by Phil Karn. The SSE2 version was made by Bogdan
 * Diaconescu. For more info see: gr-dvbt/lib/d_viterbi.h
 */
class viterbi_decoder : public base
{
public:

	virtual uint8_t* decode(ofdm_param *ofdm, frame_param *frame, uint8_t *in);

private:

	union branchtab27 {
		unsigned char c[32];
		__m128i v[2];
	} d_branchtab27_sse2[2];

	__m128i d_metric0[4] __attribute__ ((aligned(16)));
	__m128i d_metric1[4] __attribute__ ((aligned(16)));
	__m128i d_path0[4] __attribute__ ((aligned(16)));
	__m128i d_path1[4] __attribute__ ((aligned(16)));

	virtual void reset();

	void viterbi_chunks_init_sse2();
	void viterbi_butterfly2_sse2(unsigned char *symbols,
			__m128i m0[], __m128i m1[], __m128i p0[], __m128i p1[]);
	unsigned char viterbi_get_output_sse2(__m128i *mm0,
			__m128i *pp0, int ntraceback, unsigned char *outbuf);
};

} // namespace ieee802_11
} // namespace gr

#endif /* INCLUDED_IEEE802_11_VITERBI_DECODER_X86_H */
