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
#ifndef INCLUDED_IEEE802_11_VITERBI_DECODER_GENERIC_H
#define INCLUDED_IEEE802_11_VITERBI_DECODER_GENERIC_H

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
	} d_branchtab27_generic[2];

	unsigned char d_metric0_generic[64] __attribute__ ((aligned(16)));
	unsigned char d_metric1_generic[64] __attribute__ ((aligned(16)));
	unsigned char d_path0_generic[64] __attribute__ ((aligned(16)));
	unsigned char d_path1_generic[64] __attribute__ ((aligned(16)));

	void reset();

	void viterbi_chunks_init_generic();
	void viterbi_butterfly2_generic(unsigned char *symbols,
			unsigned char m0[], unsigned char m1[], unsigned char p0[],
			unsigned char p1[]);
	unsigned char viterbi_get_output_generic(unsigned char *mm0,
			unsigned char *pp0, int ntraceback, unsigned char *outbuf);
};

} // namespace ieee802_11
} // namespace gr

#endif /* INCLUDED_IEEE802_11_VITERBI_DECODER_GENERIC_H */
