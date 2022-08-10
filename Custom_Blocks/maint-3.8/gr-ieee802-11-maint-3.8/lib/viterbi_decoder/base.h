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
#ifndef INCLUDED_IEEE802_11_VITERBI_DECODER_BASE_H
#define INCLUDED_IEEE802_11_VITERBI_DECODER_BASE_H

#include "../utils.h"

namespace gr {
namespace ieee802_11 {

// Maximum number of traceback bytes
#define TRACEBACK_MAX 24

/* This Viterbi decoder was taken from the gr-dvbt module of
 * GNU Radio. It is an SSE2 version of the Viterbi Decoder
 * created by Phil Karn. The SSE2 version was made by Bogdan
 * Diaconescu. For more info see: gr-dvbt/lib/d_viterbi.h
 */
class base
{
public:

	base();
	~base();
	virtual uint8_t* decode(ofdm_param *ofdm, frame_param *frame, uint8_t *in) = 0;

protected:
	// Position in circular buffer where the current decoded byte is stored
	int d_store_pos;
	// Metrics for each state
	unsigned char d_mmresult[64] __attribute__((aligned(16)));
	// Paths for each state
	unsigned char d_ppresult[TRACEBACK_MAX][64] __attribute__((aligned(16)));

	int d_ntraceback;
	int d_k;
	ofdm_param *d_ofdm;
	frame_param *d_frame;
	const unsigned char *d_depuncture_pattern;

	uint8_t d_depunctured[MAX_ENCODED_BITS];
	uint8_t d_decoded[MAX_ENCODED_BITS * 3 / 4];

	static const unsigned char PARTAB[256];
	static const unsigned char PUNCTURE_1_2[2];
	static const unsigned char PUNCTURE_2_3[4];
	static const unsigned char PUNCTURE_3_4[6];

	virtual void reset() = 0;
	uint8_t* depuncture(uint8_t *in);
};

} // namespace ieee802_11
} // namespace gr

#endif /* INCLUDED_IEEE802_11_VITERBI_DECODER_BASE_H */
