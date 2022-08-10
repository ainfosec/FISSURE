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

#include "base.h"
#include <cstring>
#include <iostream>

using namespace gr::ieee802_11;

base::base() :
	d_store_pos(0) {
}

base::~base() {
}

uint8_t*
base::depuncture(uint8_t *in) {

	int count;
	int n_cbps = d_ofdm->n_cbps;
	uint8_t *depunctured;

	if (d_ntraceback == 5) {
		count = d_frame->n_sym * n_cbps;
		depunctured = in;

	} else {
		depunctured = d_depunctured;
		count = 0;
		for(int i = 0; i < d_frame->n_sym; i++) {
			for(int k = 0; k < n_cbps; k++) {
				while (d_depuncture_pattern[count % (2 * d_k)] == 0) {
					depunctured[count] = 2;
					count++;
				}

				// Insert received bits
				depunctured[count] = in[i * n_cbps + k];
				count++;

				while (d_depuncture_pattern[count % (2 * d_k)] == 0) {
					depunctured[count] = 2;
					count++;
				}
			}
		}
	}

	return depunctured;
}

/* Parity lookup table */
const unsigned char base::PARTAB[256] = {
	0, 1, 1, 0, 1, 0, 0, 1,
	1, 0, 0, 1, 0, 1, 1, 0,
	1, 0, 0, 1, 0, 1, 1, 0,
	0, 1, 1, 0, 1, 0, 0, 1,
	1, 0, 0, 1, 0, 1, 1, 0,
	0, 1, 1, 0, 1, 0, 0, 1,
	0, 1, 1, 0, 1, 0, 0, 1,
	1, 0, 0, 1, 0, 1, 1, 0,
	1, 0, 0, 1, 0, 1, 1, 0,
	0, 1, 1, 0, 1, 0, 0, 1,
	0, 1, 1, 0, 1, 0, 0, 1,
	1, 0, 0, 1, 0, 1, 1, 0,
	0, 1, 1, 0, 1, 0, 0, 1,
	1, 0, 0, 1, 0, 1, 1, 0,
	1, 0, 0, 1, 0, 1, 1, 0,
	0, 1, 1, 0, 1, 0, 0, 1,
	1, 0, 0, 1, 0, 1, 1, 0,
	0, 1, 1, 0, 1, 0, 0, 1,
	0, 1, 1, 0, 1, 0, 0, 1,
	1, 0, 0, 1, 0, 1, 1, 0,
	0, 1, 1, 0, 1, 0, 0, 1,
	1, 0, 0, 1, 0, 1, 1, 0,
	1, 0, 0, 1, 0, 1, 1, 0,
	0, 1, 1, 0, 1, 0, 0, 1,
	0, 1, 1, 0, 1, 0, 0, 1,
	1, 0, 0, 1, 0, 1, 1, 0,
	1, 0, 0, 1, 0, 1, 1, 0,
	0, 1, 1, 0, 1, 0, 0, 1,
	1, 0, 0, 1, 0, 1, 1, 0,
	0, 1, 1, 0, 1, 0, 0, 1,
	0, 1, 1, 0, 1, 0, 0, 1,
	1, 0, 0, 1, 0, 1, 1, 0,
};

const unsigned char base::PUNCTURE_1_2[2] = {1, 1};
const unsigned char base::PUNCTURE_2_3[4] = {1, 1, 1, 0};
const unsigned char base::PUNCTURE_3_4[6] = {1, 1, 1, 0, 0, 1};
