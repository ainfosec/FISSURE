/*
 * Copyright (C) 2015 Bastian Bloessl <bloessl@ccs-labs.org>
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

#include "sta.h"
#include <cstring>
#include <iostream>

using namespace gr::ieee802_11::equalizer;

void sta::equalize(gr_complex *in, int n, gr_complex *symbols, uint8_t *bits, boost::shared_ptr<gr::digital::constellation> mod) {

	if(n == 0) {
		std::memcpy(d_H, in, 64 * sizeof(gr_complex));

	} else if(n == 1) {
		double signal = 0;
		double noise = 0;
		for(int i = 0; i < 64; i++) {
			if((i == 32) || (i < 6) || ( i > 58)) {
				continue;
			}
			noise += std::pow(std::abs(d_H[i] - in[i]), 2);
			signal += std::pow(std::abs(d_H[i] + in[i]), 2);
			d_H[i] += in[i];
			d_H[i] /= LONG[i] * gr_complex(2, 0);
		}

		d_snr = 10 * std::log10(signal / noise / 2);

	} else {

		gr_complex H_update[64];
		gr_complex H[64];

		gr_complex p = POLARITY[(n - 2) % 127];

		H[11] = in[11] *  p;
		H[25] = in[25] *  p;
		H[39] = in[39] *  p;
		H[53] = in[53] * -p;

		int c = 0;
		for(int i = 0; i < 64; i++) {
			if( (i == 11) || (i == 25) || (i == 32) || (i == 39) || (i == 53) || (i < 6) || ( i > 58)) {
				continue;
			} else {
				symbols[c] = in[i] / d_H[i];
				bits[c] = mod->decision_maker(&symbols[c]);
				gr_complex point;
				mod->map_to_points(bits[c], &point);
				H[i] = in[i] / point;
				c++;
			}
		}

		for(int i = 0; i < 64; i++) {
			int n = 0;
			gr_complex s = 0;
			for(int k = i-beta; k <= i+beta; k++) {
				if((k == 32) || (k < 6) || ( k > 58)) {
					continue;
				}
				n++;
				s += H[k];
			}
			H_update[i] = s / gr_complex(n, 0);
		}

		for(int i = 0; i < 64; i++) {
			if((i < 6) || ( i > 58)) {
				continue;
			}
			d_H[i] = gr_complex(1-alpha,0) * d_H[i] + gr_complex(alpha,0) * H_update[i];
		}
	}
}

double
sta::get_snr() {
	return d_snr;
}
