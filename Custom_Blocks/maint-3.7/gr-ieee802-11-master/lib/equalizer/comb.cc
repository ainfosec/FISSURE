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

#include "comb.h"

using namespace gr::ieee802_11::equalizer;

void comb::equalize(gr_complex *in, int n, gr_complex *symbols, uint8_t *bits, boost::shared_ptr<gr::digital::constellation> mod) {

	gr_complex pilot[4];

	if(n < 2) {
		pilot[0] =  in[11];
		pilot[1] = -in[25];
		pilot[2] =  in[39];
		pilot[3] =  in[53];
	} else {
		gr_complex p = POLARITY[(n - 2) % 127];
		pilot[0] = in[11] *  p;
		pilot[1] = in[25] *  p;
		pilot[2] = in[39] *  p;
		pilot[3] = in[53] * -p;
	}

	gr_complex avg = (pilot[0] + pilot[1] + pilot[2] + pilot[3]) / gr_complex(4, 0);

	for(int i = 0; i < 64; i++) {
		gr_complex H;
		if(i <= 11) {
			H = gr_complex((11-i) / 11.0, 0) * avg      + gr_complex( i     / 11.0, 0) * pilot[0];
		} else if(i <= 25) {
			H = gr_complex((25-i) / 14.0, 0) * pilot[0] + gr_complex((i-11) / 14.0, 0) * pilot[1];
		} else if(i <= 39) {
			H = gr_complex((39-i) / 14.0, 0) * pilot[1] + gr_complex((i-25) / 14.0, 0) * pilot[2];
		} else if(i <= 53) {
			H = gr_complex((53-i) / 14.0, 0) * pilot[2] + gr_complex((i-39) / 14.0, 0) * pilot[3];
		} else {
			H = gr_complex((64-i) / 11.0, 0) * pilot[3] + gr_complex((i-53) / 11.0, 0) * avg;
		}

		if(n == 0) {
			d_H[i] = H;
		} else {
			d_H[i] = gr_complex(1-alpha, 0) * d_H[i] + gr_complex(alpha, 0) * H;
		}
	}

	int c = 0;
	for(int i = 0; i < 64; i++) {
		if( (i == 11) || (i == 25) || (i == 32) || (i == 39) || (i == 53) || (i < 6) || ( i > 58)) {
			continue;
		} else {
			symbols[c] = in[i] / d_H[i];
			bits[c] = mod->decision_maker(&symbols[c]);
			c++;
		}
	}
}

double
comb::get_snr() {
	return 42;
}
