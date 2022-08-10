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
#include "constellations_impl.h"

using namespace gr::ieee802_11;

constellation_bpsk::sptr
constellation_bpsk::make() {
	return constellation_bpsk::sptr(new constellation_bpsk_impl());
}

constellation_bpsk::constellation_bpsk() {}

constellation_bpsk_impl::constellation_bpsk_impl() {
	d_constellation.resize(2);
	d_constellation[0] = gr_complex(-1, 0);
	d_constellation[1] = gr_complex(1, 0);
	d_rotational_symmetry = 2;
	d_dimensionality = 1;
	calc_arity();
}

constellation_bpsk_impl::~constellation_bpsk_impl() {
}

unsigned int
constellation_bpsk_impl::decision_maker(const gr_complex *sample) {
	return (real(*sample) > 0);
}


/**********************************************************/

constellation_qpsk::sptr
constellation_qpsk::make() {
	return constellation_qpsk::sptr(new constellation_qpsk_impl());
}

constellation_qpsk::constellation_qpsk() {}

constellation_qpsk_impl::constellation_qpsk_impl() {
	const float level = sqrt(float(0.5));
	d_constellation.resize(4);
	// Gray-coded
	d_constellation[0] = gr_complex(-level, -level);
	d_constellation[1] = gr_complex( level, -level);
	d_constellation[2] = gr_complex(-level,  level);
	d_constellation[3] = gr_complex( level,  level);

	d_rotational_symmetry = 4;
	d_dimensionality = 1;
	calc_arity();
}

constellation_qpsk_impl::~constellation_qpsk_impl() {
}

unsigned int
constellation_qpsk_impl::decision_maker(const gr_complex *sample) {
	return 2*(imag(*sample)>0) + (real(*sample)>0);
}


/**********************************************************/

constellation_16qam::sptr
constellation_16qam::make() {
	return constellation_16qam::sptr(new constellation_16qam_impl());
}

constellation_16qam::constellation_16qam() {}

constellation_16qam_impl::constellation_16qam_impl()
{
	const float level = sqrt(float(0.1));
	d_constellation.resize(16);

	d_constellation[ 0] = gr_complex(-3*level,-3*level);
	d_constellation[ 1] = gr_complex( 3*level,-3*level);
	d_constellation[ 2] = gr_complex(-1*level,-3*level);
	d_constellation[ 3] = gr_complex( 1*level,-3*level);
	d_constellation[ 4] = gr_complex(-3*level, 3*level);
	d_constellation[ 5] = gr_complex( 3*level, 3*level);
	d_constellation[ 6] = gr_complex(-1*level, 3*level);
	d_constellation[ 7] = gr_complex( 1*level, 3*level);
	d_constellation[ 8] = gr_complex(-3*level,-1*level);
	d_constellation[ 9] = gr_complex( 3*level,-1*level);
	d_constellation[10] = gr_complex(-1*level,-1*level);
	d_constellation[11] = gr_complex( 1*level,-1*level);
	d_constellation[12] = gr_complex(-3*level, 1*level);
	d_constellation[13] = gr_complex( 3*level, 1*level);
	d_constellation[14] = gr_complex(-1*level, 1*level);
	d_constellation[15] = gr_complex( 1*level, 1*level);

	d_rotational_symmetry = 4;
	d_dimensionality = 1;
	calc_arity();
}

constellation_16qam_impl::~constellation_16qam_impl() {
}

unsigned int
constellation_16qam_impl::decision_maker(const gr_complex *sample)
{
	unsigned int ret = 0;
	const float level = sqrt(float(0.1));
	float re = sample->real();
	float im = sample->imag();

	ret |= re > 0;
	ret |= (std::abs(re) < (2*level)) << 1;
	ret |= (im > 0) << 2;
	ret |= (std::abs(im) < (2*level)) << 3;

	return ret;
}


/**********************************************************/

constellation_64qam::sptr
constellation_64qam::make() {
	return constellation_64qam::sptr(new constellation_64qam_impl());
}

constellation_64qam::constellation_64qam() {}

constellation_64qam_impl::constellation_64qam_impl() {
	const float level = sqrt(float(1/42.0));
	d_constellation.resize(64);

	d_constellation[ 0] = gr_complex(-7*level,-7*level);
	d_constellation[ 1] = gr_complex( 7*level,-7*level);
	d_constellation[ 2] = gr_complex(-1*level,-7*level);
	d_constellation[ 3] = gr_complex( 1*level,-7*level);
	d_constellation[ 4] = gr_complex(-5*level,-7*level);
	d_constellation[ 5] = gr_complex( 5*level,-7*level);
	d_constellation[ 6] = gr_complex(-3*level,-7*level);
	d_constellation[ 7] = gr_complex( 3*level,-7*level);
	d_constellation[ 8] = gr_complex(-7*level, 7*level);
	d_constellation[ 9] = gr_complex( 7*level, 7*level);
	d_constellation[10] = gr_complex(-1*level, 7*level);
	d_constellation[11] = gr_complex( 1*level, 7*level);
	d_constellation[12] = gr_complex(-5*level, 7*level);
	d_constellation[13] = gr_complex( 5*level, 7*level);
	d_constellation[14] = gr_complex(-3*level, 7*level);
	d_constellation[15] = gr_complex( 3*level, 7*level);
	d_constellation[16] = gr_complex(-7*level,-1*level);
	d_constellation[17] = gr_complex( 7*level,-1*level);
	d_constellation[18] = gr_complex(-1*level,-1*level);
	d_constellation[19] = gr_complex( 1*level,-1*level);
	d_constellation[20] = gr_complex(-5*level,-1*level);
	d_constellation[21] = gr_complex( 5*level,-1*level);
	d_constellation[22] = gr_complex(-3*level,-1*level);
	d_constellation[23] = gr_complex( 3*level,-1*level);
	d_constellation[24] = gr_complex(-7*level, 1*level);
	d_constellation[25] = gr_complex( 7*level, 1*level);
	d_constellation[26] = gr_complex(-1*level, 1*level);
	d_constellation[27] = gr_complex( 1*level, 1*level);
	d_constellation[28] = gr_complex(-5*level, 1*level);
	d_constellation[29] = gr_complex( 5*level, 1*level);
	d_constellation[30] = gr_complex(-3*level, 1*level);
	d_constellation[31] = gr_complex( 3*level, 1*level);
	d_constellation[32] = gr_complex(-7*level,-5*level);
	d_constellation[33] = gr_complex( 7*level,-5*level);
	d_constellation[34] = gr_complex(-1*level,-5*level);
	d_constellation[35] = gr_complex( 1*level,-5*level);
	d_constellation[36] = gr_complex(-5*level,-5*level);
	d_constellation[37] = gr_complex( 5*level,-5*level);
	d_constellation[38] = gr_complex(-3*level,-5*level);
	d_constellation[39] = gr_complex( 3*level,-5*level);
	d_constellation[40] = gr_complex(-7*level, 5*level);
	d_constellation[41] = gr_complex( 7*level, 5*level);
	d_constellation[42] = gr_complex(-1*level, 5*level);
	d_constellation[43] = gr_complex( 1*level, 5*level);
	d_constellation[44] = gr_complex(-5*level, 5*level);
	d_constellation[45] = gr_complex( 5*level, 5*level);
	d_constellation[46] = gr_complex(-3*level, 5*level);
	d_constellation[47] = gr_complex( 3*level, 5*level);
	d_constellation[48] = gr_complex(-7*level,-3*level);
	d_constellation[49] = gr_complex( 7*level,-3*level);
	d_constellation[50] = gr_complex(-1*level,-3*level);
	d_constellation[51] = gr_complex( 1*level,-3*level);
	d_constellation[52] = gr_complex(-5*level,-3*level);
	d_constellation[53] = gr_complex( 5*level,-3*level);
	d_constellation[54] = gr_complex(-3*level,-3*level);
	d_constellation[55] = gr_complex( 3*level,-3*level);
	d_constellation[56] = gr_complex(-7*level, 3*level);
	d_constellation[57] = gr_complex( 7*level, 3*level);
	d_constellation[58] = gr_complex(-1*level, 3*level);
	d_constellation[59] = gr_complex( 1*level, 3*level);
	d_constellation[60] = gr_complex(-5*level, 3*level);
	d_constellation[61] = gr_complex( 5*level, 3*level);
	d_constellation[62] = gr_complex(-3*level, 3*level);
	d_constellation[63] = gr_complex( 3*level, 3*level);

	d_rotational_symmetry = 4;
	d_dimensionality = 1;
	calc_arity();
}

constellation_64qam_impl::~constellation_64qam_impl() {
}

unsigned int
constellation_64qam_impl::decision_maker(const gr_complex *sample) {
	unsigned int ret = 0;
	const float level = sqrt(float(1/42.0));
	float re = sample->real();
	float im = sample->imag();

	ret |= re > 0;
	ret |= (std::abs(re) < (4*level)) << 1;
	ret |= (std::abs(re) < (6*level) && std::abs(re) > (2*level)) << 2;
	ret |= (im > 0) << 3;
	ret |= (std::abs(im) < (4*level)) << 4;
	ret |= (std::abs(im) < (6*level) && std::abs(im) > (2*level)) << 5;

	return ret;
}
