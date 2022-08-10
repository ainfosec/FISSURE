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
#ifndef INCLUDED_IEEE802_11_CONSTELLATIONS_IMPL_H
#define INCLUDED_IEEE802_11_CONSTELLATIONS_IMPL_H

#include <ieee802-11/constellations.h>

namespace gr {
namespace ieee802_11 {

class constellation_bpsk_impl : public constellation_bpsk
{
public:
	constellation_bpsk_impl();
	~constellation_bpsk_impl();

	unsigned int decision_maker(const gr_complex *sample);
};


class constellation_qpsk_impl : public constellation_qpsk
{
public:
	constellation_qpsk_impl();
	~constellation_qpsk_impl();

	unsigned int decision_maker(const gr_complex *sample);
};



class constellation_16qam_impl : public constellation_16qam
{
public:
	constellation_16qam_impl();
	~constellation_16qam_impl();

	unsigned int decision_maker(const gr_complex *sample);
};




class constellation_64qam_impl : public constellation_64qam
{
public:
	constellation_64qam_impl();
	~constellation_64qam_impl();

	unsigned int decision_maker(const gr_complex *sample);
};


} // namespace ieee802_11
} // namespace gr

#endif /* INCLUDED_IEEE802_11_CONSTELLATIONS_IMPL_H */
