/*
 * Copyright (C) 2013 Bastian Bloessl <bloessl@ccs-labs.org>
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
#ifndef INCLUDED_IEEE802_11_CHUNKS_TO_SYMBOLS_IMPL_H
#define INCLUDED_IEEE802_11_CHUNKS_TO_SYMBOLS_IMPL_H

#include <ieee802_11/chunks_to_symbols.h>
#include <ieee802_11/constellations.h>

namespace gr {
namespace ieee802_11 {

class chunks_to_symbols_impl : public chunks_to_symbols
{
public:
	chunks_to_symbols_impl();
	~chunks_to_symbols_impl();

	int work(int noutput_items,
			gr_vector_int &ninput_itmes,
			gr_vector_const_void_star &input_items,
			gr_vector_void_star &output_items);

private:
	boost::shared_ptr<gr::digital::constellation> d_mapping;
	constellation_bpsk::sptr d_bpsk;
	constellation_qpsk::sptr d_qpsk;
	constellation_16qam::sptr d_16qam;
	constellation_64qam::sptr d_64qam;
};

} /* namespace ieee802_11 */
} /* namespace gr */

#endif /* INCLUDED_IEEE802_11_CHUNKS_TO_SYMBOLS_IMPL_H */
