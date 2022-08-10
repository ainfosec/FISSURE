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
#include "chunks_to_symbols_impl.h"
#include "utils.h"
#include <gnuradio/io_signature.h>
#include <gnuradio/tag_checker.h>
#include <assert.h>

using namespace gr::ieee802_11;

chunks_to_symbols::sptr
chunks_to_symbols::make()
{
	return gnuradio::get_initial_sptr(new chunks_to_symbols_impl());
}

chunks_to_symbols_impl::chunks_to_symbols_impl() :
	tagged_stream_block("chunks_to_symbols",
			io_signature::make(1, 1, sizeof(char)),
			io_signature::make(1, 1, sizeof(gr_complex)), "packet_len") {

	d_bpsk = constellation_bpsk::make();
	d_qpsk = constellation_qpsk::make();
	d_16qam = constellation_16qam::make();
	d_64qam = constellation_64qam::make();

	d_mapping = d_bpsk;
}

chunks_to_symbols_impl::~chunks_to_symbols_impl() { }


int
chunks_to_symbols_impl::work(int noutput_items,
		gr_vector_int &ninput_items,
		gr_vector_const_void_star &input_items,
		gr_vector_void_star &output_items) {

	const unsigned char *in = (unsigned char*)input_items[0];
	gr_complex *out = (gr_complex*)output_items[0];

	std::vector<tag_t> tags;
	get_tags_in_range(tags, 0, nitems_read(0),
			nitems_read(0) + ninput_items[0],
			pmt::mp("encoding"));
	if(tags.size() != 1) {
		throw std::runtime_error("no encoding in input stream");
	}

	Encoding encoding = (Encoding)pmt::to_long(tags[0].value);

	switch (encoding) {
	case BPSK_1_2:
	case BPSK_3_4:
		d_mapping = d_bpsk;
		break;

	case QPSK_1_2:
	case QPSK_3_4:
		d_mapping = d_qpsk;
		break;

	case QAM16_1_2:
	case QAM16_3_4:
		d_mapping = d_16qam;
		break;

	case QAM64_2_3:
	case QAM64_3_4:
		d_mapping = d_64qam;
		break;

	default:
		throw std::invalid_argument("wrong encoding");
		break;
	}

	for(int i = 0; i < ninput_items[0]; i++) {
		d_mapping->map_to_points(in[i], out + i);
	}

	return ninput_items[0];
}
