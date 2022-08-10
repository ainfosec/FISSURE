/*
 * Copyright 2013 Bastian Bloessl<bloessl@ccs-labs.org>.
 *
 * This is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3, or (at your option)
 * any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this software; see the file COPYING.  If not, write to
 * the Free Software Foundation, Inc., 51 Franklin Street,
 * Boston, MA 02110-1301, USA.
 */

#include "burst_tagger_impl.h"

#include <gnuradio/io_signature.h>
#include <boost/format.hpp>

namespace gr {
namespace foo {

burst_tagger_impl::burst_tagger_impl(pmt::pmt_t tag_name,
		unsigned int mult)
		: gr::sync_block("burst_tagger",
			gr::io_signature::make(1, 1, sizeof(gr_complex)),
			gr::io_signature::make(1, 1, sizeof(gr_complex))),
		d_tag_name(tag_name),
		d_copy(0),
		d_mult(mult) {

	if(!d_mult) {
		throw std::out_of_range("multiplier must be > 0");
	}
}

burst_tagger_impl::~burst_tagger_impl() {
}

void
burst_tagger_impl::add_sob(uint64_t item) {
	static const pmt::pmt_t sob_key = pmt::string_to_symbol("tx_sob");
	static const pmt::pmt_t value = pmt::PMT_T;
	static const pmt::pmt_t srcid = pmt::string_to_symbol(alias());
	add_item_tag(0, item, sob_key, value, srcid);
}


void
burst_tagger_impl::add_eob(uint64_t item) {
	static const pmt::pmt_t eob_key = pmt::string_to_symbol("tx_eob");
	static const pmt::pmt_t value = pmt::PMT_T;
	static const pmt::pmt_t srcid = pmt::string_to_symbol(alias());
	add_item_tag(0, item, eob_key, value, srcid);
}


int
burst_tagger_impl::work(int noutput_items,
	gr_vector_const_void_star &input_items,
	gr_vector_void_star &output_items) {

	const gr_complex *in = (const gr_complex*)input_items[0];
	gr_complex *out = (gr_complex*)output_items[0];


	if(!d_copy) {
		std::vector<gr::tag_t> tags;
		const uint64_t nread = nitems_read(0);

		get_tags_in_range(tags, 0, nread, nread + noutput_items, d_tag_name);
		std::sort(tags.begin(), tags.end(), tag_t::offset_compare);

		// copy until the first tag
		if(tags.size()) {
			tag_t tag = tags.front();
			if(tag.offset == nitems_read(0)) {
				d_copy = pmt::to_uint64(tag.value) * d_mult;
				add_sob(nitems_written(0));
			} else {
				uint64_t cpy = std::min((uint64_t)noutput_items, tag.offset - nitems_written(0));
				std::memcpy(out, in, cpy * sizeof(gr_complex));
				return cpy;
			}
		}
	}

	if(d_copy) {
		int cpy = std::min(d_copy, noutput_items);
		std::memcpy(out, in, cpy * sizeof(gr_complex));
		d_copy -= cpy;
		if(d_copy == 0) {
			add_eob(nitems_written(0) + cpy - 1);
		}
		return cpy;
	} else {
		std::memcpy(out, in, noutput_items * sizeof(gr_complex));
		return noutput_items;
	}
}

burst_tagger::sptr burst_tagger::make(pmt::pmt_t tag_name, unsigned int mult) {
	return gnuradio::get_initial_sptr(new burst_tagger_impl(tag_name, mult));
}


} /* namespace foo */
} /* namespace gr */

