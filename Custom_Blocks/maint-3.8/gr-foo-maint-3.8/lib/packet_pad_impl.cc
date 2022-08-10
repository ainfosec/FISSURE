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
#include "packet_pad_impl.h"

#include <gnuradio/io_signature.h>
#include <iostream>
#include <sys/time.h>
#ifdef FOO_UHD
#include <uhd/types/time_spec.hpp>
#endif

using namespace gr::foo;

#define dout d_debug && std::cout

packet_pad_impl::packet_pad_impl(bool debug, bool delay, double delay_sec,
		unsigned int pad_front, unsigned int pad_tail) : block("packet_pad",
			gr::io_signature::make(1, 1, sizeof(gr_complex)),
			gr::io_signature::make(1, 1, sizeof(gr_complex))),
			d_debug(debug),
			d_pad_front(pad_front),
			d_pad_tail(pad_tail),
			d_pad(0),
			d_eob(false),
			d_delay(delay),
			d_delay_sec(delay_sec) {

	set_relative_rate(1);
	set_tag_propagation_policy(block::TPP_DONT);
}

packet_pad_impl::~packet_pad_impl(){
}

void
packet_pad_impl::add_sob(uint64_t item) {
	dout << "PACKET PAD: insert sob at: " << item << std::endl;

	static const pmt::pmt_t sob_key = pmt::string_to_symbol("tx_sob");
	static const pmt::pmt_t value = pmt::PMT_T;
	static const pmt::pmt_t srcid = pmt::string_to_symbol(alias());
	add_item_tag(0, item, sob_key, value, srcid);

	#ifdef FOO_UHD
	if(d_delay) {
		static const pmt::pmt_t time_key = pmt::string_to_symbol("tx_time");
		struct timeval t;
		gettimeofday(&t, NULL);
		uhd::time_spec_t now = uhd::time_spec_t(t.tv_sec + t.tv_usec / 1000000.0)
			+ uhd::time_spec_t(d_delay_sec);

		const pmt::pmt_t time_value = pmt::make_tuple(
			pmt::from_uint64(now.get_full_secs()),
			pmt::from_double(now.get_frac_secs())
		);
		add_item_tag(0, item, time_key, time_value, srcid);
	}
	#endif
}

void
packet_pad_impl::add_eob(uint64_t item) {
	dout << "PACKET PAD: insert eob at: " << item << std::endl;

	static const pmt::pmt_t eob_key = pmt::string_to_symbol("tx_eob");
	static const pmt::pmt_t value = pmt::PMT_T;
	static const pmt::pmt_t srcid = pmt::string_to_symbol(alias());
	add_item_tag(0, item, eob_key, value, srcid);
}

int
packet_pad_impl::general_work (int noutput_items, gr_vector_int& ninput_items,
		gr_vector_const_void_star& input_items,
		gr_vector_void_star& output_items) {

	const gr_complex *in = (const gr_complex*)input_items[0];
	gr_complex *out = (gr_complex*)output_items[0];

	int ninput = ninput_items[0];
	int noutput = noutput_items;

	dout << "call: pad " << d_pad << "   ninput " << ninput << "  noutput " << noutput << std::endl;

	// pad zeros
	if(d_pad) {
		int n = std::min(d_pad, noutput);
		std::memset(out, 0, n * sizeof(gr_complex));
		d_pad -= n;

		dout << "padded zeros: " << n << std::endl;

		// add end of burst tag
		if(!d_pad && d_eob) {
			d_eob = false;
			add_eob(nitems_written(0) + n - 1);
		}
		return n;
	}

	// search for tags
	const uint64_t nread = this->nitems_read(0);
	std::vector<gr::tag_t> tags;
	get_tags_in_range(tags, 0, nread, nread + ninput);
	std::sort(tags.begin(), tags.end(), tag_t::offset_compare);

	uint64_t n = std::min(ninput, noutput);

	if(tags.size()) {
		tag_t t = tags[0];

		dout << "found tag: " << pmt::symbol_to_string(t.key) << std::endl;

		uint64_t read = nitems_read(0);
		if(t.offset != read) {
			dout << "tag does not start at current offset" << std::endl;
			n = std::min(n, t.offset - read);

		} else {
			if(pmt::equal(t.key, pmt::mp("tx_sob"))) {
				dout << "tx_sob tag" << std::endl;
				add_sob(nitems_written(0));
				d_pad = d_pad_front;
				remove_item_tag(0, t);
				return 0;


			} else if(pmt::equal(t.key, pmt::mp("tx_eob"))) {
				dout << "tx_eob tag" << std::endl;
				d_pad = d_pad_tail;
				d_eob = true;
				if(n) {

					if(!d_pad) {
						add_eob(nitems_written(0));
						d_eob = false;
					}
					memcpy(out, in, sizeof(gr_complex));
					consume(0, 1);
					return 1;
				}
				return 0;

			} else {
				dout << "unknown tag" << std::endl;
				if(tags.size() > 1) {
					n = std::min(n, tags[1].offset - read);
				}
			}
		}
	}

	dout << "copying : " << n << std::endl;

	std::memcpy(out, in, n * sizeof(gr_complex));
	consume(0, n);
	return n;
}

void
packet_pad_impl::forecast (int noutput_items, gr_vector_int &ninput_items_required)
{

	if(d_pad) {
		ninput_items_required[0] = 0;
	} else {
		ninput_items_required[0] = noutput_items;
	}
}

packet_pad::sptr
packet_pad::make(bool debug, bool delay, double delay_sec, unsigned int pad_front, unsigned int pad_tail) {
	return gnuradio::get_initial_sptr(new packet_pad_impl(debug, delay, delay_sec, pad_front, pad_tail));
}
