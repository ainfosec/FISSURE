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
#include <foo/packet_pad2.h>

#include <gnuradio/io_signature.h>
#include <sys/time.h>
#ifdef FOO_UHD
#include <uhd/types/time_spec.hpp>
#endif

using namespace gr::foo;


class packet_pad2_impl : public packet_pad2 {

public:
packet_pad2_impl(bool debug, bool delay, double delay_sec, unsigned int pad_front, unsigned int pad_tail) : tagged_stream_block("foo_packet_pad2",
			gr::io_signature::make(1, 1, sizeof(gr_complex)),
			gr::io_signature::make(1, 1, sizeof(gr_complex)),
			"packet_len"),
			d_debug(debug),
			d_delay(delay),
			d_delay_sec(delay_sec),
			d_pad_front(pad_front),
			d_pad_tail(pad_tail) {
	set_tag_propagation_policy(block::TPP_DONT);
}

~packet_pad2_impl(){
}

int calculate_output_stream_length(const gr_vector_int &ninput_items) {
	return ninput_items[0] + d_pad_front + d_pad_tail;
}

int work (int noutput_items, gr_vector_int& ninput_items,
		gr_vector_const_void_star& input_items,
		gr_vector_void_star& output_items) {

	const gr_complex *in = (const gr_complex*)input_items[0];
	gr_complex *out = (gr_complex*)output_items[0];

	std::memset(out, 0x00, sizeof(gr_complex) * (ninput_items[0] + d_pad_front + d_pad_tail));

	std::memcpy(out + d_pad_front, in, sizeof(gr_complex) * ninput_items[0]);


	int produced = ninput_items[0] + d_pad_front + d_pad_tail;
	const pmt::pmt_t src = pmt::string_to_symbol(alias());

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
		add_item_tag(0, nitems_written(0), time_key, time_value, src);
	}
	#endif

	std::vector<gr::tag_t> tags;
	get_tags_in_range(tags, 0, nitems_read(0), nitems_read(0) + ninput_items[0]);
	for (size_t i = 0; i < tags.size(); i++) {
		add_item_tag(0, nitems_written(0),
		tags[i].key,
		tags[i].value);
	}

	return produced;
}

private:
	bool   d_debug;
	bool   d_delay;
	double d_delay_sec;
	unsigned int d_pad_front;
	unsigned int d_pad_tail;
};

packet_pad2::sptr
packet_pad2::make(bool debug, bool delay, double delay_sec, unsigned int pad_front, unsigned int pad_tail) {
	return gnuradio::get_initial_sptr(new packet_pad2_impl(debug, delay, delay_sec, pad_front, pad_tail));
}
