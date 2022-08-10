/*
 * Copyright (C) 2013, 2016 Bastian Bloessl <bloessl@ccs-labs.org>
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
#include <ieee802-11/sync_long.h>
#include "utils.h"
#include <gnuradio/io_signature.h>
#include <gnuradio/filter/fir_filter.h>
#include <gnuradio/fft/fft.h>

#include <list>
#include <tuple>

using namespace gr::ieee802_11;
using namespace std;


bool compare_abs(const std::pair<gr_complex, int>& first, const std::pair<gr_complex, int>& second) {
	return abs(get<0>(first)) > abs(get<0>(second));
}

class sync_long_impl : public sync_long {

public:
sync_long_impl(unsigned int sync_length, bool log, bool debug) : block("sync_long",
		gr::io_signature::make2(2, 2, sizeof(gr_complex), sizeof(gr_complex)),
		gr::io_signature::make(1, 1, sizeof(gr_complex))),
		d_fir(gr::filter::kernel::fir_filter_ccc(1, LONG)),
		d_log(log),
		d_debug(debug),
		d_offset(0),
		d_state(SYNC),
		SYNC_LENGTH(sync_length) {

	set_tag_propagation_policy(block::TPP_DONT);
	d_correlation = gr::fft::malloc_complex(8192);
}

~sync_long_impl(){
	gr::fft::free(d_correlation);
}

int general_work (int noutput, gr_vector_int& ninput_items,
		gr_vector_const_void_star& input_items,
		gr_vector_void_star& output_items) {

	const gr_complex *in = (const gr_complex*)input_items[0];
	const gr_complex *in_delayed = (const gr_complex*)input_items[1];
	gr_complex *out = (gr_complex*)output_items[0];

	dout << "LONG ninput[0] " << ninput_items[0] << "   ninput[1] " <<
			ninput_items[1] << "  noutput " << noutput <<
			"   state " << d_state << std::endl;

	int ninput = std::min(std::min(ninput_items[0], ninput_items[1]), 8192);

	const uint64_t nread = nitems_read(0);
	get_tags_in_range(d_tags, 0, nread, nread + ninput);
	if (d_tags.size()) {
		std::sort(d_tags.begin(), d_tags.end(), gr::tag_t::offset_compare);

		const uint64_t offset = d_tags.front().offset;

		if(offset > nread) {
			ninput = offset - nread;
		} else {
			if(d_offset && (d_state == SYNC)) {
				throw std::runtime_error("wtf");
			}
			if(d_state == COPY) {
				d_state = RESET;
			}
			d_freq_offset_short = pmt::to_double(d_tags.front().value);
		}
	}


	int i = 0;
	int o = 0;

	switch(d_state) {

	case SYNC:
		d_fir.filterN(d_correlation, in, std::min(SYNC_LENGTH, std::max(ninput - 63, 0)));

		while(i + 63 < ninput) {

			d_cor.push_back(pair<gr_complex, int>(d_correlation[i], d_offset));

			i++;
			d_offset++;

			if(d_offset == SYNC_LENGTH) {
				search_frame_start();
				mylog(boost::format("LONG: frame start at %1%") % d_frame_start);
				d_offset = 0;
				d_count = 0;
				d_state = COPY;

				break;
			}
		}

		break;

	case COPY:
		while(i < ninput && o < noutput) {

			int rel = d_offset - d_frame_start;

			if(!rel)  {
				add_item_tag(0, nitems_written(0),
						pmt::string_to_symbol("wifi_start"),
						pmt::from_double(d_freq_offset_short - d_freq_offset),
						pmt::string_to_symbol(name()));
			}

			if(rel >= 0 && (rel < 128 || ((rel - 128) % 80) > 15)) {
				out[o] = in_delayed[i] * exp(gr_complex(0, d_offset * d_freq_offset));
				o++;
			}

			i++;
			d_offset++;
		}

		break;

	case RESET: {
		while(o < noutput) {
			if(((d_count + o) % 64) == 0) {
				d_offset = 0;
				d_state = SYNC;
				break;
			} else {
				out[o] = 0;
				o++;
			}
		}

		break;
	}
	}

	dout << "produced : " << o << " consumed: " << i << std::endl;

	d_count += o;
	consume(0, i);
	consume(1, i);
	return o;
}

void forecast (int noutput_items, gr_vector_int &ninput_items_required) {

	// in sync state we need at least a symbol to correlate
	// with the pattern
	if(d_state == SYNC) {
		ninput_items_required[0] = 64;
		ninput_items_required[1] = 64;

	} else {
		ninput_items_required[0] = noutput_items;
		ninput_items_required[1] = noutput_items;
	}
}

void search_frame_start() {

	// sort list (highest correlation first)
	assert(d_cor.size() == SYNC_LENGTH);
	d_cor.sort(compare_abs);

	// copy list in vector for nicer access
	vector<pair<gr_complex, int> > vec(d_cor.begin(), d_cor.end());
	d_cor.clear();

	// in case we don't find anything use SYNC_LENGTH
	d_frame_start = SYNC_LENGTH;

	for(int i = 0; i < 3; i++) {
		for(int k = i + 1; k < 4; k++) {
			gr_complex first;
			gr_complex second;
			if(get<1>(vec[i]) > get<1>(vec[k])) {
				first = get<0>(vec[k]);
				second = get<0>(vec[i]);
			} else {
				first = get<0>(vec[i]);
				second = get<0>(vec[k]);
			}
			int diff  = abs(get<1>(vec[i]) - get<1>(vec[k]));
			if(diff == 64) {
				d_frame_start = min(get<1>(vec[i]), get<1>(vec[k]));
				d_freq_offset = arg(first * conj(second)) / 64;
				// nice match found, return immediately
				return;

			} else if(diff == 63) {
				d_frame_start = min(get<1>(vec[i]), get<1>(vec[k]));
				d_freq_offset = arg(first * conj(second)) / 63;
			} else if(diff == 65) {
				d_frame_start = min(get<1>(vec[i]), get<1>(vec[k]));
				d_freq_offset = arg(first * conj(second)) / 65;
			}
		}
	}
}

private:
	enum {SYNC, COPY, RESET} d_state;
	int         d_count;
	int         d_offset;
	int         d_frame_start;
	float       d_freq_offset;
	double      d_freq_offset_short;

	gr_complex *d_correlation;
	list<pair<gr_complex, int> > d_cor;
	std::vector<gr::tag_t> d_tags;
	gr::filter::kernel::fir_filter_ccc d_fir;

	const bool d_log;
	const bool d_debug;
	const int  SYNC_LENGTH;

	static const std::vector<gr_complex> LONG;
};

sync_long::sptr
sync_long::make(unsigned int sync_length, bool log, bool debug) {
	return gnuradio::get_initial_sptr(new sync_long_impl(sync_length, log, debug));
}

const std::vector<gr_complex> sync_long_impl::LONG = {

gr_complex(-0.0455, -1.0679), gr_complex( 0.3528, -0.9865), gr_complex( 0.8594,  0.7348), gr_complex( 0.1874,  0.2475),
gr_complex( 0.5309, -0.7784), gr_complex(-1.0218, -0.4897), gr_complex(-0.3401, -0.9423), gr_complex( 0.8657, -0.2298),
gr_complex( 0.4734,  0.0362), gr_complex( 0.0088, -1.0207), gr_complex(-1.2142, -0.4205), gr_complex( 0.2172, -0.5195),
gr_complex( 0.5207, -0.1326), gr_complex(-0.1995,  1.4259), gr_complex( 1.0583, -0.0363), gr_complex( 0.5547, -0.5547),
gr_complex( 0.3277,  0.8728), gr_complex(-0.5077,  0.3488), gr_complex(-1.1650,  0.5789), gr_complex( 0.7297,  0.8197),
gr_complex( 0.6173,  0.1253), gr_complex(-0.5353,  0.7214), gr_complex(-0.5011, -0.1935), gr_complex(-0.3110, -1.3392),
gr_complex(-1.0818, -0.1470), gr_complex(-1.1300, -0.1820), gr_complex( 0.6663, -0.6571), gr_complex(-0.0249,  0.4773),
gr_complex(-0.8155,  1.0218), gr_complex( 0.8140,  0.9396), gr_complex( 0.1090,  0.8662), gr_complex(-1.3868, -0.0000),
gr_complex( 0.1090, -0.8662), gr_complex( 0.8140, -0.9396), gr_complex(-0.8155, -1.0218), gr_complex(-0.0249, -0.4773),
gr_complex( 0.6663,  0.6571), gr_complex(-1.1300,  0.1820), gr_complex(-1.0818,  0.1470), gr_complex(-0.3110,  1.3392),
gr_complex(-0.5011,  0.1935), gr_complex(-0.5353, -0.7214), gr_complex( 0.6173, -0.1253), gr_complex( 0.7297, -0.8197),
gr_complex(-1.1650, -0.5789), gr_complex(-0.5077, -0.3488), gr_complex( 0.3277, -0.8728), gr_complex( 0.5547,  0.5547),
gr_complex( 1.0583,  0.0363), gr_complex(-0.1995, -1.4259), gr_complex( 0.5207,  0.1326), gr_complex( 0.2172,  0.5195),
gr_complex(-1.2142,  0.4205), gr_complex( 0.0088,  1.0207), gr_complex( 0.4734, -0.0362), gr_complex( 0.8657,  0.2298),
gr_complex(-0.3401,  0.9423), gr_complex(-1.0218,  0.4897), gr_complex( 0.5309,  0.7784), gr_complex( 0.1874, -0.2475),
gr_complex( 0.8594, -0.7348), gr_complex( 0.3528,  0.9865), gr_complex(-0.0455,  1.0679), gr_complex( 1.3868, -0.0000),

};
