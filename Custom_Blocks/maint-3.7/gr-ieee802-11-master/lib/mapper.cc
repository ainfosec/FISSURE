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
#include <ieee802-11/mapper.h>
#include "utils.h"
#include <gnuradio/io_signature.h>

using namespace gr::ieee802_11;


class mapper_impl : public mapper {
public:

static const int DATA_CARRIERS = 48;

mapper_impl(Encoding e, bool debug) :
	block ("mapper",
			gr::io_signature::make(0, 0, 0),
			gr::io_signature::make(1, 1, sizeof(char))),
			d_symbols_offset(0),
			d_symbols(NULL),
			d_debug(debug),
			d_scrambler(1),
			d_ofdm(e) {

	message_port_register_in(pmt::mp("in"));
	set_encoding(e);
}

~mapper_impl() {
	free(d_symbols);
}

void print_message(const char *msg, size_t len) {


	dout << std::hex << "MAPPER input symbols" << std::endl
		<< "===========================" << std::endl;

	for(int i = 0; i < len; i++) {
		dout << std::hex << (int)msg[i] << " ";
	}

	dout << std::dec << std::endl;
}


int general_work(int noutput, gr_vector_int& ninput_items,
			gr_vector_const_void_star& input_items,
			gr_vector_void_star& output_items ) {

	unsigned char *out = (unsigned char*)output_items[0];
	dout << "MAPPER called offset: " << d_symbols_offset <<
		"   length: " << d_symbols_len << std::endl;

	while(!d_symbols_offset) {
		pmt::pmt_t msg(delete_head_nowait(pmt::intern("in")));

		if(!msg.get()) {
			return 0;
		}

		if(pmt::is_pair(msg)) {
			dout << "MAPPER: received new message" << std::endl;
			gr::thread::scoped_lock lock(d_mutex);

			int psdu_length = pmt::blob_length(pmt::cdr(msg));
			const char *psdu = static_cast<const char*>(pmt::blob_data(pmt::cdr(msg)));

			// ############ INSERT MAC STUFF
			frame_param frame(d_ofdm, psdu_length);
			if(frame.n_sym > MAX_SYM) {
				std::cout << "packet too large, maximum number of symbols is " << MAX_SYM << std::endl;
				return 0;
			}

			//alloc memory for modulation steps
			char *data_bits        = (char*)calloc(frame.n_data_bits, sizeof(char));
			char *scrambled_data   = (char*)calloc(frame.n_data_bits, sizeof(char));
			char *encoded_data     = (char*)calloc(frame.n_data_bits * 2, sizeof(char));
			char *punctured_data   = (char*)calloc(frame.n_encoded_bits, sizeof(char));
			char *interleaved_data = (char*)calloc(frame.n_encoded_bits, sizeof(char));
			char *symbols          = (char*)calloc((frame.n_encoded_bits / d_ofdm.n_bpsc), sizeof(char));

			//generate the WIFI data field, adding service field and pad bits
			generate_bits(psdu, data_bits, frame);

			// scrambling
			scramble(data_bits, scrambled_data, frame, d_scrambler++);
			if(d_scrambler > 127) {
				d_scrambler = 1;
			}

			// reset tail bits
			reset_tail_bits(scrambled_data, frame);
			// encoding
			convolutional_encoding(scrambled_data, encoded_data, frame);
			// puncturing
			puncturing(encoded_data, punctured_data, frame, d_ofdm);
			//std::cout << "punctured" << std::endl;
			// interleaving
			interleave(punctured_data, interleaved_data, frame, d_ofdm);
			//std::cout << "interleaved" << std::endl;

			// one byte per symbol
			split_symbols(interleaved_data, symbols, frame, d_ofdm);

			d_symbols_len = frame.n_sym * 48;

			d_symbols = (char*)calloc(d_symbols_len, 1);
			std::memcpy(d_symbols, symbols, d_symbols_len);


			// add tags
			pmt::pmt_t key = pmt::string_to_symbol("packet_len");
			pmt::pmt_t value = pmt::from_long(d_symbols_len);
			pmt::pmt_t srcid = pmt::string_to_symbol(alias());
			add_item_tag(0, nitems_written(0), key, value, srcid);

			pmt::pmt_t psdu_bytes = pmt::from_long(psdu_length);
			add_item_tag(0, nitems_written(0), pmt::mp("psdu_len"),
					psdu_bytes, srcid);

			pmt::pmt_t encoding = pmt::from_long(d_ofdm.encoding);
			add_item_tag(0, nitems_written(0), pmt::mp("encoding"),
					encoding, srcid);


			free(data_bits);
			free(scrambled_data);
			free(encoded_data);
			free(punctured_data);
			free(interleaved_data);
			free(symbols);

			break;
		}
	}

	int i = std::min(noutput, d_symbols_len - d_symbols_offset);
	std::memcpy(out, d_symbols + d_symbols_offset, i);
	d_symbols_offset += i;

	if(d_symbols_offset == d_symbols_len) {
		d_symbols_offset = 0;
		free(d_symbols);
		d_symbols = 0;
	}

	return i;
}

void set_encoding(Encoding encoding) {

	std::cout << "MAPPER: encoding: " << encoding << std::endl;
	gr::thread::scoped_lock lock(d_mutex);

	d_ofdm = ofdm_param(encoding);
}

private:
	uint8_t      d_scrambler;
	bool         d_debug;
	char*        d_symbols;
	int          d_symbols_offset;
	int          d_symbols_len;
	ofdm_param   d_ofdm;
	gr::thread::mutex d_mutex;
};

mapper::sptr
mapper::make(Encoding mcs, bool debug) {
	return gnuradio::get_initial_sptr(new mapper_impl(mcs, debug));
}
