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
#include <ieee802_15_4/mac.h>
#include <gnuradio/io_signature.h>
#include <gnuradio/block_detail.h>

#include <iostream>
#include <iomanip>

using namespace gr::ieee802_15_4;

class mac_impl : public mac {
public:

#define dout d_debug && std::cout

mac_impl(bool debug, int fcf, int seq_nr, int dst_pan, int dst, int src) :
	block ("mac",
			gr::io_signature::make(0, 0, 0),
			gr::io_signature::make(0, 0, 0)),
	d_msg_offset(0),
	d_debug(debug),
	d_fcf(fcf),
	d_seq_nr(seq_nr),
	d_dst_pan(dst_pan),
	d_dst(dst),
	d_src(src),
	d_num_packet_errors(0),
	d_num_packets_received(0) {

	message_port_register_in(pmt::mp("app in"));
	set_msg_handler(pmt::mp("app in"), boost::bind(&mac_impl::app_in, this, _1));
	message_port_register_in(pmt::mp("pdu in"));
	set_msg_handler(pmt::mp("pdu in"), boost::bind(&mac_impl::mac_in, this, _1));

	message_port_register_out(pmt::mp("app out"));
	message_port_register_out(pmt::mp("pdu out"));
}

~mac_impl(void) {
}

void mac_in(pmt::pmt_t msg) {
	pmt::pmt_t blob;

	if(pmt::is_pair(msg)) {
		blob = pmt::cdr(msg);
	} else {
		assert(false);
	}

	size_t data_len = pmt::blob_length(blob);
	if(data_len < 11) {
		dout << "MAC: frame too short. Dropping!" << std::endl;
		return;
	}

	uint16_t crc = crc16((char*)pmt::blob_data(blob), data_len);
	d_num_packets_received++;
	if(crc) {
		d_num_packet_errors++;
		dout << "MAC: wrong crc. Dropping packet!" << std::endl;
		return;
	}
	else{
		dout << "MAC: correct crc. Propagate packet to APP layer." << std::endl;
	}

	pmt::pmt_t mac_payload = pmt::make_blob((char*)pmt::blob_data(blob) + 9 , data_len - 9 - 2);

	message_port_pub(pmt::mp("app out"), pmt::cons(pmt::PMT_NIL, mac_payload));
}

void app_in(pmt::pmt_t msg) {
	pmt::pmt_t blob;
	if(pmt::is_eof_object(msg)) {
		dout << "MAC: exiting" << std::endl;
		detail().get()->set_done(true);
		return;
	} else if(pmt::is_blob(msg)) {
		blob = msg;
	} else if(pmt::is_pair(msg)) {
		blob = pmt::cdr(msg);
	} else {
		dout << "MAC: unknown input" << std::endl;
		return;
	}

	//dout << "MAC: received new message from APP of length " << pmt::blob_length(blob) << std::endl;

	generate_mac((const char*)pmt::blob_data(blob), pmt::blob_length(blob));
	//print_message();
	message_port_pub(pmt::mp("pdu out"), pmt::cons(pmt::PMT_NIL,
			pmt::make_blob(d_msg, d_msg_len)));
}

uint16_t crc16(char *buf, int len) {
	uint16_t crc = 0;

	for(int i = 0; i < len; i++) {
		for(int k = 0; k < 8; k++) {
			int input_bit = (!!(buf[i] & (1 << k)) ^ (crc & 1));
			crc = crc >> 1;
			if(input_bit) {
				crc ^= (1 << 15);
				crc ^= (1 << 10);
				crc ^= (1 <<  3);
			}
		}
	}

	return crc;
}

void generate_mac(const char *buf, int len) {

	// FCF
	// data frame, no security
	d_msg[0] = d_fcf & 0xFF;
	d_msg[1] = (d_fcf>>8) & 0xFF;

	// seq nr
	d_msg[2] = d_seq_nr++;

	// addr info
	d_msg[3] = d_dst_pan & 0xFF;
	d_msg[4] = (d_dst_pan>>8) & 0xFF;
	d_msg[5] = d_dst & 0xFF;
	d_msg[6] = (d_dst>>8) & 0xFF;
	d_msg[7] = d_src & 0xFF;
	d_msg[8] = (d_src>>8) & 0xFF;

	std::memcpy(d_msg + 9, buf, len);

	uint16_t crc = crc16(d_msg, len + 9);

	d_msg[ 9 + len] = crc & 0xFF;
	d_msg[10 + len] = crc >> 8;

	d_msg_len = 9 + len + 2;
}

void print_message() {
	for(int i = 0; i < d_msg_len; i++) {
		dout << std::setfill('0') << std::setw(2) << std::hex << ((unsigned int)d_msg[i] & 0xFF) << std::dec << " ";
		if(i % 16 == 15) {
			dout << std::endl;
		}
	}
	dout << std::endl;
}

int get_num_packet_errors(){ return d_num_packet_errors; }

int get_num_packets_received(){ return d_num_packets_received; }

float get_packet_error_ratio(){ return float(d_num_packet_errors)/d_num_packets_received; }

private:
	bool        d_debug;
	int         d_msg_offset;
	int         d_msg_len;
	uint16_t    d_fcf;
	uint8_t     d_seq_nr;
	uint16_t    d_dst_pan;
	uint16_t    d_dst;
	uint16_t    d_src;
	char        d_msg[256];

	int d_num_packet_errors;
	int d_num_packets_received;
};

mac::sptr
mac::make(bool debug, int fcf, int seq_nr, int dst_pan, int dst, int src) {
	return gnuradio::get_initial_sptr(new mac_impl(debug,fcf,seq_nr,dst_pan,dst,src));
}
