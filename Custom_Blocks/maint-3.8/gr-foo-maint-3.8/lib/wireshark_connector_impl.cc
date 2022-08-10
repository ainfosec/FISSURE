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
#include "wireshark_connector_impl.h"
#include <foo/wireshark_connector.h>
#include <gnuradio/io_signature.h>
#include <gnuradio/block_detail.h>

#include <iostream>
#include <iomanip>
#include <sys/time.h>

using namespace gr::foo;


#define dout d_debug && std::cout

wireshark_connector_impl::wireshark_connector_impl(LinkType type, bool debug) :
	block ("wireshark_connector",
			gr::io_signature::make(0, 0, 0),
			gr::io_signature::make(1, 1, sizeof(uint8_t))),
			d_msg_offset(0),
			d_debug(debug),
			d_link(type) {

	message_port_register_in(pmt::mp("in"));

	d_msg_len = sizeof(pcap_file_hdr);
	d_msg = reinterpret_cast<char*>(std::malloc(d_msg_len));

	pcap_file_hdr *hdr   = reinterpret_cast<pcap_file_hdr*>(d_msg);
	hdr->magic_number  = 0xa1b2c3d4;
	hdr->version_major = 2;
	hdr->version_minor = 4;
	hdr->thiszone      = 0;
	hdr->sigfigs       = 0;
	hdr->snaplen       = 65535;
	hdr->network       = d_link;
}

void
wireshark_connector_impl::handle_pdu(pmt::pmt_t pdu) {

	// get current time
	struct timeval t;
	gettimeofday(&t, NULL);

	const char *buf = reinterpret_cast<const char*>(pmt::blob_data(pmt::cdr(pdu)));
	std::size_t len = pmt::blob_length(pmt::cdr(pdu));
	std::size_t offset = 0;

	switch(d_link) {

	case WIFI: {

		// if crc is included ignore last 4 bytes
		pmt::pmt_t dict = pmt::car(pdu);
		pmt::pmt_t crc_inc = pmt::dict_ref(dict, pmt::mp("crc_included"), pmt::PMT_NIL);
		if(pmt::is_bool(crc_inc) && pmt::is_true(crc_inc)) {
			len -= 4;
		}

		// pcap header
		d_msg = reinterpret_cast<char*>(std::malloc(
				len + sizeof(radiotap_hdr) + sizeof(pcap_hdr)));

		pcap_hdr *hdr = reinterpret_cast<pcap_hdr*>(d_msg);
		hdr->ts_sec   = t.tv_sec;
		hdr->ts_usec  = t.tv_usec;
		hdr->incl_len = len + sizeof(radiotap_hdr);
		hdr->orig_len = len + sizeof(radiotap_hdr);
		offset += sizeof(struct pcap_hdr);

		// check if rate is attached
		uint8_t rate = 12;
		pmt::pmt_t encoding = pmt::dict_ref(dict, pmt::mp("encoding"), pmt::PMT_NIL);
		if(pmt::is_uint64(encoding)) {
			rate = encoding_to_rate(pmt::to_uint64(encoding));
		}

		int snr = 42;
		if(pmt::dict_has_key(dict, pmt::mp("snr"))) {
			pmt::pmt_t s = pmt::dict_ref(dict, pmt::mp("snr"), pmt::PMT_NIL);
			if(pmt::is_number(s)) {
				snr = std::round(pmt::to_double(s));
			}
		}

		uint8_t signal = 0;
		uint8_t noise = 0;

		if(snr >= 0) {
			signal = snr;
			noise = 0;
		} else {
			signal = 0;
			noise = -1 * snr;
		}

		// radiotap header
		radiotap_hdr *rhdr = reinterpret_cast<radiotap_hdr*>(d_msg + offset);
		rhdr->version     = 0;
		rhdr->hdr_length  = sizeof(radiotap_hdr);
		rhdr->bitmap      = 0x0000086e;
		rhdr->flags       = 0;
		rhdr->rate        = rate;
		rhdr->channel     = 178;
		rhdr->signal      = signal;
		rhdr->noise       = noise;
		rhdr->antenna     = 1;
		offset += sizeof(struct radiotap_hdr);

		break;
	}

	case ZIGBEE: {

		d_msg = reinterpret_cast<char*>(std::malloc(
				len + sizeof(pcap_hdr)));

		pcap_hdr *hdr = reinterpret_cast<pcap_hdr*>(d_msg);
		hdr->ts_sec   = t.tv_sec;
		hdr->ts_usec  = t.tv_usec;
		hdr->incl_len = len;
		hdr->orig_len = len;
		offset += sizeof(pcap_hdr);
		break;
	}
	}

	memcpy(d_msg + offset, buf, len);
	d_msg_len = offset + len;
}

uint8_t
wireshark_connector_impl::encoding_to_rate(uint64_t encoding) {

	// rates in radiotab rate field
	// are in 0.5 Mbit/s steps
	switch(encoding) {
	case 0:
		return  6 * 2;
	case 1:
		return  9 * 2;
	case 2:
		return 12 * 2;
	case 3:
		return 18 * 2;
	case 4:
		return 24 * 2;
	case 5:
		return 36 * 2;
	case 6:
		return 48 * 2;
	case 7:
		return 54 * 2;
	}

	throw std::invalid_argument("wrong encoding");
	return 0;
}

int
wireshark_connector_impl::general_work(int noutput, gr_vector_int& ninput_items,
                gr_vector_const_void_star& input_items,
		gr_vector_void_star& output_items ) {

	gr_complex *out = (gr_complex*)output_items[0];

	if(!d_msg_len) {
		pmt::pmt_t msg(delete_head_nowait(pmt::mp("in")));

		if(!msg) {
			return 0;
		}

		if(pmt::is_eof_object(msg)) {
			dout << "WIRESHARK: exiting" << std::endl;
			return -1;
		} else if(pmt::is_pair(msg)) {
			dout << "WIRESHARK: received new message" << std::endl;
			dout << "message length " << pmt::blob_length(pmt::cdr(msg)) << std::endl;
			handle_pdu(msg);
		} else {
			dout << "WIRESHARK: ignoring message" << std::endl;
			return 0;
		}
	}

	int to_copy = std::min((d_msg_len - d_msg_offset), noutput);
	memcpy(out, d_msg + d_msg_offset, to_copy);

	dout << "WIRESHARK: d_msg_offset: " <<  d_msg_offset <<
		"   to_copy: " << to_copy << 
		"   d_msg_len " << d_msg_len << std::endl;

	d_msg_offset += to_copy;

	if(d_msg_offset == d_msg_len) {
		d_msg_offset = 0;
		d_msg_len = 0;
		std::free(d_msg);
	}

	dout << "WIRESHARK: output size: " <<  noutput <<
		"   produced items: " << to_copy << std::endl;
	return to_copy;
}

wireshark_connector::sptr
wireshark_connector::make(LinkType type, bool debug) {
	return gnuradio::get_initial_sptr(new wireshark_connector_impl(type, debug));
}
