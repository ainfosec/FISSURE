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
#include "ether_encap_impl.h"
#include "utils.h"

#include <gnuradio/io_signature.h>
#include <gnuradio/block_detail.h>
#include <string>

using namespace gr::ieee802_11;

ether_encap_impl::ether_encap_impl(bool debug) :
		block("ether_encap",
				gr::io_signature::make(0, 0, 0),
				gr::io_signature::make(0, 0, 0)),
		d_debug(debug),
		d_last_seq(123) {

    message_port_register_out(pmt::mp("to tap"));
    message_port_register_out(pmt::mp("to wifi"));

    message_port_register_in(pmt::mp("from tap"));
    set_msg_handler(pmt::mp("from tap"), boost::bind(&ether_encap_impl::from_tap, this, _1));
    message_port_register_in(pmt::mp("from wifi"));
    set_msg_handler(pmt::mp("from wifi"), boost::bind(&ether_encap_impl::from_wifi, this, _1));
}

void
ether_encap_impl::from_wifi(pmt::pmt_t msg) {

	msg = pmt::cdr(msg);

	int data_len = pmt::blob_length(msg);
	const mac_header *mhdr = reinterpret_cast<const mac_header*>(pmt::blob_data(msg));

	if(d_last_seq == mhdr->seq_nr) {
		dout << "Ether Encap: frame already seen -- skipping" << std::endl;
		return;
	}

	d_last_seq = mhdr->seq_nr;


	if(data_len < 33) {
		dout << "Ether Encap: frame too short to parse (<33)" << std::endl;
		return;
	}

	// this is more than needed
	char *buf = static_cast<char*>(std::malloc(data_len + sizeof(ethernet_header)));
	ethernet_header *ehdr = reinterpret_cast<ethernet_header*>(buf);

        if(((mhdr->frame_control >> 2) & 3) != 2) {
		dout << "this is not a data frame -- ignoring" << std::endl;
		return;
	}

	std::memcpy(ehdr->dest, mhdr->addr1, 6);
	std::memcpy(ehdr->src, mhdr->addr2, 6);
	ehdr->type = 0x0008;

	char *frame = (char*)pmt::blob_data(msg);

	// DATA
	if((((mhdr->frame_control) >> 2) & 63) == 2) {
		memcpy(buf + sizeof(ethernet_header), frame + 32, data_len - 32);
		pmt::pmt_t payload = pmt::make_blob(buf, data_len - 32 + 14);
		message_port_pub(pmt::mp("to tap"), pmt::cons(pmt::PMT_NIL, payload));

	// QoS Data
	} else if((((mhdr->frame_control) >> 2) & 63) == 34) {

		memcpy(buf + sizeof(ethernet_header), frame + 34, data_len - 34);
		pmt::pmt_t payload = pmt::make_blob(buf, data_len - 34 + 14);
		message_port_pub(pmt::mp("to tap"), pmt::cons(pmt::PMT_NIL, payload));
	}

	free(buf);
}

void
ether_encap_impl::from_tap(pmt::pmt_t msg) {
	size_t len = pmt::blob_length(pmt::cdr(msg));
	const char* data = static_cast<const char*>(pmt::blob_data(pmt::cdr(msg)));

	const ethernet_header *ehdr = reinterpret_cast<const ethernet_header*>(data);

	switch(ehdr->type) {
	case 0x0008: {
		std::cout << "ether type: IP" << std::endl;

		char *buf = static_cast<char*>(malloc(len + 8 - sizeof(ethernet_header)));
		buf[0] = 0xaa;
		buf[1] = 0xaa;
		buf[2] = 0x03;
		buf[3] = 0x00;
		buf[4] = 0x00;
		buf[5] = 0x00;
		buf[6] = 0x08;
		buf[7] = 0x00;
		std::memcpy(buf + 8, data + sizeof(ethernet_header), len - sizeof(ethernet_header));
		pmt::pmt_t blob = pmt::make_blob(buf, len + 8 - sizeof(ethernet_header));
		message_port_pub(pmt::mp("to wifi"), pmt::cons(pmt::PMT_NIL, blob));
		break;
	}
	case 0x0608:
		std::cout << "ether type: ARP " << std::endl;
		break;
	default:
		std::cout << "unknown ether type" << std::endl;
		break;
	}

}

ether_encap::sptr
ether_encap::make(bool debug) {
	return gnuradio::get_initial_sptr(new ether_encap_impl(debug));
}

