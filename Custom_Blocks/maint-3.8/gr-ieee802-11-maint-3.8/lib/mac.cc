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
#include <ieee802_11/mac.h>

#include <gnuradio/io_signature.h>
#include <gnuradio/block_detail.h>

#include "utils.h"

#if defined(__APPLE__)
#include <architecture/byte_order.h>
#define htole16(x) OSSwapHostToLittleInt16(x)
#else
#include <endian.h>
#endif

#include <boost/crc.hpp>
#include <iostream>
#include <stdexcept>

using namespace gr::ieee802_11;

class mac_impl : public mac {

public:

mac_impl(std::vector<uint8_t> src_mac, std::vector<uint8_t> dst_mac, std::vector<uint8_t> bss_mac) :
		block("mac",
			gr::io_signature::make(0, 0, 0),
			gr::io_signature::make(0, 0, 0)),
		d_seq_nr(0) {

	message_port_register_out(pmt::mp("phy out"));
	message_port_register_out(pmt::mp("app out"));

	message_port_register_in(pmt::mp("app in"));
	set_msg_handler(pmt::mp("app in"), boost::bind(&mac_impl::app_in, this, boost::placeholders::_1));

	message_port_register_in(pmt::mp("phy in"));
	set_msg_handler(pmt::mp("phy in"), boost::bind(&mac_impl::phy_in, this, boost::placeholders::_1));

	if(!check_mac(src_mac)) throw std::invalid_argument("wrong mac address size");
	if(!check_mac(dst_mac)) throw std::invalid_argument("wrong mac address size");
	if(!check_mac(bss_mac)) throw std::invalid_argument("wrong mac address size");

	for(int i = 0; i < 6; i++) {
		d_src_mac[i] = src_mac[i];
		d_dst_mac[i] = dst_mac[i];
		d_bss_mac[i] = bss_mac[i];
	}
}

void phy_in (pmt::pmt_t msg) {
	// this must be a pair
	if (!pmt::is_blob(pmt::cdr(msg))) {
		throw std::runtime_error("PMT must be blob");
	}

	// strip MAC header
	// TODO: check for frame type to determine header size
	pmt::pmt_t blob(pmt::cdr(msg));
	const char *mpdu = reinterpret_cast<const char *>(pmt::blob_data(blob));
	std::cout << "pdu len " << pmt::blob_length(blob) << std::endl;
	pmt::pmt_t msdu = pmt::make_blob(mpdu + 24, pmt::blob_length(blob) - 24);

	message_port_pub(pmt::mp("app out"), pmt::cons(pmt::car(msg), msdu));
}

void app_in (pmt::pmt_t msg) {

	size_t       msg_len;
	const char   *msdu;
	std::string  str;

	if(pmt::is_symbol(msg)) {

		str = pmt::symbol_to_string(msg);
		msg_len = str.length();
		msdu = str.data();

	} else if(pmt::is_pair(msg)) {

		msg_len = pmt::blob_length(pmt::cdr(msg));
		msdu = reinterpret_cast<const char *>(pmt::blob_data(pmt::cdr(msg)));

	} else {
		throw std::invalid_argument("MAC expects PDUs or strings");
		return;
	}

	if(msg_len > MAX_PAYLOAD_SIZE) {
		throw std::invalid_argument("Frame too large (> 1500)");
	}

	// make MAC frame
	int    psdu_length;
	generate_mac_data_frame(msdu, msg_len, &psdu_length);

	// dict
	pmt::pmt_t dict = pmt::make_dict();
	dict = pmt::dict_add(dict, pmt::mp("crc_included"), pmt::PMT_T);

	// blob
	pmt::pmt_t mac = pmt::make_blob(d_psdu, psdu_length);

	// pdu
	message_port_pub(pmt::mp("phy out"), pmt::cons(dict, mac));
}

void generate_mac_data_frame(const char *msdu, int msdu_size, int *psdu_size) {

	// mac header
	mac_header header;
	header.frame_control = 0x0008;
	header.duration = 0x0000;

	for(int i = 0; i < 6; i++) {
		header.addr1[i] = d_dst_mac[i];
		header.addr2[i] = d_src_mac[i];
		header.addr3[i] = d_bss_mac[i];
	}

	header.seq_nr = 0;
	for (int i = 0; i < 12; i++) {
		if(d_seq_nr & (1 << i)) {
			header.seq_nr |=  (1 << (i + 4));
		}
	}
	header.seq_nr = htole16(header.seq_nr);
	d_seq_nr++;

	//header size is 24, plus 4 for FCS means 28 bytes
	*psdu_size = 28 + msdu_size;

	//copy mac header into psdu
	std::memcpy(d_psdu, &header, 24);
	//copy msdu into psdu
	memcpy(d_psdu + 24, msdu, msdu_size);
	//compute and store fcs
	boost::crc_32_type result;
	result.process_bytes(d_psdu, msdu_size + 24);

	uint32_t fcs = result.checksum();
	memcpy(d_psdu + msdu_size + 24, &fcs, sizeof(uint32_t));
}

bool check_mac(std::vector<uint8_t> mac) {
	if(mac.size() != 6) return false;
	return true;
}

private:
	uint16_t d_seq_nr;
	uint8_t d_src_mac[6];
	uint8_t d_dst_mac[6];
	uint8_t d_bss_mac[6];
	uint8_t d_psdu[MAX_PSDU_SIZE];
};

mac::sptr
mac::make(std::vector<uint8_t> src_mac, std::vector<uint8_t> dst_mac, std::vector<uint8_t> bss_mac) {
	return gnuradio::get_initial_sptr(new mac_impl(src_mac, dst_mac, bss_mac));
}

