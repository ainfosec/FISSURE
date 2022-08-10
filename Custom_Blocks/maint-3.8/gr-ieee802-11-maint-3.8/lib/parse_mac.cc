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
#include <ieee802_11/parse_mac.h>
#include "utils.h"

#include <gnuradio/io_signature.h>
#include <gnuradio/block_detail.h>
#include <string>

using namespace gr::ieee802_11;

class parse_mac_impl : public parse_mac {

public:

parse_mac_impl(bool log, bool debug) :
		block("parse_mac",
				gr::io_signature::make(0, 0, 0),
				gr::io_signature::make(0, 0, 0)),
		d_log(log), d_last_seq_no(-1),
		d_debug(debug) {

	message_port_register_in(pmt::mp("in"));
	set_msg_handler(pmt::mp("in"), boost::bind(&parse_mac_impl::parse, this, boost::placeholders::_1));

	message_port_register_out(pmt::mp("fer"));
}

~parse_mac_impl() {

}

void parse(pmt::pmt_t msg) {

	if(pmt::is_eof_object(msg)) {
		detail().get()->set_done(true);
		return;
	} else if(pmt::is_symbol(msg)) {
		return;
	}

	msg = pmt::cdr(msg);

	int data_len = pmt::blob_length(msg);
	mac_header *h = (mac_header*)pmt::blob_data(msg);

	mylog(boost::format("length: %1%") % data_len );

	dout << std::endl << "new mac frame  (length " << data_len << ")" << std::endl;
	dout << "=========================================" << std::endl;
	if(data_len < 20) {
		dout << "frame too short to parse (<20)" << std::endl;
		return;
	}
	#define HEX(a) std::hex << std::setfill('0') << std::setw(2) << int(a) << std::dec
	dout << "duration: " << HEX(h->duration >> 8) << " " << HEX(h->duration  & 0xff) << std::endl;
	dout << "frame control: " << HEX(h->frame_control >> 8) << " " << HEX(h->frame_control & 0xff);

        switch((h->frame_control >> 2) & 3) {

		case 0:
			dout << " (MANAGEMENT)" << std::endl;
			parse_management((char*)h, data_len);
			break;
		case 1:
			dout << " (CONTROL)" << std::endl;
			parse_control((char*)h, data_len);
			break;

		case 2:
			dout << " (DATA)" << std::endl;
			parse_data((char*)h, data_len);
			break;

		default:
			dout << " (unknown)" << std::endl;
			break;
	}

	char *frame = (char*)pmt::blob_data(msg);

	// DATA
	if((((h->frame_control) >> 2) & 63) == 2) {
		print_ascii(frame + 24, data_len - 24);
	// QoS Data
	} else if((((h->frame_control) >> 2) & 63) == 34) {
		print_ascii(frame + 26, data_len - 26);
	}
}

void parse_management(char *buf, int length) {
	mac_header* h = (mac_header*)buf;

	if(length < 24) {
		dout << "too short for a management frame" << std::endl;
		return;
	}

	dout << "Subtype: ";
	switch(((h->frame_control) >> 4) & 0xf) {
		case 0:
			dout << "Association Request";
			break;
		case 1:
			dout << "Association Response";
			break;
		case 2:
			dout << "Reassociation Request";
			break;
		case 3:
			dout << "Reassociation Response";
			break;
		case 4:
			dout << "Probe Request";
			break;
		case 5:
			dout << "Probe Response";
			break;
		case 6:
			dout << "Timing Advertisement";
			break;
		case 7:
			dout << "Reserved";
			break;
		case 8:
			dout << "Beacon" << std::endl;
			if(length < 38) {
				return;
			}
			{
			uint8_t* len = (uint8_t*) (buf + 24 + 13);
			if(length < 38 + *len) {
				return;
			}
			std::string s(buf + 24 + 14, *len);
			dout << "SSID: " << s;
			}
			break;
		case 9:
			dout << "ATIM";
			break;
		case 10:
			dout << "Disassociation";
			break;
		case 11:
			dout << "Authentication";
			break;
		case 12:
			dout << "Deauthentication";
			break;
		case 13:
			dout << "Action";
			break;
		case 14:
			dout << "Action No ACK";
			break;
		case 15:
			dout << "Reserved";
			break;
		default:
			break;
	}
	dout << std::endl;

	dout << "seq nr: " << int(h->seq_nr >> 4) << std::endl;
	dout << "mac 1: ";
	print_mac_address(h->addr1, true);
	dout << "mac 2: ";
	print_mac_address(h->addr2, true);
	dout << "mac 3: ";
	print_mac_address(h->addr3, true);

}


void parse_data(char *buf, int length) {
	mac_header* h = (mac_header*)buf;
	if(length < 24) {
		dout << "too short for a data frame" << std::endl;
		return;
	}

	dout << "Subtype: ";
	switch(((h->frame_control) >> 4) & 0xf) {
		case 0:
			dout << "Data";
			break;
		case 1:
			dout << "Data + CF-ACK";
			break;
		case 2:
			dout << "Data + CR-Poll";
			break;
		case 3:
			dout << "Data + CF-ACK + CF-Poll";
			break;
		case 4:
			dout << "Null";
			break;
		case 5:
			dout << "CF-ACK";
			break;
		case 6:
			dout << "CF-Poll";
			break;
		case 7:
			dout << "CF-ACK + CF-Poll";
			break;
		case 8:
			dout << "QoS Data";
			break;
		case 9:
			dout << "QoS Data + CF-ACK";
			break;
		case 10:
			dout << "QoS Data + CF-Poll";
			break;
		case 11:
			dout << "QoS Data + CF-ACK + CF-Poll";
			break;
		case 12:
			dout << "QoS Null";
			break;
		case 13:
			dout << "Reserved";
			break;
		case 14:
			dout << "QoS CF-Poll";
			break;
		case 15:
			dout << "QoS CF-ACK + CF-Poll";
			break;
		default:
			break;
	}
	dout << std::endl;

	int seq_no = int(h->seq_nr >> 4);
	dout << "seq nr: " << seq_no << std::endl;
	dout << "mac 1: ";
	print_mac_address(h->addr1, true);
	dout << "mac 2: ";
	print_mac_address(h->addr2, true);
	dout << "mac 3: ";
	print_mac_address(h->addr3, true);

	float lost_frames = seq_no - d_last_seq_no - 1;
	if(lost_frames  < 0)
		lost_frames += 1 << 12;

	// calculate frame error rate
	float fer = lost_frames / (lost_frames + 1);
	dout << "instantaneous fer: " << fer << std::endl;

	// keep track of values
	d_last_seq_no = seq_no;

	// publish FER estimate
	pmt::pmt_t pdu = pmt::make_f32vector(lost_frames + 1, fer * 100);
	message_port_pub(pmt::mp("fer"), pmt::cons( pmt::PMT_NIL, pdu ));
}

void parse_control(char *buf, int length) {
	mac_header* h = (mac_header*)buf;

	dout << "Subtype: ";
	switch(((h->frame_control) >> 4) & 0xf) {
		case 7:
			dout << "Control Wrapper";
			break;
		case 8:
			dout << "Block ACK Requrest";
			break;
		case 9:
			dout << "Block ACK";
			break;
		case 10:
			dout << "PS Poll";
			break;
		case 11:
			dout << "RTS";
			break;
		case 12:
			dout << "CTS";
			break;
		case 13:
			dout << "ACK";
			break;
		case 14:
			dout << "CF-End";
			break;
		case 15:
			dout << "CF-End + CF-ACK";
			break;
		default:
			dout << "Reserved";
			break;
	}
	dout << std::endl;

	dout << "RA: ";
	print_mac_address(h->addr1, true);
	dout << "TA: ";
	print_mac_address(h->addr2, true);

}

void print_mac_address(uint8_t *addr, bool new_line = false) {
	if(!d_debug) {
		return;
	}

	std::cout << std::setfill('0') << std::hex << std::setw(2);

	for(int i = 0; i < 6; i++) {
		std::cout << (int)addr[i];
		if(i != 5) {
			std::cout << ":";
		}
	}

	std::cout << std::dec;

	if(new_line) {
		std::cout << std::endl;
	}
}

void print_ascii(char* buf, int length) {

	for(int i = 0; i < length; i++) {
		if((buf[i] > 31) && (buf[i] < 127)) {
			dout << buf[i];
		} else {
			dout << ".";
		}
	}
	dout << std::endl;
}

private:
	bool d_log;
	bool d_debug;
	int d_last_seq_no;
};

parse_mac::sptr
parse_mac::make(bool log, bool debug) {
	return gnuradio::get_initial_sptr(new parse_mac_impl(log, debug));
}


