/*
 * Copyright (C) 2013 Christoph Leitner <c.leitner@student.uibk.ac.at>
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

#include "uc_connection.h"
#include "bc_connection.h"

using namespace gr::ieee802_15_4;

uc_connection::uc_connection(rime_stack *block, uint16_t channel,
							pmt::pmt_t inport, pmt::pmt_t outport,
							const uint8_t rime_add_mine[2])
	: rime_connection(block, channel, inport, outport, rime_add_mine)
{

}

std::array<uint8_t,256>
uc_connection::make_msgbuf(uint16_t channel, const uint8_t src[2],
		const uint8_t dest[2])
{
	std::array<uint8_t,256> buf;

	buf[0] = channel & 0xff;
	buf[1] = (channel >> 8) & 0xff;
	buf[2] = dest[0];
	buf[3] = dest[1];
	buf[4] = src[0];
	buf[5] = src[1];

	return buf;
}

bool
uc_connection::rime_add_from_string(std::string &to_parse, uint8_t addr[2])
{
	unsigned long rime_zero_long = std::strtoul(to_parse.data(), nullptr, 10);
	size_t index = to_parse.find(".");
	to_parse.erase(0, index+1);
	unsigned long rime_one_long =  std::strtoul(to_parse.data(), nullptr, 10);
	index = to_parse.find_first_not_of("0123456789");
	if(to_parse.at(index) == ' '){
		to_parse.erase(0, index+1);
	} else {
		to_parse.erase(0, index);
	}
	if(rime_zero_long > 255 || rime_one_long > 255 ||
		(rime_zero_long == 0 && rime_one_long == 0)){
			return false;
	}
	addr[0] = static_cast<uint8_t>(rime_zero_long);
	addr[1] = static_cast<uint8_t>(rime_one_long);
	return true;
}



void
uc_connection::pack(pmt::pmt_t msg)
{
	if(pmt::is_eof_object(msg)){
		d_block->message_port_pub(d_mac_outport, pmt::PMT_EOF);
		d_block->detail().get()->set_done(true);
		return;
	}

	std::string tmp = rime_connection::msg_to_string(msg);
	
	uint8_t dest[2];
	if(!uc_connection::rime_add_from_string(tmp, dest)){
		std::cerr << "Warning: invalid target RIME-Address for unicast on channel ";
		std::cerr << static_cast<unsigned>(d_channel);
		std::cerr <<  ". Message will not be sent." << std::endl;
		return;
	}

	std::array<uint8_t,256> buf = uc_connection::make_msgbuf(d_channel,
			d_rime_add_mine, dest);

	size_t data_len = tmp.length();
	assert(data_len);
	assert(data_len < 256 - header_length);

	std::memcpy(buf.data() + header_length, tmp.data(), data_len);
	pmt::pmt_t rime_msg = pmt::make_blob(buf.data(), data_len + header_length);

	d_block->message_port_pub(d_mac_outport,
			pmt::cons(pmt::PMT_NIL, rime_msg));
}

void
uc_connection::unpack(pmt::pmt_t msg)
{
	unsigned char buf[256];
	size_t data_len = pmt::blob_length(msg);
	std::memcpy(buf, pmt::blob_data(msg), data_len);

	//this block is not the destination of the message
	if(buf[2] != d_rime_add_mine[0] || buf[3] != d_rime_add_mine[1]){
		std::cout << "wrong rime add " << int(buf[2]) << "." << int(buf[3]) << std::endl;
		return;
	}

	pmt::pmt_t rime_payload = pmt::make_blob(buf + header_length, data_len - header_length);
	d_block->message_port_pub(d_outport, pmt::cons(pmt::PMT_NIL, rime_payload));
}
