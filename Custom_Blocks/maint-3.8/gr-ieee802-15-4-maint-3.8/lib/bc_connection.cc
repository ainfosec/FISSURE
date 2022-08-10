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
#include "bc_connection.h"

using namespace gr::ieee802_15_4;

bc_connection::bc_connection(rime_stack *block, uint16_t channel, pmt::pmt_t inport,
							pmt::pmt_t outport, const uint8_t rime_add_mine[2])
	: rime_connection(block, channel, inport, outport, rime_add_mine)
{

}

std::array<uint8_t,256>
bc_connection::make_msgbuf(uint16_t channel, const uint8_t src[2])
{
	std::array<uint8_t,256> buf;
	buf[0] = channel & 0xff;
	buf[1] = (channel >> 8) & 0xff;
	buf[2] = src[0];
	buf[3] = src[1];
	return buf;
}

void
bc_connection::pack(pmt::pmt_t msg)
{
	std::array<uint8_t,256> buf = bc_connection::make_msgbuf(d_channel,
			d_rime_add_mine);

	if(pmt::is_eof_object(msg)){
		d_block->message_port_pub(d_mac_outport, pmt::PMT_EOF);
		d_block->detail().get()->set_done(true);
		return;
	}

 	std::string tmp = rime_connection::msg_to_string(msg);
	size_t data_len = tmp.length();
	assert(data_len);
	assert(data_len < 256 - header_length);

	std::memcpy(buf.data() + header_length, tmp.data(), data_len);
	pmt::pmt_t rime_msg = pmt::make_blob(buf.data(), data_len + header_length);

	d_block->message_port_pub(d_mac_outport,
							  pmt::cons(pmt::PMT_NIL, rime_msg));
}

void
bc_connection::unpack(pmt::pmt_t msg)
{
	unsigned char buf[256];
	size_t data_len = pmt::blob_length(msg);
	std::memcpy(buf, pmt::blob_data(msg), data_len);
	pmt::pmt_t rime_payload = pmt::make_blob(buf + header_length, data_len - header_length);
	d_block->message_port_pub(d_outport, pmt::cons(pmt::PMT_NIL, rime_payload));
}


