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
#include "rime_connection.h" 

using namespace gr::ieee802_15_4;

rime_connection::rime_connection(rime_stack *block, uint16_t channel, 
								pmt::pmt_t inport, pmt::pmt_t outport, 
								const uint8_t rime_add_mine[2])
	: d_block(block), d_channel(channel), d_inport(inport), d_outport(outport),
	d_mac_outport(pmt::mp("toMAC"))
{
	d_rime_add_mine[0] = rime_add_mine[0];
	d_rime_add_mine[1] = rime_add_mine[1];
}

uint16_t
rime_connection::channel() const
{
	return d_channel;
}

std::string
rime_connection::msg_to_string(pmt::pmt_t msg)
{
	if(pmt::is_pair(msg)) {
		pmt::pmt_t blob = pmt::cdr(msg);
		return std::string(static_cast<const char *>(pmt::blob_data(blob)),
				pmt::blob_length(blob));
	} else if(pmt::is_symbol(msg)) {
		return std::string(pmt::symbol_to_string(msg));
	} else if(pmt::is_blob(msg)) {
		return std::string(static_cast<const char *>(pmt::blob_data(msg)),
				pmt::blob_length(msg));
	}

	throw std::runtime_error("rime connection: wrong message type");
	return "";
}


