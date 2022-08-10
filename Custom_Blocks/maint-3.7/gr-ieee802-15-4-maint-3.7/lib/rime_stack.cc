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
#include <ieee802_15_4/rime_stack.h>
#include "rime_connection.h"
#include "bc_connection.h"
#include "uc_connection.h"
#include "ruc_connection.h"

#include <gnuradio/io_signature.h>
#include <gnuradio/block_detail.h>
#include <string>

using namespace gr::ieee802_15_4;

class rime_stack_impl : public rime_stack {

private:
	enum conn_type{bc, uc, ruc};
	uint8_t d_rime_add[2];
	std::vector<rime_connection *> d_connections;

public:

    rime_stack_impl(std::vector<uint16_t> bc_channels, std::vector<uint16_t> uc_channels,
					std::vector<uint16_t> ruc_channels,
					std::vector<uint8_t> rime_add)
	: block("rime_stack", gr::io_signature::make(0, 0, 0),
				gr::io_signature::make(0, 0, 0))
	{
		if(rime_add.size() != 2)
			throw std::invalid_argument("rime address has to consist of two integers");
		d_rime_add[0] = rime_add[0];
		d_rime_add[1] = rime_add[1];

		int num_bcs = bc_channels.size();
		int num_ucs = uc_channels.size();
		int num_rucs = ruc_channels.size();

		pmt::pmt_t mac_in = pmt::mp("fromMAC");
		pmt::pmt_t mac_out = pmt::mp("toMAC");

		message_port_register_in(mac_in);
		set_msg_handler(mac_in, 
						boost::bind(&rime_stack_impl::unpack, this, _1));
		message_port_register_out(mac_out);

		//register broadcast message ports
		add_connections(num_bcs, bc_channels, "bcin", "bcout", bc);

		//register unicast message ports
		add_connections(num_ucs, uc_channels, "ucin", "ucout", uc);

		//register runicast message ports
		add_connections(num_rucs, ruc_channels, "rucin", "rucout", ruc);
	}

	~rime_stack_impl() {
		for(rime_connection *conn : d_connections){
			delete conn;
		}
	}

	void add_connections(int num_conns, std::vector<uint16_t> &channels,
			const char *inport_base, const char *outport_base,
			conn_type type)
	{
		if(std::strlen(inport_base) == 0 || std::strlen(outport_base) == 0){
			throw std::invalid_argument("no in/outport name specified");
		}
		for(int i = 0; i < num_conns; i++){
			pmt::pmt_t inport;
			pmt::pmt_t outport;

			if(num_conns == 1){
				inport = pmt::mp(inport_base);
				outport = pmt::mp(outport_base);
			} else {
				inport = pmt::mp(inport_base + std::to_string(i));
				outport = pmt::mp(outport_base + std::to_string(i));
			}

			message_port_register_out(outport);
			message_port_register_in(inport);

			switch(type){
			case bc:
			{
				bc_connection *to_add = new bc_connection(this, channels[i],
						inport, outport, d_rime_add);
				set_msg_handler(inport,
						boost::bind(&bc_connection::pack, to_add, _1));
				d_connections.push_back(to_add);
				break;
			}
			case uc:
			{
				uc_connection *to_add = new uc_connection(this, channels[i],
						inport, outport, d_rime_add);
				set_msg_handler(inport,
						boost::bind(&uc_connection::pack, to_add, _1));
				d_connections.push_back(to_add);
				break;
			}
			case ruc:
			{
				ruc_connection *to_add = new ruc_connection(this, channels[i],
						inport, outport, d_rime_add);
				set_msg_handler(inport,
						boost::bind(&ruc_connection::pack, to_add, _1));
				d_connections.push_back(to_add);
				break;
			}
			default:
				break;
			}
		}
	}

	void unpack(pmt::pmt_t msg)
	{
		pmt::pmt_t blob;
		if(pmt::is_eof_object(msg)) {
			//  message_port_pub(pmt::mp("bcrxout1"), pmt::PMT_EOF);
			detail().get()->set_done(true);
			return;
		} else if(pmt::is_pair(msg)) {
			blob = pmt::cdr(msg);
		} else {
			assert(false);
		}

		unsigned char buf[2];
		std::memcpy(buf, pmt::blob_data(blob), 2);
		for(rime_connection *conn : d_connections){
			if(conn->channel() == buf[0] && (conn->channel() >> 8) == buf[1]){
				conn->unpack(blob);
				return;
			}
		}
	}
};

rime_stack::sptr
rime_stack::make(std::vector<uint16_t> bc_channels, std::vector<uint16_t> uc_channels, 
				 std::vector<uint16_t> ruc_channels,
				std::vector<uint8_t> rime_add) 
{
	return gnuradio::get_initial_sptr(new rime_stack_impl(bc_channels, uc_channels,
										ruc_channels, rime_add));
}
