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

#include "packet_dropper_impl.h"
#include <gnuradio/io_signature.h>

using namespace gr::foo;

packet_dropper_impl::packet_dropper_impl(double drop_rate, unsigned long seed)
		: block("packet_dropper",
				gr::io_signature::make(0, 0, 0),
				gr::io_signature::make(0, 0, 0)),
		d_drop_rate(drop_rate),
		d_generator(seed),
		d_distribution(0.0, 1.0)
{
	if(d_drop_rate >= 1){
		throw std::out_of_range("drop rate has to be < 1");
	}
	message_port_register_in(pmt::mp("in"));
	set_msg_handler(pmt::mp("in"), boost::bind(&packet_dropper_impl::msg_handler, this, _1));
	message_port_register_out(pmt::mp("out"));
}

void
packet_dropper_impl::msg_handler(pmt::pmt_t msg)
{
	if(d_distribution(d_generator) <= d_drop_rate){
		return;
	}
	message_port_pub(pmt::mp("out"), msg);
}

packet_dropper::sptr
packet_dropper::make(double drop_rate, unsigned long seed)
{
	return gnuradio::get_initial_sptr(new packet_dropper_impl(drop_rate, seed));
}

