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
#ifndef INCLUDED_RIME_CONNECTION_H
#define INCLUDED_RIME_CONNECTION_H

#include <ieee802_15_4/api.h>
#include <ieee802_15_4/rime_stack.h>
#include <gnuradio/block_detail.h>

namespace gr{
	namespace ieee802_15_4{
		class IEEE802_15_4_API rime_connection{
		protected:
			rime_stack *d_block;
			uint16_t d_channel;
			pmt::pmt_t d_inport;
			pmt::pmt_t d_outport;
			pmt::pmt_t d_mac_outport;
			uint8_t d_rime_add_mine[2];
			
		public:
			static std::string msg_to_string(pmt::pmt_t msg);
			rime_connection(rime_stack *block, uint16_t channel, pmt::pmt_t inport,
				pmt::pmt_t outport, const uint8_t rime_add_mine[2]);
			virtual ~rime_connection() {};
			virtual void pack(pmt::pmt_t msg) = 0;
			virtual void unpack(pmt::pmt_t msg) = 0;
			uint16_t channel() const;
		};
	}
}

#endif 
