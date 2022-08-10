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

#ifndef INCLUDED_RUC_CONNECTION_H
#define INCLUDED_RUC_CONNECTION_H

#include "rime_connection.h"
#include "stubborn_sender.h"
#include <array>

namespace gr{
	namespace ieee802_15_4{
		class IEEE802_15_4_API ruc_connection : public rime_connection{
		private:
			static const int header_length = 7;
			static const int seqno_bits = 2;
			int d_send_seqno;
			int d_recv_seqno;
			stubborn_sender d_stubborn_sender;
			gr::thread::mutex d_mutex;
		public:
			static std::array<uint8_t, 256> make_msgbuf(uint16_t channel, bool ack, int seqno,
					const uint8_t src[2], const uint8_t dest[2]);
			ruc_connection(rime_stack *block, uint16_t channel,
						pmt::pmt_t inport, pmt::pmt_t outport,
						const uint8_t rime_add_mine[2]);
			void pack(pmt::pmt_t msg);
			void unpack(pmt::pmt_t msg);
			void inc_recv_seqno();
			int recv_seqno();
		};
	}
}
#endif
