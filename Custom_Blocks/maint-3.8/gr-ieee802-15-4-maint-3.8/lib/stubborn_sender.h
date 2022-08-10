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
#ifndef INCLUDED_STUBBORN_SENDER_H
#define INCLUDED_STUBBORN_SENDER_H

#include <ieee802_15_4/rime_stack.h>
#include <thread>
#include <atomic>
#include <queue>

namespace gr{
	namespace ieee802_15_4{
		class ruc_connection;
		class IEEE802_15_4_API stubborn_sender{
		private:
			rime_stack *d_block;
			ruc_connection *d_caller;
			pmt::pmt_t d_mac_outport;
			long d_retxtime;
			int d_retxs;
			std::atomic_bool d_stop;
			std::queue<pmt::pmt_t> d_msg_queue;
			gr::thread::mutex d_mutex;
			gr::thread::condition_variable d_queue_filled;
			gr::thread::condition_variable d_ack_received;
			void thread_func();
			pmt::pmt_t queue_pop();
			
		public:
			stubborn_sender(rime_stack *block, ruc_connection *caller,
							pmt::pmt_t mac_outport);
			void start(long retxtime = 1000L, int retxs = 3);
			void enqueue(pmt::pmt_t msg);
			void stop();
		};
	}
}

#endif
