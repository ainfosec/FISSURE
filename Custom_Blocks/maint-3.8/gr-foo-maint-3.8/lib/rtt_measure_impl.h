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

#ifndef INCLUDED_FOO_RTT_MEASURE_IMPL_H
#define INCLUDED_FOO_RTT_MEASURE_IMPL_H

#include <foo/rtt_measure.h>
#include <atomic>
namespace gr {
namespace foo {
	class rtt_measure_impl : public rtt_measure {
		private:
			unsigned long d_interval;
			std::atomic_bool d_stop;
			boost::posix_time::ptime d_start_time;
			gr::thread::mutex d_mutex;
			gr::thread::thread d_thread;
			gr::thread::condition_variable d_msg_received;
		public:
			rtt_measure_impl(unsigned long interval);
			~rtt_measure_impl();
			void run();
			int general_work(int noutput, gr_vector_int& ninput_items,
					gr_vector_const_void_star& input_items,
					gr_vector_void_star& output_items );
			boost::posix_time::ptime start_time();
	};
}
}

#endif
