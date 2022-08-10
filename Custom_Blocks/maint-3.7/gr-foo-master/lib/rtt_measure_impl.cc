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

#include "rtt_measure_impl.h"
#include <gnuradio/io_signature.h>

using namespace gr::foo;

rtt_measure_impl::rtt_measure_impl(unsigned long interval)
		: block("rtt_measure",
				gr::io_signature::make(0, 0, 0),
				gr::io_signature::make(1, 1, sizeof(uint8_t))),
		d_interval(interval), d_thread(&rtt_measure_impl::run, this),
		d_stop(false)
{
	message_port_register_in(pmt::mp("in"));
	message_port_register_out(pmt::mp("out"));
}

rtt_measure_impl::~rtt_measure_impl() {
	d_stop.store(true);
	d_thread.interrupt(); //if thread was sleeping
	d_thread.join();
}

void
rtt_measure_impl::run()
{
	// flow graph startup delay
	boost::this_thread::sleep(boost::posix_time::milliseconds(500));
	std::string text("fnord");
	pmt::pmt_t msg = pmt::make_blob(text.data(), text.length());
	while(!d_stop.load()){
		gr::thread::scoped_lock lock(d_mutex);
		message_port_pub(pmt::mp("out"), pmt::cons(pmt::PMT_NIL, msg));
		d_start_time = boost::posix_time::microsec_clock::local_time();
		lock.unlock();
		boost::this_thread::sleep(boost::posix_time::milliseconds(d_interval));
	}
}

int
rtt_measure_impl::general_work(int noutput, gr_vector_int& ninput_items,
		gr_vector_const_void_star& input_items,
		gr_vector_void_star& output_items )
{
	gr_complex *out = (gr_complex*)output_items[0];

	pmt::pmt_t msg(delete_head_nowait(pmt::mp("in")));
	if(!msg.get()){
		return 0;
	}
	boost::posix_time::time_duration dur =
			boost::posix_time::microsec_clock::local_time() - start_time();
	std::string time_string(std::to_string(dur.total_microseconds()) + "\n");
	std::cout << time_string;

	if(pmt::is_eof_object(msg)) {
			return -1;
	} else if(!pmt::is_pair(msg)) {
		throw std::invalid_argument("only PDU messages allowed");
	}
	int to_copy = time_string.length();
	std::memcpy(out, time_string.data(), to_copy);

	return to_copy;
}

boost::posix_time::ptime
rtt_measure_impl::start_time()
{
	gr::thread::scoped_lock(d_mutex);
	return d_start_time;
}

rtt_measure::sptr
rtt_measure::make(unsigned long interval)
{
	return gnuradio::get_initial_sptr(new rtt_measure_impl(interval));
}