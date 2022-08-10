/*
 * Copyright (C) 2013 Bastian Bloessl <bloessl@ccs-labs.org>
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
#include "periodic_msg_source_impl.h"

#include <gnuradio/io_signature.h>
#include <gnuradio/block_detail.h>
#include <string.h>

using namespace gr::foo;

#define dout d_debug && std::cout

periodic_msg_source_impl::periodic_msg_source_impl(pmt::pmt_t msg,
			long interval, int num_msg, bool quit, bool debug) :
		block("periodic_msg_source",
				gr::io_signature::make(0, 0, 0),
				gr::io_signature::make(0, 0, 0)),
		d_msg(msg),
		d_nmsg_total(num_msg),
		d_nmsg_left(num_msg),
		d_interval(interval),
		d_debug(debug),
		d_finished(false),
		d_quit(quit) {

	message_port_register_out(pmt::mp("out"));

	d_thread = new boost::thread(boost::bind(&periodic_msg_source_impl::run, this, this));
}

periodic_msg_source_impl::~periodic_msg_source_impl() {
	gr::thread::scoped_lock(d_mutex);

	d_finished = true;
	d_thread->interrupt();
	d_thread->join();
	delete d_thread;
}

void
periodic_msg_source_impl::run(periodic_msg_source_impl *instance) {

	try {

	// flow graph startup delay
	boost::this_thread::sleep(boost::posix_time::milliseconds(500));

	while(1) {
		long delay;
		{
			gr::thread::scoped_lock(d_mutex);
			if(d_finished || !d_nmsg_left) {
				d_finished = true;
				if(d_quit) {
					boost::this_thread::sleep(boost::posix_time::milliseconds(500));
					message_port_pub( pmt::mp("out"), pmt::PMT_EOF);
					post(pmt::mp("system"), pmt::cons(pmt::mp("done"), pmt::from_long(1)));
				}
				break;
			}

			dout << "PMS: number of messages left: " << d_nmsg_left << std::endl;

			message_port_pub( pmt::mp("out"), d_msg );

			if(d_nmsg_left > 0) {
				d_nmsg_left--;
			}

			delay = d_interval;
		}
		boost::this_thread::sleep(boost::posix_time::milliseconds(delay));
	}

	} catch(boost::thread_interrupted) {
		gr::thread::scoped_lock(d_mutex);
		dout << "PMS: thread interrupted" << std::endl;
		d_finished = true;
		if(d_quit) {
			boost::this_thread::sleep(boost::posix_time::milliseconds(500));
			message_port_pub( pmt::mp("out"), pmt::PMT_EOF);
			post(pmt::mp("system"), pmt::cons(pmt::mp("done"), pmt::from_long(1)));
		}
	}
}

void
periodic_msg_source_impl::set_nmsg(int nmsg) {
	gr::thread::scoped_lock(d_mutex);
	d_nmsg_total = nmsg;
}

int
periodic_msg_source_impl::get_nmsg() {
	gr::thread::scoped_lock(d_mutex);
	return d_nmsg_total;
}

void
periodic_msg_source_impl::set_delay(long delay) {
	gr::thread::scoped_lock(d_mutex);
	d_interval = delay;
}

long
periodic_msg_source_impl::get_delay() {
	gr::thread::scoped_lock(d_mutex);
	return d_interval;
}


void
periodic_msg_source_impl::start_tx() {
	gr::thread::scoped_lock(d_mutex);

	if(is_running()) return;

	d_nmsg_left = d_nmsg_total;
	d_finished = false;
	d_thread->join();
	delete d_thread;

	d_thread = new boost::thread(boost::bind(&periodic_msg_source_impl::run, this, this));
}

void
periodic_msg_source_impl::stop_tx() {
	d_thread->interrupt();
}

bool
periodic_msg_source_impl::is_running() {
	return !d_finished;
}

periodic_msg_source::sptr
periodic_msg_source::make(pmt::pmt_t msg, long interval, int num_msg, bool quit, bool debug) {
	return gnuradio::get_initial_sptr(new periodic_msg_source_impl(msg, interval, num_msg, quit, debug));
}
