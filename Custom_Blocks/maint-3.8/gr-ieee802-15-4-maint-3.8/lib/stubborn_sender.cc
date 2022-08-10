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


#include "stubborn_sender.h"
#include "ruc_connection.h"

#define debug 1
#if debug
#define dout std::cout
#endif

using namespace gr::ieee802_15_4;

stubborn_sender::stubborn_sender(rime_stack* block, ruc_connection *caller,
								 pmt::pmt_t outport) 
	:d_stop(false), d_mac_outport(outport), d_block(block), d_caller(caller)
{

}

void
stubborn_sender::start(long int retxtime, int retxs)
{
	d_retxtime = retxtime;
	d_retxs = retxs;

	gr::thread::thread t(&stubborn_sender::thread_func, this);
	t.detach();

	dout << "sender started" << std::endl;

}

void
stubborn_sender::enqueue(pmt::pmt_t msg)
{
	gr::thread::scoped_lock lock(d_mutex);
	d_msg_queue.push(msg);
	d_queue_filled.notify_one();
}

pmt::pmt_t
stubborn_sender::queue_pop()
{
	gr::thread::scoped_lock lock(d_mutex);

	while(d_msg_queue.size() == 0){
		d_queue_filled.wait(lock);
	}
	pmt::pmt_t msg = d_msg_queue.front();
	d_msg_queue.pop();
	return msg;
}



void
stubborn_sender::thread_func()
{
	while(true){
		d_stop.store(false);
		pmt::pmt_t to_send = queue_pop();
		int i = 0;
		do{
			d_block->message_port_pub(d_mac_outport, to_send);
			dout << "send try " << i << std::endl;
			gr::thread::scoped_lock lock(d_mutex);
			d_ack_received.timed_wait(lock, boost::posix_time::milliseconds(d_retxtime));
			lock.unlock();
		} while(i++ < d_retxs && !d_stop.load()); 

		if(!d_stop.load()){
			dout << "timeout" << std::endl;
			d_caller->inc_recv_seqno();
		} else {
			dout << "stopped" << std::endl;
		}
	}
}


void
stubborn_sender::stop()
{
	dout << "stopping sender..." << std::endl;
	d_stop.store(true);
	d_ack_received.notify_one();
}

