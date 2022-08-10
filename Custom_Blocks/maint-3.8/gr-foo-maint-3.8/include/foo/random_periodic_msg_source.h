/*
 * Copyright (C) 2016 Bastian Bloessl <bloessl@ccs-labs.org>
 *               2016 Paul Garver <garverp@gatech.edu>
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
#ifndef INCLUDED_FOO_RANDOM_PERIODIC_MSG_SOURCE_H
#define INCLUDED_FOO_RANDOM_PERIODIC_MSG_SOURCE_H

#include <foo/api.h>
#include <gnuradio/block.h>

namespace gr {
namespace foo {

class FOO_API random_periodic_msg_source : virtual public gr::block
{
public:

	typedef boost::shared_ptr<random_periodic_msg_source> sptr;
	static sptr make(int msg_len, long interval, int num_msg = 1,
			bool quit = true, bool debug = false, int seed = 0);

	virtual void set_nmsg(int nmsg) = 0;
	virtual int get_nmsg() = 0;

	virtual void set_delay(long delay) = 0;
	virtual long get_delay() = 0;

	virtual void start_tx() = 0;
	virtual void stop_tx() = 0;
	virtual bool is_running() = 0;
};

}  // namespace foo
}  // namespace gr

#endif /* INCLUDED_FOO_RANDOM_PERIODIC_MSG_SOURCE */
