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
#ifndef @GUARD_NAME@
#define @GUARD_NAME@

#include <ieee802-11/api.h>
#include <gnuradio/sync_block.h>

namespace gr {
namespace ieee802_11 {

class IEEE802_11_API @NAME@ : virtual public sync_block
{
public: 
	typedef boost::shared_ptr<@NAME@> sptr;
	static sptr make(int length);

	virtual int length() const = 0;
	virtual void set_length(int length) = 0;

};

} /* namespace blocks */
} /* namespace gr */

#endif /* @GUARD_NAME@ */
