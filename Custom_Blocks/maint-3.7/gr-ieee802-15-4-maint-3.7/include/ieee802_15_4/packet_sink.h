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
#ifndef INCLUDED_GR_IEEE802_15_4_PACKET_SINK_H
#define INCLUDED_GR_IEEE802_15_4_PACKET_SINK_H

#include <ieee802_15_4/api.h>
#include <gnuradio/block.h>

namespace gr {
namespace ieee802_15_4 {

class IEEE802_15_4_API packet_sink : virtual public block
{
public:

	typedef boost::shared_ptr<packet_sink> sptr;
	static sptr make(unsigned int threshold = 10);

};

}  // namespace ieee802_15_4
}  // namespace gr

#endif /* INCLUDED_GR_IEEE802_15_4_PACKET_SINK_H */
