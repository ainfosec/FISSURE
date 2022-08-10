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
#ifndef INCLUDED_FOO_WIRESHARK_CONNECTOR_H
#define INCLUDED_FOO_WIRESHARK_CONNECTOR_H

#include <foo/api.h>
#include <gnuradio/block.h>

namespace gr {
namespace foo {

enum LinkType {
	WIFI = 127,
	ZIGBEE = 195
};

class FOO_API wireshark_connector : virtual public gr::block
{
public:
	
	typedef boost::shared_ptr<wireshark_connector> sptr;
	static sptr make(LinkType type, bool debug= false);
};

}  // namespace foo
}  // namespace gr

#endif /* INCLUDED_FOO_WIRESHARK_CONNECTOR_H */
