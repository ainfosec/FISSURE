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
#ifndef INCLUDED_IEEE802_11_ETHER_ENCAP_IMPL_H
#define INCLUDED_IEEE802_11_ETHER_ENCAP_IMPL_H

#include <ieee802-11/ether_encap.h>

namespace gr {
namespace ieee802_11 {

	struct ethernet_header {
		uint8_t   dest[6];
		uint8_t   src[6];
		uint16_t  type;
	}__attribute__((packed));

	class ether_encap_impl : public ether_encap {

		public:
			ether_encap_impl(bool debug);

		private:
			void from_tap(pmt::pmt_t msg);
			void from_wifi(pmt::pmt_t msg);

			bool d_debug;
			uint16_t d_last_seq;
	};

} // namespace ieee802_11
} // namespace gr

#endif /* INCLUDED_IEEE802_11_ETHER_ENCAP_IMPL_H */

