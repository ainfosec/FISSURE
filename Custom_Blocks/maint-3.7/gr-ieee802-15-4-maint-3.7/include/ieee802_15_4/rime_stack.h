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
#ifndef INCLUDED_GR_IEEE802_15_4_RIME_STACK_H
#define INCLUDED_GR_IEEE802_15_4_RIME_STACK_H

#include <ieee802_15_4/api.h>
#include <gnuradio/block.h>
#include <vector>

namespace gr {
	namespace ieee802_15_4 {

		class IEEE802_15_4_API rime_stack : virtual public block
		{
		public:

			typedef boost::shared_ptr<rime_stack> sptr;
			static sptr make(std::vector<uint16_t> bc_channels, 
				std::vector<uint16_t> uc_channels,
				std::vector<uint16_t> ruc_channels,
				std::vector<uint8_t> rime_add);
		};
	}  // namespace ieee802_15_4
}  // namespace gr

#endif /* INCLUDED_GR_IEEE802_15_4_RIME_STACK_H */
 
