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

#ifndef INCLUDED_IEEE802_11_SIGNAL_FIELD_IMPL_H
#define INCLUDED_IEEE802_11_SIGNAL_FIELD_IMPL_H

#include <ieee802_11/signal_field.h>
#include "utils.h"

namespace gr {
namespace ieee802_11 {

class signal_field_impl : public signal_field
{
public:
	signal_field_impl();
	~signal_field_impl();

	bool header_formatter(long packet_len, unsigned char *out,
			const std::vector<tag_t> &tags);

	bool header_parser(const unsigned char *header,
			std::vector<tag_t> &tags);
private:
	int get_bit(int b, int i);
	void generate_signal_field(char *out, frame_param &frame, ofdm_param &ofdm);
};

} // namespace ieee802_11
} // namespace gr

#endif /* INCLUDED_IEEE802_11_SIGNAL_FIELD_IMPL_H */

