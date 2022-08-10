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
#ifndef @GUARD_NAME_IMPL@
#define @GUARD_NAME_IMPL@

#include <ieee802-11/@NAME@.h>

namespace gr {
namespace ieee802_11 {

class @NAME_IMPL@ : public @NAME@
{
private:
	int d_length;
	int d_new_length;
	bool d_updated;

public:
	@NAME_IMPL@(int length);

	int length() const { return d_new_length; }
	void set_length(int length);

	int work(int noutput_items,
		gr_vector_const_void_star &input_items,
		gr_vector_void_star &output_items);

};

} /* namespace blocks */
} /* namespace gr */

#endif /* @GUARD_NAME_IMPL@ */
