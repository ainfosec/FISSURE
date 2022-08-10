/* 
 * Copyright 2013 Bastian Bloessl <bloessl@ccs-labs.org>.
 * 
 * This is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3, or (at your option)
 * any later version.
 * 
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this software; see the file COPYING.  If not, write to
 * the Free Software Foundation, Inc., 51 Franklin Street,
 * Boston, MA 02110-1301, USA.
 */

#ifndef INCLUDED_FOO_PACKET_PAD_IMPL_H
#define INCLUDED_FOO_PACKET_PAD_IMPL_H

#include <foo/packet_pad.h>

namespace gr {
namespace foo {

	class packet_pad_impl : public packet_pad {
		private:
			void add_eob(uint64_t item);
			void add_sob(uint64_t item);

			bool d_debug;
			bool d_delay;
			double d_delay_sec;

			int d_pad_front;
			int d_pad_tail;

			int d_pad;
			bool d_eob;

		public:
			packet_pad_impl(bool debug, bool delay, double delay_sec,
					unsigned int pad_front, unsigned int pad_tail);

			~packet_pad_impl();

			int general_work (int noutput_items,
					gr_vector_int& ninput_items,
					gr_vector_const_void_star& input_items,
					gr_vector_void_star& output_items);
			void forecast (int noutput_items,
					gr_vector_int &ninput_items_required);
	};

} // namespace foo
} // namespace gr

#endif /* INCLUDED_FOO_BURST_TAGGER_IMPL_H */

