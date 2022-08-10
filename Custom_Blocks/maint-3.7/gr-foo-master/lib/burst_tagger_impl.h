/* -*- c++ -*- */
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

#ifndef INCLUDED_FOO_BURST_TAGGER_IMPL_H
#define INCLUDED_FOO_BURST_TAGGER_IMPL_H

#include <foo/burst_tagger.h>

namespace gr {
namespace foo {

	class burst_tagger_impl : public burst_tagger {
		private:
			void add_eob(uint64_t item);
			void add_sob(uint64_t item);

			pmt::pmt_t d_tag_name;
			int d_copy;
			unsigned int d_mult;

		public:
			burst_tagger_impl(pmt::pmt_t tag_name,
					unsigned int mult);
			~burst_tagger_impl();

			int work(int noutput_items,
				gr_vector_const_void_star &input_items,
				gr_vector_void_star &output_items);
	};

} // namespace foo
} // namespace gr

#endif /* INCLUDED_FOO_BURST_TAGGER_IMPL_H */

