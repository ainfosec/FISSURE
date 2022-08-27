/* -*- c++ -*- */
/* 
 * Copyright 2015 Pavel Yazev <pyazev@gmail.com>
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

#ifndef INCLUDED_DECT2_PHASE_DIFF_IMPL_H
#define INCLUDED_DECT2_PHASE_DIFF_IMPL_H

#include <gnuradio/dect2/phase_diff.h>

namespace gr {
  namespace dect2 {

    class phase_diff_impl : public phase_diff
    {
     private:

     public:
      phase_diff_impl();
      ~phase_diff_impl();

      int work(int noutput_items,
	       gr_vector_const_void_star &input_items,
	       gr_vector_void_star &output_items);
    };

  } // namespace dect2
} // namespace gr

#endif /* INCLUDED_DECT2_PHASE_DIFF_IMPL_H */

