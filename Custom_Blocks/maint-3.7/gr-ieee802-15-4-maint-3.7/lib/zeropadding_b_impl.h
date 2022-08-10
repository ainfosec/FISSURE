/* -*- c++ -*- */
/* 
 * Copyright 2015 Felix Wunsch, Communications Engineering Lab (CEL) / Karlsruhe Institute of Technology (KIT) <wunsch.felix@googlemail.com>.
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

#ifndef INCLUDED_IEEE802_15_4_ZEROPADDING_B_IMPL_H
#define INCLUDED_IEEE802_15_4_ZEROPADDING_B_IMPL_H

#include <ieee802_15_4/zeropadding_b.h>

namespace gr {
  namespace ieee802_15_4 {

    class zeropadding_b_impl : public zeropadding_b
    {
     private:
      std::vector<unsigned char> d_buf;
      int d_nzeros;
      void pad_zeros(pmt::pmt_t msg);

     public:
      zeropadding_b_impl(int nzeros);
      ~zeropadding_b_impl();

      int general_work(int noutput_items,
		       gr_vector_int &ninput_items,
		       gr_vector_const_void_star &input_items,
		       gr_vector_void_star &output_items);
    };

  } // namespace ieee802_15_4
} // namespace gr

#endif /* INCLUDED_IEEE802_15_4_ZEROPADDING_B_IMPL_H */

