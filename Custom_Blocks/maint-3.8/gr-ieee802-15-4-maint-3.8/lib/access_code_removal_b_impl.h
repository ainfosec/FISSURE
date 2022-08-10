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

#ifndef INCLUDED_IEEE802_15_4_ACCESS_CODE_REMOVAL_B_IMPL_H
#define INCLUDED_IEEE802_15_4_ACCESS_CODE_REMOVAL_B_IMPL_H

#include <ieee802_15_4/access_code_removal_b.h>

namespace gr {
  namespace ieee802_15_4 {

    class access_code_removal_b_impl : public access_code_removal_b
    {
     private:
      static const int d_len_SHR = 5;
      static const int d_len_PHR = 1;
      int d_len_payload;
      bool d_fixed_payload_len;
      int d_byte_ctr;
      unsigned char d_buf[256];
      void extract_payload();

     public:
      access_code_removal_b_impl(int len_payload);
      ~access_code_removal_b_impl();

      int work(int noutput_items,
	       gr_vector_const_void_star &input_items,
	       gr_vector_void_star &output_items);
    };

  } // namespace ieee802_15_4
} // namespace gr

#endif /* INCLUDED_IEEE802_15_4_ACCESS_CODE_REMOVAL_B_IMPL_H */

