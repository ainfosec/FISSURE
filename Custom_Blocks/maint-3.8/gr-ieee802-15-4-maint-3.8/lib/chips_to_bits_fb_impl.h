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

#ifndef INCLUDED_IEEE802_15_4_CHIPS_TO_BITS_FB_IMPL_H
#define INCLUDED_IEEE802_15_4_CHIPS_TO_BITS_FB_IMPL_H

#include <ieee802_15_4/chips_to_bits_fb.h>

namespace gr {
  namespace ieee802_15_4 {

    class chips_to_bits_fb_impl : public chips_to_bits_fb
    {
     private:
      std::vector< std::vector< float > > d_chip_seq;
      int d_bits_per_seq;
      int d_len_chip_seq;
      int d_num_chip_seq;
      std::vector<unsigned char> dec2bin_lsb(int dec, int nbit);
     public:
      chips_to_bits_fb_impl(std::vector< std::vector< float > > chip_seq);
      ~chips_to_bits_fb_impl();

      int work(int noutput_items,
	       gr_vector_const_void_star &input_items,
	       gr_vector_void_star &output_items);
    };

  } // namespace ieee802_15_4
} // namespace gr

#endif /* INCLUDED_IEEE802_15_4_CHIPS_TO_BITS_FB_IMPL_H */

