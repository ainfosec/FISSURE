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

#ifndef INCLUDED_IEEE802_15_4_CODEWORD_MAPPER_BI_IMPL_H
#define INCLUDED_IEEE802_15_4_CODEWORD_MAPPER_BI_IMPL_H

#include <ieee802_15_4/codeword_mapper_bi.h>

namespace gr {
  namespace ieee802_15_4 {

    class codeword_mapper_bi_impl : public codeword_mapper_bi
    {
     private:
      int d_bits_per_cw;
      std::vector < std::vector<int> > d_codewords;
      int d_len_cw;
      float d_coderate;
      int bin2dec(const unsigned char* bin_ptr, int nbits);

     public:
      codeword_mapper_bi_impl(int bits_per_cw, std::vector< std::vector< int > > codewords);
      ~codeword_mapper_bi_impl();

      void forecast(int noutput_items, gr_vector_int &ninput_items_required);

      int general_work(int noutput_items,
		       gr_vector_int &ninput_items,
		       gr_vector_const_void_star &input_items,
		       gr_vector_void_star &output_items);
    };

  } // namespace ieee802_15_4
} // namespace gr

#endif /* INCLUDED_IEEE802_15_4_CODEWORD_MAPPER_BI_IMPL_H */

