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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <gnuradio/io_signature.h>
#include "codeword_mapper_bi_impl.h"

namespace gr {
  namespace ieee802_15_4 {

    codeword_mapper_bi::sptr
    codeword_mapper_bi::make(int bits_per_cw, std::vector< std::vector< int > > codewords)
    {
      return gnuradio::get_initial_sptr
        (new codeword_mapper_bi_impl(bits_per_cw, codewords));
    }

    /*
     * The private constructor
     */
    codeword_mapper_bi_impl::codeword_mapper_bi_impl(int bits_per_cw, std::vector< std::vector< int > > codewords)
      : gr::block("codeword_mapper_bi",
              gr::io_signature::make(1,1,sizeof(unsigned char)),
              gr::io_signature::make(1,1,sizeof(int))),
      d_bits_per_cw(bits_per_cw),
      d_codewords(codewords)
    {
      // describes the I/O ratio (>=1)
      d_len_cw = d_codewords[0].size();
      d_coderate = float(d_len_cw)/bits_per_cw;
      // set_relative_rate(d_coderate);
      set_output_multiple(d_len_cw);
    }

    /*
     * Our virtual destructor.
     */
    codeword_mapper_bi_impl::~codeword_mapper_bi_impl()
    {
    }

    void
    codeword_mapper_bi_impl::forecast(int noutput_items, gr_vector_int &ninput_items_required)
    {
      ninput_items_required[0] = d_bits_per_cw;
    }

    int 
    codeword_mapper_bi_impl::bin2dec(const unsigned char* bin_ptr, int nbits)
    {
      int dec=0;
      for(int i=0; i<nbits; i++)
        dec += (bin_ptr[nbits-i-1] << i) & (0x01 << i);
      // std::cout << "bin in:";
      // for(int i=0; i<nbits; i++)
      //   std::cout << " " << int(bin_ptr[i]);
      // std::cout << ", dec out: " << dec << std::endl;
      return dec;    
    }

    int
    codeword_mapper_bi_impl::general_work (int noutput_items,
                       gr_vector_int &ninput_items,
                       gr_vector_const_void_star &input_items,
                       gr_vector_void_star &output_items)
    {
        const unsigned char *in = (const unsigned char *) input_items[0];
        int *out = (int*) output_items[0];

        int num_output_cw = std::min(std::floor(ninput_items[0]/d_bits_per_cw), std::floor(noutput_items/d_len_cw));
        for(int i=0; i<num_output_cw; i++)
        {
          int idx = bin2dec(in+i*d_bits_per_cw, d_bits_per_cw);
          memcpy(out+i*d_len_cw, &d_codewords[idx][0], sizeof(int)*d_len_cw);
        }

        consume_each(num_output_cw*d_bits_per_cw);
        return num_output_cw*d_len_cw;
    }

  } /* namespace ieee802_15_4 */
} /* namespace gr */

