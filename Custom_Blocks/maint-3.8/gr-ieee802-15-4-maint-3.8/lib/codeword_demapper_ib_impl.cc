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
#include "codeword_demapper_ib_impl.h"

namespace gr {
  namespace ieee802_15_4 {

    codeword_demapper_ib::sptr
    codeword_demapper_ib::make(int bits_per_cw, std::vector< std::vector< int > > codewords)
    {
      return gnuradio::get_initial_sptr
        (new codeword_demapper_ib_impl(bits_per_cw, codewords));
    }

    /*
     * The private constructor
     */
    codeword_demapper_ib_impl::codeword_demapper_ib_impl(int bits_per_cw, std::vector< std::vector< int > > codewords)
      : gr::block("codeword_demapper_ib",
              gr::io_signature::make(1,1, sizeof(int)),
              gr::io_signature::make(1,1, sizeof(unsigned char))),
      d_bits_per_cw(bits_per_cw),
      d_codewords(codewords)
    {
      // describes the I/O ratio (<=1)
      d_len_cw = d_codewords[0].size();
      d_coderate = float(d_bits_per_cw)/d_len_cw;
      // set_relative_rate(d_coderate);
      set_output_multiple(d_bits_per_cw);
    }

    /*
     * Our virtual destructor.
     */
    codeword_demapper_ib_impl::~codeword_demapper_ib_impl()
    {
    }

    void
    codeword_demapper_ib_impl::forecast (int noutput_items, gr_vector_int &ninput_items_required)
    {
        ninput_items_required[0] = d_len_cw;
    }

    std::vector<int>
    codeword_demapper_ib_impl::calc_distances(const int* in)
    {
      std::vector<int> d(d_codewords.size(), 0);
      for(int i=0; i<d_codewords.size(); i++)
      {
        for(int n=0; n<d_len_cw; n++)
        {
          d[i] += abs(in[n] - d_codewords[i][n]);
        }
      }
      return d;
    }

    std::vector<unsigned char>
    codeword_demapper_ib_impl::dec2bin(int dec, int nbit)
    {
      std::vector<unsigned char> bin(nbit,0);
      for(int i=0; i<nbit; i++)
        bin[nbit-i-1] = (dec >> i) & 0x01;
      return bin;
    }

    int
    codeword_demapper_ib_impl::general_work (int noutput_items,
                       gr_vector_int &ninput_items,
                       gr_vector_const_void_star &input_items,
                       gr_vector_void_star &output_items)
    {
        const int *in = (const int *) input_items[0];
        unsigned char *out = (unsigned char *) output_items[0];

        int nwords = std::min(ninput_items[0]/d_len_cw, noutput_items/d_bits_per_cw);

        // this implements the search for the minimum hamming distance
        std::vector<int> hd; // hamming distances
        int idx; // index of minimum hamming distance
        std::vector<unsigned char> idx_bin; // binary representation of idx
        for(int i=0; i<nwords; i++)
        {
          hd = calc_distances(in+i*d_len_cw);
          idx = std::distance(hd.begin(), std::min_element(hd.begin(), hd.end()));
          // std::cout << "sym: " << idx << std::endl;
          idx_bin = dec2bin(idx, d_bits_per_cw);
          memcpy(out+i*d_bits_per_cw, &idx_bin[0], sizeof(unsigned char)*d_bits_per_cw);
        }

        consume_each (nwords*d_len_cw);
        return nwords*d_bits_per_cw;
    }

  } /* namespace ieee802_15_4 */
} /* namespace gr */

