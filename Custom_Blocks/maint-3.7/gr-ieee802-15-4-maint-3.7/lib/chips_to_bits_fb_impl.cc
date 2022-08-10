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
#include "chips_to_bits_fb_impl.h"
#include <volk/volk.h>

namespace gr {
  namespace ieee802_15_4 {

    chips_to_bits_fb::sptr
    chips_to_bits_fb::make(std::vector< std::vector< float > > chip_seq)
    {
      return gnuradio::get_initial_sptr
        (new chips_to_bits_fb_impl(chip_seq));
    }

    /*
     * The private constructor
     */
    chips_to_bits_fb_impl::chips_to_bits_fb_impl(std::vector< std::vector< float > > chip_seq)
      : gr::sync_decimator("chips_to_bits_fb",
              gr::io_signature::make(1,1, sizeof(float)),
              gr::io_signature::make(1,1, sizeof(unsigned char)),
              (unsigned)(((float)chip_seq[0].size())/std::log2((float)chip_seq.size()))),
      d_chip_seq(chip_seq),
      d_bits_per_seq(std::log2(chip_seq.size())),
      d_len_chip_seq(chip_seq[0].size()),
      d_num_chip_seq(chip_seq.size())
    {
      set_output_multiple(d_bits_per_seq);

      // encode the chip sequence as nrz
      for(int i=0; i<d_num_chip_seq; i++)
      {
        for(int k=0; k<d_len_chip_seq; k++)
        {
          d_chip_seq[i][k] = 2*d_chip_seq[i][k]-1;
        }
      }
    }

    /*
     * Our virtual destructor.
     */
    chips_to_bits_fb_impl::~chips_to_bits_fb_impl()
    {
    }

    std::vector<unsigned char>
    chips_to_bits_fb_impl::dec2bin_lsb(int dec, int nbit)
    {
      std::vector<unsigned char> bin(nbit,0);
      for(int i=0; i<nbit; i++)
        bin[i] = (dec >> i) & 0x01;
      return bin;
    }

    int
    chips_to_bits_fb_impl::work(int noutput_items,
			  gr_vector_const_void_star &input_items,
			  gr_vector_void_star &output_items)
    {
        const float *in = (const float *) input_items[0];
        unsigned char *out = (unsigned char *) output_items[0];

        int nblocks = noutput_items/d_bits_per_seq;

        std::vector<float> dist(d_num_chip_seq, 0.0);
        int idx;
        std::vector<unsigned char> idx_bin(d_bits_per_seq,0);
        for(int n=0; n<nblocks; n++)
        {
          // std::cout << "in: ";
          // for(int i=0; i<d_len_chip_seq; i++)
          //   std::cout << in[n*d_len_chip_seq+i] << " ";
          // std::cout << std::endl;

          memset(&dist[0], 0, sizeof(float)*dist.size());
          for(int i=0; i<d_num_chip_seq; i++)
          {
            volk_32f_x2_dot_prod_32f(&dist[i], &d_chip_seq[i][0], in+n*d_len_chip_seq, d_len_chip_seq);
            // std::cout << "dist[" << i << "]=" << dist[i] << std::endl;
          }

          idx = std::distance(dist.begin(), std::max_element(dist.begin(), dist.end()));
          idx_bin = dec2bin_lsb(idx, d_bits_per_seq);
          // std::cout << "max_i: " << idx << ", bit arr: ";
          // for(int i=0;i<d_bits_per_seq;i++)
          //   std::cout << int(idx_bin[i]) << " ";
          // std::cout << std::endl;
          memcpy(out+n*d_bits_per_seq, &idx_bin[0], sizeof(unsigned char)*d_bits_per_seq);
        }

        return nblocks*d_bits_per_seq;
    }

  } /* namespace ieee802_15_4 */
} /* namespace gr */

