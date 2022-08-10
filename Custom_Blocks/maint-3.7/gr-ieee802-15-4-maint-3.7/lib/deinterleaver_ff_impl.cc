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
#include "deinterleaver_ff_impl.h"

namespace gr {
  namespace ieee802_15_4 {

    deinterleaver_ff::sptr
    deinterleaver_ff::make(std::vector<int> intlv_seq)
    {
      return gnuradio::get_initial_sptr
        (new deinterleaver_ff_impl(intlv_seq));
    }

    /*
     * The private constructor
     */
    deinterleaver_ff_impl::deinterleaver_ff_impl(std::vector<int> intlv_seq)
      : gr::sync_block("deinterleaver_ff",
              gr::io_signature::make(1,1, sizeof(float)),
              gr::io_signature::make(1,1, sizeof(float))),
              d_intlv_seq(intlv_seq),
              d_len_intlv_seq(intlv_seq.size())
    {
      if(d_len_intlv_seq != 0)
        set_output_multiple(d_len_intlv_seq);
    }

    /*
     * Our virtual destructor.
     */
    deinterleaver_ff_impl::~deinterleaver_ff_impl()
    {
    }

    int
    deinterleaver_ff_impl::work(int noutput_items,
			  gr_vector_const_void_star &input_items,
			  gr_vector_void_star &output_items)
    {
        const float *in = (const float *) input_items[0];
        float *out = (float *) output_items[0];

        if(d_len_intlv_seq != 0) // if no interleaver sequence is given, copy input to output
        {
          int nblocks = noutput_items/d_len_intlv_seq;
          for(int n=0; n<nblocks; n++)
          {
            for(int i=0; i<d_len_intlv_seq; i++)
              out[n*d_len_intlv_seq+d_intlv_seq[i]] = in[n*d_len_intlv_seq+i];                   
          }  
        }
        else
        {
          memcpy(out, in, sizeof(int)*noutput_items);
        }
        return noutput_items;
    }

  } /* namespace ieee802_15_4 */
} /* namespace gr */

