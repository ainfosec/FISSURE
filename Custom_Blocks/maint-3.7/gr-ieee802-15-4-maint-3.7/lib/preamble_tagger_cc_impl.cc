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
#include "preamble_tagger_cc_impl.h"

namespace gr {
  namespace ieee802_15_4 {

    preamble_tagger_cc::sptr
    preamble_tagger_cc::make(int len_preamble)
    {
      return gnuradio::get_initial_sptr
        (new preamble_tagger_cc_impl(len_preamble));
    }

    /*
     * The private constructor
     */
    preamble_tagger_cc_impl::preamble_tagger_cc_impl(int len_preamble)
      : gr::sync_block("preamble_tagger_cc",
              gr::io_signature::make(1, 1, sizeof(gr_complex)),
              gr::io_signature::make(1, 1, sizeof(gr_complex))),
      d_len_preamble(len_preamble)
    {
      set_output_multiple(2*d_len_preamble);
      set_tag_propagation_policy(TPP_DONT);
    }

    /*
     * Our virtual destructor.
     */
    preamble_tagger_cc_impl::~preamble_tagger_cc_impl()
    {
    }

    int
    preamble_tagger_cc_impl::work(int noutput_items,
			  gr_vector_const_void_star &input_items,
			  gr_vector_void_star &output_items)
    {
        const gr_complex *in = (const gr_complex *) input_items[0];
        gr_complex *out = (gr_complex *) output_items[0];

        int ctr = 1;
        for(int i=1; i<2*d_len_preamble-1; i++)
        {
          if(std::arg(in[i]/in[i-1]) < M_PI/4)
          {
            ctr++;
          }
          else
          {
            ctr = 1;
          }
          if(ctr >= d_len_preamble && std::abs(std::arg(in[i+1]/in[i])) > M_PI/4) // first SFD symbol after preamble has different phase
          {
            // std::cout << "Preamble tagger: Add SOF tag after " << nitems_read(0) + i - (d_len_preamble - 1) << " symbols" << std::endl;
            add_item_tag(0, nitems_written(0)+i-(d_len_preamble-1), pmt::string_to_symbol("SOF"), pmt::from_long(0));
            ctr = 1;
          }
        }

        memcpy(out, in, sizeof(gr_complex)*d_len_preamble);
        return d_len_preamble;
    }

  } /* namespace ieee802_15_4 */
} /* namespace gr */

