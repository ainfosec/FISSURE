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
#include "preamble_sfd_prefixer_ii_impl.h"

namespace gr {
  namespace ieee802_15_4 {

    preamble_sfd_prefixer_ii::sptr
    preamble_sfd_prefixer_ii::make(std::vector<int> preamble, std::vector<int> sfd, int nsym_frame)
    {
      return gnuradio::get_initial_sptr
        (new preamble_sfd_prefixer_ii_impl(preamble, sfd, nsym_frame));
    }

    /*
     * The private constructor
     */
    preamble_sfd_prefixer_ii_impl::preamble_sfd_prefixer_ii_impl(std::vector<int> preamble, std::vector<int> sfd, int nsym_frame)
      : gr::block("preamble_sfd_prefixer_ii",
              gr::io_signature::make(1,1, sizeof(int)),
              gr::io_signature::make(1,1, sizeof(int)))
    {
      d_preamble_sfd = preamble;
      d_preamble_sfd.insert(d_preamble_sfd.end(), sfd.begin(), sfd.end());
      d_nsym_frame = nsym_frame;
      if(d_nsym_frame < d_preamble_sfd.size())
        throw std::runtime_error("Invalid number of symbols per frame or preamble / SFD");
      d_sym_ctr = 0;
    }

    /*
     * Our virtual destructor.
     */
    preamble_sfd_prefixer_ii_impl::~preamble_sfd_prefixer_ii_impl()
    {
    }

    int
    preamble_sfd_prefixer_ii_impl::general_work (int noutput_items,
                       gr_vector_int &ninput_items,
                       gr_vector_const_void_star &input_items,
                       gr_vector_void_star &output_items)
    {
        const int *in = (const int *) input_items[0];
        int *out = (int *) output_items[0];

        int nitems_consumed = 0;
        for(int i=0; i<noutput_items; i++)
        {
          // insert preamble and SFD at the beginning of each frame
          if(d_sym_ctr < d_preamble_sfd.size())
          {
            out[i] = d_preamble_sfd[d_sym_ctr];   
            d_sym_ctr++;      
          }
          // follow up with PHR and payload
          else
          {
            out[i] = in[nitems_consumed];
            nitems_consumed++;
            d_sym_ctr++;
          }
          // reset counter when EOF is reached
          d_sym_ctr = d_sym_ctr % d_nsym_frame;
        }

        consume_each (nitems_consumed);
        return noutput_items;
    }

  } /* namespace ieee802_15_4 */
} /* namespace gr */

