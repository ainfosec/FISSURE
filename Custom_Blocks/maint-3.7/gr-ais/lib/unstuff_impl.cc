/* -*- c++ -*- */
/* 
 * Copyright 2013 <+YOU OR YOUR COMPANY+>.
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
#include "unstuff_impl.h"

namespace gr {
  namespace ais {

    unstuff::sptr
    unstuff::make()
    {
      return gnuradio::get_initial_sptr
        (new unstuff_impl());
    }

    /*
     * The private constructor
     */
    unstuff_impl::unstuff_impl()
      : gr::block("unstuff",
              gr::io_signature::make(1, 1, sizeof(char)),
              gr::io_signature::make(1, 1, sizeof(char)))
    {
        set_relative_rate((double)1.0);
        d_consecutive = 0;
        set_output_multiple(1000);
    }

    /*
     * Our virtual destructor.
     */
    unstuff_impl::~unstuff_impl()
    {
    }

    void
    unstuff_impl::forecast (int noutput_items, gr_vector_int &ninput_items_required)
    {
        int size = noutput_items + 2*(noutput_items / 256); //on average
        ninput_items_required[0] = size;
    }

    int
    unstuff_impl::general_work (int noutput_items,
                       gr_vector_int &ninput_items,
                       gr_vector_const_void_star &input_items,
                       gr_vector_void_star &output_items)
    {
        const char *in = (const char *) input_items[0];
        char *out = (char *) output_items[0];

        int j = 0;
        int i = 0;

        while(j < noutput_items && i < ninput_items[0]){
            if(in[i] & 0x01) {//if bit 0 is set (the data bit)
                d_consecutive++;
            } else {
                if(d_consecutive == 5) {
                    i++;
            }
                d_consecutive = 0;
            }
                out[j++] = in[i++];
        }

        consume_each(i); //tell gnuradio how many input items we used
        // Tell runtime system how many output items we produced.
        return j;
    }
  } /* namespace ais */
} /* namespace gr */

