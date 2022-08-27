/* -*- c++ -*- */
/* 
 * Copyright 2014 Jared Boone <jared@sharebrained.com>.
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
#include "ask_env_impl.h"

namespace gr {
  namespace tpms {

    ask_env::sptr
    ask_env::make(float alpha)
    {
      return gnuradio::get_initial_sptr
        (new ask_env_impl(alpha));
    }

    /*
     * The private constructor
     */
    ask_env_impl::ask_env_impl(float alpha)
      : gr::sync_block("ask_env",
              gr::io_signature::make(1, 1, sizeof(float)),
              gr::io_signature::make(1, 1, sizeof(float))),
        d_max(0),
        d_min(0)
    {
      set_alpha(alpha);
    }

    /*
     * Our virtual destructor.
     */
    ask_env_impl::~ask_env_impl()
    {
    }

    float
    ask_env_impl::alpha() {
      return d_alpha;
    }

    void
    ask_env_impl::set_alpha(float alpha) {
      d_alpha = alpha;
    }
    
    int
    ask_env_impl::work(int noutput_items,
			  gr_vector_const_void_star &input_items,
			  gr_vector_void_star &output_items)
    {
        const float *in = (const float*)input_items[0];
        float *out = (float*)output_items[0];

        for(int i=0; i<noutput_items; i++) {
          if( in[i] > d_max ) {
            d_max = in[i];
          }

          if( in[i] < d_min ) {
            d_min = in[i];
          }

          const float diff = d_max - d_min;
          if( diff > 0.0f ) {
            out[i] = (in[i] - d_min) / (diff * 0.5f) - 1.0f;
          } else {
            out[i] = 0.0f;
          }

          d_max -= diff * d_alpha;
          d_min += diff * d_alpha;
        }

        // Tell runtime system how many output items we produced.
        return noutput_items;
    }

  } /* namespace tpms */
} /* namespace gr */

