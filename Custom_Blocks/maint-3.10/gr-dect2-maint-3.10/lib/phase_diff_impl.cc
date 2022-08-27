/* -*- c++ -*- */
/* 
 * Copyright 2015 Pavel Yazev <pyazev@gmail.com>
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
#include "phase_diff_impl.h"

#include <gnuradio/math.h>
#include <cstdio>

namespace gr {
  namespace dect2 {

    phase_diff::sptr
    phase_diff::make()
    {
      return gnuradio::get_initial_sptr
        (new phase_diff_impl());
    }
    phase_diff_impl::phase_diff_impl()
      : gr::sync_block("phase_diff",
              gr::io_signature::make(1, 1, sizeof(gr_complex)),
              gr::io_signature::make(1, 1, sizeof(float)))
    {
        set_history(4);  
    }

    phase_diff_impl::~phase_diff_impl()
    {
    }


    int
    phase_diff_impl::work(int noutput_items,
			  gr_vector_const_void_star &input_items,
			  gr_vector_void_star &output_items)
    {
        const gr_complex *in  = (const gr_complex *) input_items[0];
        float            *out = (float *) output_items[0];

        for(int i = 0; i < noutput_items; i++) 
        {
            gr_complex ph_diff = in[i] * conj(in[i + 3]);
            *out++ = gr::fast_atan2f(ph_diff.imag(), ph_diff.real());
        }
        return noutput_items;
    }

  } /* namespace dect2 */
} /* namespace gr */

