/* -*- c++ -*- */
/*
 * Copyright 2020 gr-iridium author.
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
#include "iuchar_to_complex_impl.h"

namespace gr {
  namespace iridium {

    iuchar_to_complex::sptr
    iuchar_to_complex::make()
    {
      return gnuradio::get_initial_sptr
        (new iuchar_to_complex_impl());
    }


    /*
     * The private constructor
     */
    iuchar_to_complex_impl::iuchar_to_complex_impl()
      : gr::sync_decimator("iuchar_to_complex",
              gr::io_signature::make(1, 1, sizeof(uint8_t)),
              gr::io_signature::make(1, 1, sizeof(gr_complex)), 2)
    {
      // From gr-osmosdr:
      // create a lookup table for gr_complex values
      for (unsigned int i = 0; i <= 0xffff; i++) {
      #ifdef BOOST_LITTLE_ENDIAN
        d_lut.push_back( gr_complex( (float(i & 0xff) - 127.4f) * (1.0f/128.0f),
                                     (float(i >> 8) - 127.4f) * (1.0f/128.0f) ) );
      #else // BOOST_BIG_ENDIAN
        d_lut.push_back( gr_complex( (float(i >> 8) - 127.4f) * (1.0f/128.0f),
                                     (float(i & 0xff) - 127.4f) * (1.0f/128.0f) ) );
      #endif
      }
    }

    /*
     * Our virtual destructor.
     */
    iuchar_to_complex_impl::~iuchar_to_complex_impl()
    {
    }

    int
    iuchar_to_complex_impl::work(int noutput_items,
        gr_vector_const_void_star &input_items,
        gr_vector_void_star &output_items)
    {
      const unsigned short *in = (const unsigned short *) input_items[0];
      gr_complex *out = (gr_complex *) output_items[0];


      for(int i = 0; i < noutput_items; ++i)
        *out++ = d_lut[ *(in + i) ];


      // Tell runtime system how many output items we produced.
      return noutput_items;
    }

  } /* namespace iridium */
} /* namespace gr */

