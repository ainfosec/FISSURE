/* -*- c++ -*- */
/*
 * Copyright 2019 "Cyancali".
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
#include "pad_tagged_stream_impl.h"

namespace gr {
  namespace foo {

    pad_tagged_stream::sptr
    pad_tagged_stream::make(int buffer_size, const std::string len_tag_name)
    {
      return gnuradio::get_initial_sptr
        (new pad_tagged_stream_impl(buffer_size, len_tag_name));
    }


    /*
     * The private constructor
     */
    pad_tagged_stream_impl::pad_tagged_stream_impl(int buffer_size, const std::string len_tag_name)
      : gr::tagged_stream_block("pad_tagged_stream",
                                gr::io_signature::make(1, 1, sizeof(gr_complex)),
                                gr::io_signature::make(1, 1, sizeof(gr_complex)),
                                len_tag_name),
        d_buf_len(buffer_size),
        d_len_tag(len_tag_name)
    {
        set_min_output_buffer(buffer_size*2);
        set_tag_propagation_policy(TPP_DONT);
    }

    /*
     * Our virtual destructor.
     */
    pad_tagged_stream_impl::~pad_tagged_stream_impl()
    {
    }

    int
    pad_tagged_stream_impl::calculate_output_stream_length(const gr_vector_int &ninput_items)
    {
      return d_buf_len;
    }

    int
    pad_tagged_stream_impl::work (int noutput_items,
                       gr_vector_int &ninput_items,
                       gr_vector_const_void_star &input_items,
                       gr_vector_void_star &output_items)
    {
      const gr_complex *in = (const gr_complex *) input_items[0];
      gr_complex *out = (gr_complex *) output_items[0];

      noutput_items = d_buf_len;


      memcpy(out, in, sizeof(gr_complex) * std::min(d_buf_len, ninput_items[0]));

      if (ninput_items[0] <= noutput_items)
      {
        memset((out+ninput_items[0]), 0, sizeof(gr_complex) * noutput_items-ninput_items[0]);
      }
      else // ninput_items[0] > noutput_items
      {
        std::cout << "PadTaggedStream: Warning - Tagged stream is longer than buffer" << std::endl;
      }

      return noutput_items;
    }

  } /* namespace foo */
} /* namespace gr */

