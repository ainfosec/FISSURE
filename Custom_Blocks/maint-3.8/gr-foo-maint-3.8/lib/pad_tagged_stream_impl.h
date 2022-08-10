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

#ifndef INCLUDED_FOO_PAD_TAGGED_STREAM_IMPL_H
#define INCLUDED_FOO_PAD_TAGGED_STREAM_IMPL_H

#include <foo/pad_tagged_stream.h>

namespace gr {
  namespace foo {

    class pad_tagged_stream_impl : public pad_tagged_stream
    {
     private:
      int d_buf_len;
      std::string d_len_tag;

     public:
      pad_tagged_stream_impl(int buffer_size, const std::string len_tag_name);
      ~pad_tagged_stream_impl();

      int calculate_output_stream_length(const gr_vector_int &ninput_items);

      // Where all the action really happens
      int work(int noutput_items,
           gr_vector_int &ninput_items,
           gr_vector_const_void_star &input_items,
           gr_vector_void_star &output_items);
    };

  } // namespace foo
} // namespace gr

#endif /* INCLUDED_FOO_PAD_TAGGED_STREAM_IMPL_H */

