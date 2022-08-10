/* -*- c++ -*- */
/*
 * Copyright 2017 Clayton Smith.
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

#ifndef INCLUDED_NRSC5_HDC_ENCODER_IMPL_H
#define INCLUDED_NRSC5_HDC_ENCODER_IMPL_H

#include <nrsc5/hdc_encoder.h>

extern "C" {
#include "fdk-aac/aacenc_lib.h"
}

namespace gr {
  namespace nrsc5 {

    class hdc_encoder_impl : public hdc_encoder
    {
     private:
      int channels;
      int bytes_per_frame;
      HANDLE_AACENCODER handle;
      int frame_length;
      int max_out_buf_bytes;
      short *convert_buf;
      unsigned char *outbuf;
      int outbuf_off;
      int outbuf_len;

     public:
      hdc_encoder_impl(int channels, int bitrate);
      ~hdc_encoder_impl();

      // Where all the action really happens
      void forecast (int noutput_items, gr_vector_int &ninput_items_required);

      int general_work(int noutput_items,
           gr_vector_int &ninput_items,
           gr_vector_const_void_star &input_items,
           gr_vector_void_star &output_items);

    };

  } // namespace nrsc5
} // namespace gr

#endif /* INCLUDED_NRSC5_HDC_ENCODER_IMPL_H */
