/* -*- c++ -*- */
/* 
 * Copyright 2015 Ron Economos.
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

#ifndef INCLUDED_PAINT_PAINT_BC_IMPL_H
#define INCLUDED_PAINT_PAINT_BC_IMPL_H

#include <paint/paint_bc.h>
#include <gnuradio/fft/fft.h>

namespace gr {
  namespace paint {

    class paint_bc_impl : public paint_bc
    {
     private:
      int image_width;
      int line_repeat;
      int pixel_repeat;
      int left_nulls;
      int right_nulls;
      int random_source;
      int equalization_enable;
      gr_complex m_point[1];
      fft::fft_complex_rev ofdm_fft;
      int ofdm_fft_size;
      float normalization;
      float magnitude_line[4096];
      float angle_line[4096];
      float angle_cos[4096];
      float angle_sin[4096];
      gr_complex inverse_sinc[4096];

     public:
      paint_bc_impl(int width, int repeats, int equalization, int randomsrc, int inputs);
      ~paint_bc_impl();

      // Where all the action really happens
      void forecast (int noutput_items, gr_vector_int &ninput_items_required);

      int general_work(int noutput_items,
		       gr_vector_int &ninput_items,
		       gr_vector_const_void_star &input_items,
		       gr_vector_void_star &output_items);
    };

  } // namespace paint
} // namespace gr

#endif /* INCLUDED_PAINT_PAINT_BC_IMPL_H */

