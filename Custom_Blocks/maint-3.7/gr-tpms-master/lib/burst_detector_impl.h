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

#ifndef INCLUDED_TPMS_BURST_DETECTOR_IMPL_H
#define INCLUDED_TPMS_BURST_DETECTOR_IMPL_H

#include <tpms/burst_detector.h>

#include <fftw3.h>

namespace gr {
  namespace tpms {

    class burst_detector_impl : public burst_detector
    {
     private:
      unsigned int d_hysteresis_timeout;
      unsigned int d_hysteresis_count;
      bool d_burst;
      pmt::pmt_t d_tag_burst;

      size_t d_block_size;
      size_t d_advance;
      size_t d_readahead_items;

      float* d_fft_window;
      float* d_temp_f;

      gr_complex *d_fft_in;
      gr_complex *d_fft_out;
      fftwf_plan d_fft_plan;

     public:
      burst_detector_impl();
      ~burst_detector_impl();

      void forecast(int noutput_items,
           gr_vector_int &ninput_items_required);
      
      int general_work(int noutput_items,
           gr_vector_int &ninput_items,
		       gr_vector_const_void_star &input_items,
		       gr_vector_void_star &output_items);
    };

  } // namespace tpms
} // namespace gr

#endif /* INCLUDED_TPMS_BURST_DETECTOR_IMPL_H */

