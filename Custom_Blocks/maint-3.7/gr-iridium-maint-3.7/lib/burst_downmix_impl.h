/* -*- c++ -*- */
/* 
 * Copyright 2016 Free Software Foundation, Inc
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

#ifndef INCLUDED_IRIDIUM_TOOLKIT_BURST_DOWNMIX_IMPL_H
#define INCLUDED_IRIDIUM_TOOLKIT_BURST_DOWNMIX_IMPL_H

#include <gnuradio/blocks/rotator.h>
#include <gnuradio/filter/fir_filter.h>

#include <iridium/burst_downmix.h>

namespace gr {
  namespace iridium {

    class burst_downmix_impl : public burst_downmix
    {
     private:
      float d_output_sample_rate;
      int d_output_samples_per_symbol;
      size_t d_max_burst_size;
      int d_search_depth;
      int d_pre_start_samples;
      int d_cfo_est_fft_size;
      int d_fft_over_size_facor;
      int d_corr_fft_size;
      int d_sync_search_len;
      int d_hard_max_queue_len;
      uint64_t d_n_dropped_bursts;
      bool d_handle_multiple_frames_per_burst;
      bool d_debug;

      gr_complex * d_frame;
      gr_complex * d_tmp_a;
      gr_complex * d_tmp_b;
      gr_complex * d_dl_preamble_reversed_conj_fft;
      gr_complex * d_ul_preamble_reversed_conj_fft;

      float * d_magnitude_f;
      float * d_magnitude_filtered_f;
      float * d_cfo_est_window_f;

      gr::fft::fft_complex * d_corr_fft;
      gr::fft::fft_complex * d_corr_dl_ifft;
      gr::fft::fft_complex * d_corr_ul_ifft;

      filter::kernel::fir_filter_ccf d_input_fir;
      filter::kernel::fir_filter_fff d_start_finder_fir;
      filter::kernel::fir_filter_ccf d_rrc_fir;

      std::vector<gr_complex> d_dl_preamble_reversed_conj;
      std::vector<gr_complex> d_ul_preamble_reversed_conj;

      blocks::rotator d_r;
      gr::fft::fft_complex d_cfo_est_fft;

      void handler(pmt::pmt_t msg);
      int process_next_frame(float sample_rate, float center_frequency,
            uint64_t offset, uint64_t id, size_t burst_size, int start);
 
      void update_buffer_sizes(size_t burst_size);
      void initialize_cfo_est_fft(void);
      void initialize_correlation_filter(void);
      std::vector<gr_complex> generate_sync_word(::iridium::direction direction);
      int fft_shift_index(int index, int fft_size);
      int fft_unshift_index(int index, int fft_size);

     public:
      burst_downmix_impl(int sample_rate, int search_depth, size_t hard_max_queue_len,
            const std::vector<float> &input_taps, const std::vector<float> &start_finder_taps,
            bool handle_multiple_frames_per_burst);
      ~burst_downmix_impl();

      size_t get_input_queue_size();
      uint64_t get_n_dropped_bursts();

      int work(int noutput_items,
         gr_vector_const_void_star &input_items,
         gr_vector_void_star &output_items);
    };

  } // namespace iridium
} // namespace gr

#endif /* INCLUDED_IRIDIUM_TOOLKIT_BURST_DOWNMIX_IMPL_H */

