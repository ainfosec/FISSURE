/* -*- c++ -*- */
/*
 * Copyright 2020 Free Software Foundation, Inc.
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

#ifndef INCLUDED_IRIDIUM_FFT_BURST_TAGGER_IMPL_H
#define INCLUDED_IRIDIUM_FFT_BURST_TAGGER_IMPL_H

#include <iridium/fft_burst_tagger.h>
#include <gnuradio/fft/fft.h>

namespace gr {
  namespace iridium {

    struct burst {
        uint64_t start;
        uint64_t stop;
        uint64_t last_active;
        int center_bin;
        float magnitude;
        float noise;
        uint64_t id;
    };

    struct peak {
        int bin;
        float relative_magnitude;
    };

    class fft_burst_tagger_impl : public fft_burst_tagger
    {
     private:
      bool d_history_primed;
      bool d_debug;
      bool d_offline;

      int d_fft_size;
      int d_burst_pre_len;
      int d_history_size;
      int d_burst_width;
      int d_history_index;
      int d_burst_post_len;
      int d_max_bursts;
      int d_sample_rate;
      uint64_t d_index;
      uint64_t d_burst_id;
      uint64_t d_n_tagged_bursts;
      uint64_t d_sample_count;
      uint64_t d_last_rx_time_offset;
      uint64_t d_last_rx_time_timestamp;

      float * d_window_f;
      float * d_magnitude_f;
      float * d_magnitude_shifted_f;
      float * d_baseline_sum_f;
      float * d_baseline_history_f;
      float * d_relative_magnitude_f;
      float * d_burst_mask_f;
      float * d_ones_f;
      float d_threshold;
      float d_center_frequency;
      float d_window_enbw;

      FILE * d_burst_debug_file;

      gr::fft::fft_complex          *d_fft;
      std::vector<peak> d_peaks;
      std::vector<burst> d_bursts;
      std::vector<burst> d_new_bursts;
      std::vector<burst> d_gone_bursts;

      bool update_filters_pre(void);
      void update_filters_post(void);
      void extract_peaks(void);
      void save_peaks_to_debug_file(char * filename);
      void remove_peaks_around_bursts(void);
      void update_burst_mask(void);
      void update_bursts(void);
      void delete_gone_bursts(void);
      void create_new_bursts(void);
      void mask_burst(burst &b);
      void tag_new_bursts(void);
      void tag_gone_bursts(int noutput_items);

     public:
      fft_burst_tagger_impl(float center_frequency, int fft_size, int sample_rate,
                            int burst_pre_len, int burst_post_len, int burst_width,
                            int max_bursts, float threshold, int history_size,
                            bool offline, bool debug);
      ~fft_burst_tagger_impl();

      uint64_t get_n_tagged_bursts();
      uint64_t get_sample_count();

      int work(int noutput_items,
         gr_vector_const_void_star &input_items,
         gr_vector_void_star &output_items);
    };

  } // namespace iridium
} // namespace gr

#endif /* INCLUDED_IRIDIUM_FFT_BURST_TAGGER_IMPL_H */

