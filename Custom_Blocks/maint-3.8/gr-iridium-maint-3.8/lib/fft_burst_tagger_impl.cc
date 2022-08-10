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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <gnuradio/io_signature.h>
#include <gnuradio/fft/fft.h>
#include <gnuradio/fft/window.h>

#include "fft_burst_tagger_impl.h"

#include <volk/volk.h>

#include <stdio.h>
#include <inttypes.h>

namespace gr {
  namespace iridium {

    fft_burst_tagger::sptr
    fft_burst_tagger::make(float center_frequency, int fft_size, int sample_rate,
                            int burst_pre_len, int burst_post_len, int burst_width,
                            int max_bursts, float threshold, int history_size,
                            bool offline, bool debug)
    {
      return gnuradio::get_initial_sptr
        (new fft_burst_tagger_impl(center_frequency, fft_size, sample_rate,
                burst_pre_len, burst_post_len, burst_width,
                max_bursts, threshold, history_size, offline, debug));
    }


    /*
     * The private constructor
     */
    fft_burst_tagger_impl::fft_burst_tagger_impl(float center_frequency, int fft_size, int sample_rate,
                        int burst_pre_len, int burst_post_len, int burst_width,
                        int max_bursts, float threshold, int history_size,
                        bool offline, bool debug)
      : gr::sync_block("fft_burst_tagger",
              gr::io_signature::make(1, 1, sizeof(gr_complex)),
              gr::io_signature::make(1, 1, sizeof(gr_complex))),
        d_center_frequency(center_frequency), d_sample_rate(sample_rate),
        d_fft_size(fft_size), d_burst_pre_len(burst_pre_len),
        d_burst_id(0),
        d_sample_count(0),
        d_n_tagged_bursts(0),
        d_fft(NULL), d_history_size(history_size), d_peaks(std::vector<peak>()),
        d_bursts(std::vector<burst>()), d_history_primed(false), d_history_index(0),
        d_burst_post_len(burst_post_len), d_debug(debug), d_burst_debug_file(NULL),
        d_last_rx_time_offset(0),
        d_last_rx_time_timestamp(0),
        d_offline(offline)
    {
        const int nthreads = 1;
        d_fft = new fft::fft_complex(d_fft_size, true, nthreads);

        set_output_multiple(d_fft_size);

        // We need to keep d_burst_pre_len samples
        // in the buffer to be able to tag a burst at it's start.
        // Set the history to this + 1, so we always have
        // this amount of samples available at the start of
        // our input buffer.
        set_history(d_burst_pre_len + 1);

        d_window_f = (float *)volk_malloc(sizeof(float) * d_fft_size, volk_get_alignment());
        std::vector<float> window = fft::window::build(fft::window::WIN_BLACKMAN, d_fft_size, 0);
        memcpy(d_window_f, &window[0], sizeof(float) * d_fft_size);

        // To get better SNR and noise floor estimates we apply the scaling factor and
        // Equivalent noise bandwidth of our window.
        // See https://www.sjsu.edu/people/burford.furman/docs/me120/FFT_tutorial_NI.pdf page 15
        // And https://www.ap.com/blog/fft-spectrum-and-spectral-densities-same-data-different-scaling/

        // Scaling factor
        for(int j=0; j<d_fft_size; j++) {
          d_window_f[j] /= 0.42;
        }

        // Equivalent noise bandwidth
        d_window_enbw = 1.72;

        d_baseline_history_f = (float *)volk_malloc(sizeof(float) * d_fft_size * d_history_size, volk_get_alignment());
        d_baseline_sum_f = (float *)volk_malloc(sizeof(float) * d_fft_size, volk_get_alignment());
        d_magnitude_f = (float *)volk_malloc(sizeof(float) * d_fft_size, volk_get_alignment());
        d_magnitude_shifted_f = (float *)volk_malloc(sizeof(float) * d_fft_size, volk_get_alignment());
        d_relative_magnitude_f = (float *)volk_malloc(sizeof(float) * d_fft_size, volk_get_alignment());
        d_burst_mask_f = (float *)volk_malloc(sizeof(float) * d_fft_size, volk_get_alignment());
        d_ones_f = (float *)volk_malloc(sizeof(float) * d_fft_size, volk_get_alignment());

        memset(d_baseline_history_f, 0, sizeof(float) * d_fft_size * d_history_size);
        memset(d_baseline_sum_f, 0, sizeof(float) * d_fft_size);
        memset(d_magnitude_f, 0, sizeof(float) * d_fft_size);
        memset(d_magnitude_shifted_f, 0, sizeof(float) * d_fft_size);
        memset(d_relative_magnitude_f, 0, sizeof(float) * d_fft_size);

        for(int i = 0; i < d_fft_size; i++) {
            d_ones_f[i] = 1.0;
            d_burst_mask_f[i] = 1.0;
        }

        // Divide by the ENBW as the calculation of d_relative_magnitude_f does
        // not take the ENBW of the FFT into account.
        d_threshold = pow(10, threshold/10) / d_history_size / d_window_enbw;
        if(d_debug) {
          fprintf(stderr, "threshold=%f, d_threshold=%f (%f/%d)\n",
              threshold, d_threshold, d_threshold * d_history_size, d_history_size);
        }

        d_peaks.reserve(d_fft_size);
        
        if(max_bursts){
          d_max_bursts = max_bursts;
        } else {
          // Consider the signal to be invalid if more than 80%
          // of all channels are in use.
          d_max_bursts = (sample_rate / burst_width) * 0.8;
        }

        // Area to ignore around an already found signal in FFT bins
        // Internal representation is in FFT bins
        d_burst_width = burst_width / (sample_rate / fft_size);

        if(d_debug) {
          fprintf(stderr, "d_max_bursts=%d\n", d_max_bursts);
        }

        if(d_debug) {
          d_burst_debug_file = fopen("/tmp/fft_burst_tagger-bursts.log", "w");
        }
    }

    /*
     * Our virtual destructor.
     */
    fft_burst_tagger_impl::~fft_burst_tagger_impl()
    {
      fprintf(stderr, "Tagged %" PRIu64 " bursts\n", d_n_tagged_bursts);
      delete d_fft;
      volk_free(d_window_f);
      volk_free(d_baseline_history_f);
      volk_free(d_baseline_sum_f);
      volk_free(d_relative_magnitude_f);
      if(d_burst_debug_file) {
        fclose(d_burst_debug_file);
      }
    }

    bool
    fft_burst_tagger_impl::update_filters_pre(void)
    {
      if(!d_history_primed) {
        return false;
      }
      
      volk_32f_x2_divide_32f(d_relative_magnitude_f, d_magnitude_shifted_f, d_baseline_sum_f, d_fft_size);
      return true;
    }
           
#define HIST(i) (d_baseline_history_f + (i % d_history_size) * d_fft_size)
    void
    fft_burst_tagger_impl::update_filters_post(void)
    {
      // We only update the average if there is no burst going on at the moment
      if(d_bursts.size() == 0) {
        volk_32f_x2_subtract_32f(d_baseline_sum_f, d_baseline_sum_f, HIST(d_history_index), d_fft_size);
        volk_32f_x2_add_32f(d_baseline_sum_f, d_baseline_sum_f, d_magnitude_shifted_f, d_fft_size);
        memcpy(HIST(d_history_index), d_magnitude_shifted_f,  sizeof(float) * d_fft_size);

        d_history_index++;

        if(d_history_index == d_history_size) {
          d_history_primed = true;
        }
      }
    }

    void
    fft_burst_tagger_impl::update_bursts(void)
    {
      auto b = std::begin(d_bursts);
      while (b != std::end(d_bursts)) {
        if(d_relative_magnitude_f[b->center_bin-1] > d_threshold ||
           d_relative_magnitude_f[b->center_bin] > d_threshold ||
           d_relative_magnitude_f[b->center_bin+1] > d_threshold) {
          b->last_active = d_index;
        }
        ++b;
      }
    }

    void
    fft_burst_tagger_impl::delete_gone_bursts(void)
    {
      auto b = std::begin(d_bursts);

      while (b != std::end(d_bursts)) {
        if((b->last_active + d_burst_post_len) < d_index) {
          //printf("Deleting gone burst %" PRIu64 " (start=%" PRIu64 ", d_index=%" PRIu64 ")\n", b->id, b->start, d_index); 
          b->stop = d_index;
          d_gone_bursts.push_back(*b);
          b = d_bursts.erase(b);
        } else {
          ++b;
        }
      }
    }

    void
    fft_burst_tagger_impl::create_new_bursts(void)
    {
      for(peak p : d_peaks) {
        if(d_burst_mask_f[p.bin]) {
          burst b;
          b.id = d_burst_id;
          b.center_bin = p.bin;

          // Allow downstream blocks to split this burst
          // and assign sub ids
          d_burst_id += 10;

          // Normalize the relative magnitude
          // relative_magnitude relates to the uncorrected (regarding ENBW) noise floor.
          // We apply the ENBW here to have a more accurate SNR estimate
          b.magnitude = 10 * log10(p.relative_magnitude * d_history_size * d_window_enbw);
          // The burst might have started one FFT earlier
          b.start = d_index - d_burst_pre_len;
          b.last_active = b.start;
          // Keep noise level around (dbFS/Hz)
          // Need to divide by the fft size twice as d_baseline_sum_f is a square of the FFT's magnitude
          // Apply the ENBW again to get an accurate estimate
          b.noise = 10 * log10(d_baseline_sum_f[b.center_bin] / d_history_size / (d_fft_size * d_fft_size) / d_window_enbw / (d_sample_rate / d_fft_size));

          d_bursts.push_back(b);
          d_new_bursts.push_back(b);
          mask_burst(b);

          if(d_burst_debug_file) {
            fprintf(d_burst_debug_file, "%" PRIu64 ",%d,x\n", b.start, b.center_bin);
            //float f_rel = (b.center_bin - d_fft_size / 2) / float(d_fft_size);
            //fprintf(d_burst_debug_file, "%f,%f,x\n", b.start/4e6, f_rel * 4e6 + 1624800000);
          }
        }
      }
      if(d_max_bursts > 0 && d_bursts.size() > d_max_bursts) {
        fprintf(stderr, "Detector in burst squelch at %f\n", d_index / float(d_sample_rate));
        d_new_bursts.clear();
        for(burst b : d_bursts) {
          if(b.start != d_index - d_burst_pre_len) {
            b.stop = d_index;
            d_gone_bursts.push_back(b);
          }
        }
        d_bursts.clear();
      }
    }

    void
    fft_burst_tagger_impl::mask_burst(burst &b)
    {
      int clear_start = std::max(b.center_bin - d_burst_width / 2, 0);
      int clear_stop = std::min(b.center_bin + d_burst_width / 2, d_fft_size - 1);
      memset(d_burst_mask_f + clear_start, 0, (clear_stop - clear_start + 1) * sizeof(float));
    }

    void
    fft_burst_tagger_impl::update_burst_mask(void)
    {
      memcpy(d_burst_mask_f, d_ones_f, sizeof(float) * d_fft_size);
      for(burst b : d_bursts) {
        mask_burst(b);
      }
    }

    void
    fft_burst_tagger_impl::remove_peaks_around_bursts(void)
    {
      volk_32f_x2_multiply_32f(d_relative_magnitude_f, d_relative_magnitude_f, d_burst_mask_f, d_fft_size);
    }

    void
    fft_burst_tagger_impl::extract_peaks(void)
    {

      d_peaks.clear();

      for(int bin = d_burst_width / 2; bin < (d_fft_size - d_burst_width / 2); bin++) {
        if(d_relative_magnitude_f[bin] > d_threshold) {
          peak p;
          p.bin = bin;
          p.relative_magnitude = d_relative_magnitude_f[bin];
          d_peaks.push_back(p);
          //printf("ts %" PRIu64 " bin %d val %f\n", d_index, p.bin, p.relative_magnitude);
        }
      }

      struct {
        bool operator()(peak a, peak b)
        {   
          return a.relative_magnitude > b.relative_magnitude;
        }   
      } mag_gt;

      std::sort(d_peaks.begin(), d_peaks.end(), mag_gt);
    }

    void
    fft_burst_tagger_impl::save_peaks_to_debug_file(char * filename)
    {
      FILE * file = fopen(filename, "a");
      for(peak p : d_peaks) {
        fprintf(file, "%" PRIu64 ",%d,x\n", d_index, p.bin);
        //float f_rel = (p.bin - d_fft_size / 2) / float(d_fft_size);
        //fprintf(file, "%f,%f,x\n", d_index/4e6, f_rel * 4e6 + 1624800000);
      }
      fclose(file);
    }

    void
    fft_burst_tagger_impl::tag_new_bursts(void)
    {
      for(burst b : d_new_bursts) {
        //printf("new burst %" PRIu64 " %" PRIu64 " %" PRIu64 "\n", nitems_read(0), b.start, nitems_read(0) - b.start);
        pmt::pmt_t key = pmt::string_to_symbol("new_burst");
        float relative_frequency = (b.center_bin - d_fft_size / 2) / float(d_fft_size);


        const uint64_t offset = b.start - d_last_rx_time_offset;
        const uint64_t timestamp = d_last_rx_time_timestamp + offset * 1e9 / d_sample_rate;

        pmt::pmt_t value = pmt::make_dict();
        value = pmt::dict_add(value, pmt::mp("id"), pmt::from_uint64(b.id));
        value = pmt::dict_add(value, pmt::mp("relative_frequency"), pmt::from_float(relative_frequency));
        value = pmt::dict_add(value, pmt::mp("center_frequency"), pmt::from_float(d_center_frequency));
        value = pmt::dict_add(value, pmt::mp("magnitude"), pmt::from_float(b.magnitude));
        value = pmt::dict_add(value, pmt::mp("sample_rate"), pmt::from_float(d_sample_rate));
        value = pmt::dict_add(value, pmt::mp("timestamp"), pmt::from_uint64(timestamp));
        value = pmt::dict_add(value, pmt::mp("noise"), pmt::from_float(b.noise));

        // Our output is lagging by d_burst_pre_len samples.
        // Compensate by moving the tag into the past
        //printf("Tagging new burst %" PRIu64 " on sample %" PRIu64 " (nitems_read(0)=%" PRIu64 ")\n", b.id, b.start + d_burst_pre_len, nitems_read(0));
        add_item_tag(0, b.start + d_burst_pre_len, key, value);
      }
      d_new_bursts.clear();
    }

    void
    fft_burst_tagger_impl::tag_gone_bursts(int noutput_items)
    {
      auto b = std::begin(d_gone_bursts);

      while (b != std::end(d_gone_bursts)) {
        uint64_t output_index = b->stop + d_burst_pre_len;

        if(nitems_read(0) <= output_index && output_index < nitems_read(0) + noutput_items) {
          pmt::pmt_t key = pmt::string_to_symbol("gone_burst");
          pmt::pmt_t value = pmt::make_dict();
          value = pmt::dict_add(value, pmt::mp("id"), pmt::from_uint64(b->id));
          //printf("Tagging gone burst %" PRIu64 " on sample %" PRIu64 " (nitems_read(0)=%" PRIu64 ", noutput_items=%u)\n", b->id, output_index, nitems_read(0), noutput_items);
          add_item_tag(0, output_index, key, value);
          d_n_tagged_bursts++;

          b = d_gone_bursts.erase(b);
        } else {
          ++b;
        }
      }
    }

    uint64_t
    fft_burst_tagger_impl::get_n_tagged_bursts()
    {
      return d_n_tagged_bursts;
    }

    uint64_t
    fft_burst_tagger_impl::get_sample_count()
    {
      return d_sample_count;
    }

    int
    fft_burst_tagger_impl::work(int noutput_items,
        gr_vector_const_void_star &input_items,
        gr_vector_void_star &output_items)
    {
	  d_sample_count+=noutput_items;

      // We keep d_burst_pre_len additional samples in front of our data
      const gr_complex *in = (const gr_complex *) input_items[0] + d_burst_pre_len;
      gr_complex *out = (gr_complex *) output_items[0];

      assert(noutput_items % d_fft_size == 0);

      if(d_last_rx_time_timestamp == 0 && !d_offline) {
        struct timeval time_now{};
        gettimeofday(&time_now, nullptr);
        d_last_rx_time_timestamp = time_now.tv_sec * 1e9 + time_now.tv_usec * 1e3;
      }

      std::vector<tag_t> rx_time_tags;
      get_tags_in_window(rx_time_tags, 0, 0, noutput_items, pmt::mp("rx_time"));
      if(!rx_time_tags.empty()) {
        std::sort(rx_time_tags.begin(), rx_time_tags.end(), tag_t::offset_compare);
        const auto& rx_time_tag = rx_time_tags.back();

        d_last_rx_time_offset = rx_time_tag.offset;

        const pmt::pmt_t& value = rx_time_tag.value;
        const uint64_t seconds = pmt::to_uint64(pmt::tuple_ref(value, 0));
        const double seconds_fraction = pmt::to_double(pmt::tuple_ref(value, 1));

        d_last_rx_time_timestamp = seconds * 1e9 + seconds_fraction * 1e9;
      }

      for(int i = 0; i < noutput_items; i += d_fft_size) {
        d_index = nitems_read(0) + i;

        volk_32fc_32f_multiply_32fc(d_fft->get_inbuf(), &in[i], d_window_f, d_fft_size);
        d_fft->execute();
        volk_32fc_magnitude_squared_32f(d_magnitude_f, d_fft->get_outbuf(), d_fft_size);
        memcpy(&d_magnitude_shifted_f[0], &d_magnitude_f[d_fft_size/2], sizeof(float) * d_fft_size/2);
        memcpy(&d_magnitude_shifted_f[d_fft_size/2], &d_magnitude_f[0], sizeof(float) * d_fft_size/2);

        if(update_filters_pre()) {
          update_bursts();
          if(d_debug) {
            extract_peaks();
            save_peaks_to_debug_file((char *)"/tmp/fft_burst_tagger-peaks.log");
          }
          remove_peaks_around_bursts();
          extract_peaks();
          if(d_debug) {
            save_peaks_to_debug_file((char *)"/tmp/fft_burst_tagger-peaks-filtered.log");
          }
          delete_gone_bursts();
          update_burst_mask();
          create_new_bursts();
        }
        update_filters_post();
      }

      memcpy(out, in - d_burst_pre_len, sizeof(gr_complex) * noutput_items); 

      tag_new_bursts();
      tag_gone_bursts(noutput_items);

      // Tell runtime system how many output items we produced.
      return noutput_items;
    }

  } /* namespace iridium */
} /* namespace gr */

