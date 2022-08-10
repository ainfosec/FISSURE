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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <gnuradio/io_signature.h>
#include <gnuradio/fft/window.h>
#include <volk/volk.h>

#include "burst_detector_impl.h"

/* Good reference:
 * http://gnuradio.squarespace.com/storage/tutorial/gr_scheduler_overview.pdf
 */

/* TODO: Terrible hack for volk_malloc not being present before
 * GNU Radio 3.7.2.1-something. Remove this and require GR>=3.7.3? */
#if !defined(volk_malloc)
#define volk_malloc(x, y) (fftwf_malloc(x))
#endif
#if !defined(volk_free)
#define volk_free(x) (fftwf_free(x))
#endif

namespace gr {
  namespace tpms {

    burst_detector::sptr
    burst_detector::make()
    {
      return gnuradio::get_initial_sptr
        (new burst_detector_impl());
    }

    /*
     * The private constructor
     */
    burst_detector_impl::burst_detector_impl()
      : gr::block("burst_detector",
              gr::io_signature::make(1, 1, sizeof(gr_complex)),
              gr::io_signature::make(1, 1, sizeof(gr_complex))),
      d_block_size(1024),
      d_advance(d_block_size / 2),
      d_readahead_items(d_advance)
    {
      d_burst = false;
      d_tag_burst = pmt::mp("burst");

      d_hysteresis_timeout = 2;
      d_hysteresis_count = 0;

      d_fft_window = (float*)volk_malloc(d_block_size * sizeof(float), 256);
      assert((d_fft_window & 0xff) == 0);

      std::vector<float> window = fft::window::hann(d_block_size);
      std::copy(window.begin(), window.end(), d_fft_window);

      d_temp_f = (float*)volk_malloc(d_block_size * sizeof(float), 256);
      assert((d_temp_f * 0xff) == 0);

      d_fft_in = (gr_complex*)fftwf_malloc(sizeof(gr_complex) * d_block_size);
      d_fft_out = (gr_complex*)fftwf_malloc(sizeof(gr_complex) * d_block_size);
      d_fft_plan = fftwf_plan_dft_1d(d_block_size, reinterpret_cast<fftwf_complex*>(d_fft_in), reinterpret_cast<fftwf_complex*>(d_fft_out), FFTW_FORWARD, FFTW_PATIENT | FFTW_DESTROY_INPUT);

      set_history(d_readahead_items + 1);
      set_output_multiple(d_advance);
    }

    /*
     * Our virtual destructor.
     */
    burst_detector_impl::~burst_detector_impl()
    {
      fftwf_destroy_plan(d_fft_plan);
      fftwf_free(d_fft_out);
      fftwf_free(d_fft_in);

      volk_free(d_temp_f);
      volk_free(d_fft_window);
    }

    void
    burst_detector_impl::forecast(int noutput_items,
                       gr_vector_int &ninput_items_required)
    {
      size_t block_count = ceilf(float(noutput_items) / d_advance);
      ninput_items_required[0] = block_count * d_advance + history() - 1;
    }

    int
    burst_detector_impl::general_work(int noutput_items,
                       gr_vector_int &ninput_items,
                       gr_vector_const_void_star &input_items,
                       gr_vector_void_star &output_items)
    {
        const gr_complex *in = (const gr_complex*)input_items[0];
        gr_complex *out = (gr_complex*)output_items[0];

        const size_t block_count = std::min(ninput_items[0], noutput_items) / d_advance;

        const uint64_t _nitems_written = nitems_written(0);
        for(size_t block_n=0; block_n<block_count; block_n++) {
          const size_t index_start = block_n * d_advance;

          volk_32fc_32f_multiply_32fc((gr_complex*)d_fft_in, &in[index_start], d_fft_window, d_block_size);
          fftwf_execute(d_fft_plan);
          volk_32fc_magnitude_32f(d_temp_f, (gr_complex*)d_fft_out, d_block_size);

          float stddev = 0, mean = 0;
          volk_32f_stddev_and_mean_32f_x2(&stddev, &mean, d_temp_f, d_block_size);

          if( stddev > mean ) {
            d_hysteresis_count = d_hysteresis_timeout;
          } else {
            d_hysteresis_count = d_hysteresis_count ? (d_hysteresis_count - 1) : 0;
          }

          if( d_hysteresis_count ) {
            if( d_burst == false ) {
              add_item_tag(0, _nitems_written + index_start, d_tag_burst, pmt::PMT_T);
              d_burst = true;
            }
          } else {
            if( d_burst == true ) {
              add_item_tag(0, _nitems_written + index_start + d_block_size - 1, d_tag_burst, pmt::PMT_F);
              d_burst = false;
            }
          }
        }

        //noutput_items = block_count * d_block_size;
        // Effective delay of d_advance samples.
        memcpy(out, in, noutput_items * sizeof(gr_complex));

        consume_each(noutput_items);

        return noutput_items;
    }

  } /* namespace tpms */
} /* namespace gr */

