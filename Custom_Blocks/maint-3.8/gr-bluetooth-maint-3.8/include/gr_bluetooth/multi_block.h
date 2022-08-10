/* -*- c++ -*- */
/* 
 * Copyright 2013 Christopher D. Kilgour
 * Copyright 2008, 2009 Dominic Spill, Michael Ossmann
 * Copyright 2007 Dominic Spill
 * Copyright 2005, 2006 Free Software Foundation, Inc.
 * 
 * This is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
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


#ifndef INCLUDED_GR_BLUETOOTH_MULTI_BLOCK_H
#define INCLUDED_GR_BLUETOOTH_MULTI_BLOCK_H

#include <gr_bluetooth/api.h>
#include <gnuradio/sync_block.h>
#include <gnuradio/filter/mmse_fir_interpolator_ff.h>
#include <gnuradio/filter/freq_xlating_fir_filter.h>

namespace gr {
  namespace bluetooth {

    /*!
     * \brief Bluetooth multi-channel parent class.
     * \ingroup bluetooth
     */
    class  GR_BLUETOOTH_API multi_block : virtual public gr::sync_block
    {
    protected:
      multi_block() {} // to allow for pure virtual
      multi_block(double sample_rate, double center_freq, double squelch_threshold);

      /* symbols per second */
      static const int SYMBOL_RATE = 1000000;

      static const int SYMBOLS_PER_BASIC_RATE_SHORTENED_ACCESS_CODE = 68;
      static const int SYMBOLS_PER_LOW_ENERGY_PREAMBLE_AA = 40;

      /* length of time slot in symbols */
      static const int SYMBOLS_PER_BASIC_RATE_SLOT    = 625;
      static const int SYMBOLS_FOR_BASIC_RATE_HISTORY = 3125;

      /* channel 0 in Hz */
      static const uint32_t BASE_FREQUENCY = 2402000000UL;

      /* channel width in Hz */
      static const int CHANNEL_WIDTH = 1000000;

      /* total number of samples elapsed */
      uint64_t d_cumulative_count;

      /* sample rate of raw input stream */
      double d_sample_rate;

      /* number of raw samples per symbol */
      double d_samples_per_symbol;

      /* number of raw samples per time slot (625 microseconds) */
      double d_samples_per_slot;

      /* center frequency of input stream */
      double d_center_freq;

      /* lowest frequency we can decode */
      double d_low_freq;

      /* highest frequency we can decode */
      double d_high_freq;

      /* decimation rate of digital downconverter */
      int d_ddc_decimation_rate;

      /* mm_cr variables */
      float d_gain_mu;		// gain for adjusting mu
      float d_mu;				// fractional sample position [0.0, 1.0]
      float d_omega_relative_limit;	// used to compute min and max omega
      float d_omega;			// nominal frequency
      float d_gain_omega;		// gain for adjusting omega
      float d_omega_mid;		// average omega
      float d_last_sample;

      /* target SNR */
      double d_target_snr;

      /* channel filter coefficients for digital downconverter */
      double d_channel_filter_width;
      std::vector<float> d_channel_filter;
      std::map<int, gr::filter::freq_xlating_fir_filter_ccf::sptr> d_channel_ddcs;

      /* noise power filter coefficients */
      double d_noise_filter_width;
      std::vector<float> d_noise_filter;
      std::map<int, gr::filter::freq_xlating_fir_filter_ccf::sptr> d_noise_ddcs;

      /* input sample offset where channel and noise extraction happens */
      int d_first_channel_sample;
      int d_first_noise_sample;

      /* quadrature frequency demodulator sensitivity */
      float d_demod_gain;

      /* interpolator M&M clock recovery block */
      gr::filter::mmse_fir_interpolator_ff *d_interp;

      /* M&M clock recovery, adapted from gr_clock_recovery_mm_ff */
      int mm_cr(const float *in, int ninput_items, float *out, int noutput_items);

      /* fm demodulation, taken from gr_quadrature_demod_cf */
      void demod(const gr_complex *in, float *out, int noutput_items);

      /* binary slicer, similar to gr_binary_slicer_fb */
      void slicer(const float *in, char *out, int noutput_items);

      /**
       * Extract a single BT channel's worth of samples from the wider
       * bandwidth samples.
       */
      int channel_samples( const double               freq,
                           gr_vector_const_void_star& in, 
                           gr_vector_void_star&       out,
                           double&                    energy,
                           int                        ninput_items );

      /**
       * Produce symbols stream for a single BT channel, developed
       * from of the raw samples for a single BT channel.
       */
      int channel_symbols( gr_vector_const_void_star &in, 
                           char *out, 
                           int ninput_items );

      bool check_snr( const double               freq, 
                      const double               on_channel_energy,
                      double&                    snr, 
                      gr_vector_const_void_star& in );

      /* add some number of symbols to the block's history requirement */
      void set_symbol_history(int num_symbols);

      /* set available channels based on d_center_freq and d_sample_rate */
      void set_channels();

      /* returns relative (with respect to d_center_freq) frequency in Hz of given channel */
      double channel_rel_freq(int channel);

      double channel_abs_freq(int channel);

      int abs_freq_channel(double freq);

    public:
      virtual int work (int noutput_items,
                        gr_vector_const_void_star &input_items,
                        gr_vector_void_star &output_items) = 0;
    };

  } // namespace bluetooth
} // namespace gr

#endif /* INCLUDED_GR_BLUETOOTH_MULTI_BLOCK_H */

