/* -*- c++ -*- */
/* 
 * Copyright 2013 Christopher D. Kilgour
 * Copyright 2008, 2009 Dominic Spill, Michael Ossmann
 * Copyright 2007 Dominic Spill
 * Copyright 2005, 2006 Free Software Foundation, Inc.
 *
 * This file is part of gr-bluetooth
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <gnuradio/io_signature.h>
#include "gr_bluetooth/multi_block.h"
#include "gr_bluetooth/packet.h"
#include <gnuradio/filter/firdes.h>
#include <gnuradio/math.h>
#include <stdio.h>
#include <gnuradio/blocks/complex_to_mag_squared.h>

namespace gr {
  namespace bluetooth {
    multi_block::multi_block(double sample_rate, double center_freq, double squelch_threshold)
      : gr::sync_block ("bluetooth multi block",
                       gr::io_signature::make (1, 1, sizeof (gr_complex)),
                       gr::io_signature::make (0, 0, 0))
    {
      d_target_snr = squelch_threshold;

      d_cumulative_count = 0;
      d_sample_rate = sample_rate;
      d_center_freq = center_freq;

      /*
       * how many time slots we attempt to decode on each hop:
       * 1 for now, could be as many as 5 plus a little slop
       */
      int slots = 1;
      d_samples_per_symbol = sample_rate / SYMBOL_RATE;
      //FIXME make sure that d_samples_per_symbol >= 2 (requirement of clock_recovery_mm_ff)
      d_samples_per_slot = (int) SYMBOLS_PER_BASIC_RATE_SLOT * d_samples_per_symbol;
      int history_required = (int) slots * d_samples_per_slot;

      /* channel filter coefficients */
      double gain = 1;
      d_channel_filter_width = 500000;
      double transition_width = 300000;
      d_channel_filter = gr::filter::firdes::low_pass( gain, 
                                              sample_rate, 
                                              d_channel_filter_width, 
                                              transition_width, 
                                              gr::filter::firdes::WIN_HANN);

      /* noise filter coefficients */
      double n_gain = 1;
      d_noise_filter_width = 22500;
      double n_trans_width = 10000;
      d_noise_filter = gr::filter::firdes::low_pass( n_gain, 
                                            sample_rate, 
                                            d_noise_filter_width, 
                                            n_trans_width, 
                                            gr::filter::firdes::WIN_HANN );

      /* we will decimate by the largest integer that results in enough samples per symbol */
      d_ddc_decimation_rate = (int) d_samples_per_symbol / 2;
      double channel_samples_per_symbol = d_samples_per_symbol / d_ddc_decimation_rate;

      set_channels();

      /* fm demodulator */
      d_demod_gain = channel_samples_per_symbol / M_PI_2;

      /* mm_cr variables */
      d_gain_mu = 0.175;
      d_mu = 0.32;
      d_omega_relative_limit = 0.005;
      d_omega = channel_samples_per_symbol;
      d_gain_omega = .25 * d_gain_mu * d_gain_mu;
      d_omega_mid = d_omega;
      d_interp = new gr::filter::mmse_fir_interpolator_ff();
      d_last_sample = 0;
      
      /* the required history is the slot data + the max of either
         channed DDC + demod, or noise DDC */
      int channel_history = (int) (d_channel_filter.size( ) + 
                                   d_ddc_decimation_rate * d_interp->ntaps());
      int noise_history   = (int) d_noise_filter.size( );
      if (channel_history > noise_history) {
        history_required += channel_history;
        d_first_channel_sample = 0;
        d_first_noise_sample   = (channel_history - noise_history);
      }
      else {
        history_required += noise_history;
        d_first_noise_sample   = 0;
        d_first_channel_sample = (noise_history - channel_history);
      }

      printf( "history set to %d samples: channel=%d, noise=%d\n", 
              history_required, channel_history, noise_history );

      set_history( history_required );
    }  

    static inline float slice(float x)
    {
      return (x < 0) ? -1.0F : 1.0F;
    }

    /* M&M clock recovery, adapted from gr_clock_recovery_mm_ff */
    int 
    multi_block::mm_cr(const float *in, int ninput_items, float *out, int noutput_items)
    {
      unsigned int ii = 0; /* input index */
      int          oo = 0; /* output index */
      unsigned int ni = ninput_items - d_interp->ntaps(); /* max input */
      float        mm_val;

      while ((oo < noutput_items) && (ii < ni)) {
        // produce output sample
		//printf("d_mu %3.3f\n", d_mu);
        out[oo]       = d_interp->interpolate( &in[ii], d_mu );
        mm_val        = slice(d_last_sample) * out[oo] - slice(out[oo]) * d_last_sample;
        d_last_sample = out[oo];
        
        d_omega += d_gain_omega * mm_val;
        d_omega  = d_omega_mid + gr::branchless_clip( d_omega-d_omega_mid, 
                                                     d_omega_relative_limit );   // make sure we don't walk away
        d_mu    += d_omega + d_gain_mu * mm_val;

        ii      += (int) floor( d_mu );
        d_mu    -= floor( d_mu );
        oo++;
      }

      /* return number of output items produced */
      return oo;
    }

    /* fm demodulation, taken from gr_quadrature_demod_cf */
    void 
    multi_block::demod(const gr_complex *in, float *out, int noutput_items)
    {
      int i;
      gr_complex product;

      for (i = 1; i < noutput_items; i++) {
        gr_complex product = in[i] * conj (in[i-1]);
        out[i] = d_demod_gain * gr::fast_atan2f(imag(product), real(product));
      }
    }

    /* binary slicer, similar to gr_binary_slicer_fb */
    void 
    multi_block::slicer(const float *in, char *out, int noutput_items)
    {
      int i;

      for (i = 0; i < noutput_items; i++)
        out[i] = (in[i] < 0) ? 0 : 1;
    }

    int 
    multi_block::channel_samples( double                     freq,
                                  gr_vector_const_void_star& in, 
                                  gr_vector_void_star&       out,
                                  double&                    energy,
                                  int                        ninput_items )
    {
      int ddc_noutput_items       = 0;
      int classic_chan = abs_freq_channel( freq );
      std::map<int, gr::filter::freq_xlating_fir_filter_ccf::sptr>::const_iterator ddci = 
        d_channel_ddcs.find( classic_chan );

      if (ddci != d_channel_ddcs.end( )) {
        gr::filter::freq_xlating_fir_filter_ccf::sptr ddc = ddci->second;
        int ddc_samples = ninput_items - (ddc->history( ) - 1) - d_first_channel_sample;
		// This changes how many iterations it takes to crash... Definitely on to something.
		//printf("ddc_samples: %i\n", ddc_samples);
		//printf("fcs: %i\n", d_first_channel_sample);
        gr_vector_const_void_star ddc_in( 1 );
        ddc_in[0] = &(((gr_complex *) in[0])[d_first_channel_sample]);
        ddc_noutput_items = ddc->fixed_rate_ninput_to_noutput( ddc_samples ); // ddc_samples
		//printf("ddc_noutput_items: %i\n", ddc_noutput_items);
		//gr_vector_void_star ddc_out( 1 );
		//ddc_out[0] = out[0];//malloc(100000);
        ddc_noutput_items = ddc->work( ddc_noutput_items, ddc_in, out );
		//printf("after work %i\n", ddc_noutput_items);
        gr::blocks::complex_to_mag_squared::sptr mag2 = gr::blocks::complex_to_mag_squared::make( 1 );
		//printf("past\n");
        float *mag2_out = new float[ddc_noutput_items];
        gr_vector_void_star mag2_out_vector( 1 );
        mag2_out_vector[0] = &mag2_out[0];
        gr_vector_const_void_star ddc_out_const( 1 );
        ddc_out_const[0] = out[0];
        (void) mag2->work( ddc_noutput_items, ddc_out_const, mag2_out_vector );
        energy = 0.0;
        for( unsigned i=0; i<ddc_noutput_items; i++ ) {
          energy += mag2_out[i];
        }
        energy /= ddc_noutput_items;
		delete [] mag2_out;
		//free(ddc_out[0]);
        //energy /= d_channel_filter_width;
      }
      else {
        energy = 1.0;
      }

      return ddc_noutput_items;
    }

    int 
    multi_block::channel_symbols( gr_vector_const_void_star& in, 
                                  char *                     out, 
                                  int                        ninput_items )
    {
      /* fm demodulation */
      int demod_noutput_items = ninput_items - 1;
      float demod_out[demod_noutput_items];
      gr_complex *ch_samps = (gr_complex *) in[0];
      demod( ch_samps, demod_out, demod_noutput_items );
      
      /* clock recovery */
      int cr_ninput_items = demod_noutput_items;
      int noutput_items = cr_ninput_items; // poor estimate but probably safe
      float cr_out[noutput_items];
      noutput_items = mm_cr(demod_out, cr_ninput_items, cr_out, noutput_items);
      
      /* binary slicer */
      slicer(cr_out, out, noutput_items);
      
      return noutput_items;
    }

    bool 
    multi_block::check_snr( const double               freq, 
                            const double               on_channel_energy,
                            double&                    snr,
                            gr_vector_const_void_star& in )
    {
      double off_channel_energy = 0.0;

      int classic_chan = abs_freq_channel( freq );
      std::map<int, gr::filter::freq_xlating_fir_filter_ccf::sptr>::const_iterator nddci = 
        d_noise_ddcs.find( classic_chan );

      if (nddci != d_noise_ddcs.end( )) {
        gr::filter::freq_xlating_fir_filter_ccf::sptr nddc = nddci->second;
        gr_vector_const_void_star ddc_in( 1 );
        ddc_in[0] = &(((gr_complex *) in[0])[d_first_noise_sample]);
        int ddc_noutput_items = nddc->fixed_rate_ninput_to_noutput( (int) d_samples_per_slot );
        gr_complex ddc_out[ddc_noutput_items];
        gr_vector_void_star ddc_out_vector( 1 );
        gr_vector_const_void_star ddc_out_const( 1 );
        ddc_out_vector[0] = &ddc_out[0];
        ddc_out_const[0]  = &ddc_out[0];
        ddc_noutput_items = nddc->work( ddc_noutput_items, ddc_in, ddc_out_vector );
      
        // average mag2 for valley
        gr::blocks::complex_to_mag_squared::sptr mag2 = gr::blocks::complex_to_mag_squared::make( 1 );
        float mag2_out[ddc_noutput_items];
        gr_vector_void_star mag2_out_vector( 1 );
        mag2_out_vector[0] = &mag2_out[0];
        (void) mag2->work( ddc_noutput_items, ddc_out_const, mag2_out_vector );
        for( unsigned i=0; i<ddc_noutput_items; i++ ) {
          off_channel_energy += mag2_out[i];
        }
        off_channel_energy /= ddc_noutput_items;
        //off_channel_energy /= d_noise_filter_width;
      }
      else {
        off_channel_energy = 1.0;
      }

      snr = 10.0 * log10( on_channel_energy / off_channel_energy );

      return (snr >= d_target_snr);
    }

    /* add some number of symbols to the block's history requirement */
    void 
    multi_block::set_symbol_history(int num_symbols)
    {
      set_history((int) (history() + (num_symbols * d_samples_per_symbol)));
    }

    /* set available channels based on d_center_freq and d_sample_rate */
    void 
    multi_block::set_channels()
    {
      /* center frequency described as a fractional channel */
      double center = (d_center_freq - BASE_FREQUENCY) / CHANNEL_WIDTH;
      /* bandwidth in terms of channels */
      double channel_bandwidth = d_sample_rate / CHANNEL_WIDTH;
      /* low edge of our received signal */
      double low_edge = center - (channel_bandwidth / 2);
      /* high edge of our received signal */
      double high_edge = center + (channel_bandwidth / 2);
      /* minimum bandwidth required per channel - ideally 1.0 (1 MHz), but can probably decode with a bit less */
      double min_channel_width = 0.9;

      int low_classic_channel = (int) (low_edge + (min_channel_width / 2) + 1);
      low_classic_channel = (low_classic_channel < 0) ? 0 : low_classic_channel;

      int high_classic_channel = (int) (high_edge - (min_channel_width / 2));
      high_classic_channel = (high_classic_channel > 78) ? 78 : high_classic_channel;

      d_low_freq = channel_abs_freq(low_classic_channel);
      d_high_freq = channel_abs_freq(high_classic_channel);

      for( int ch=low_classic_channel; ch<=high_classic_channel; ch++ ) {
        double freq = channel_abs_freq( ch );
        d_channel_ddcs[ch] = 
          gr::filter::freq_xlating_fir_filter_ccf::make( d_ddc_decimation_rate, 
                                               d_channel_filter, 
                                               freq-d_center_freq, 
                                               d_sample_rate );
        d_noise_ddcs[ch] = 
          gr::filter::freq_xlating_fir_filter_ccf::make( d_ddc_decimation_rate, 
                                               d_noise_filter, 
                                               freq+790000.0-d_center_freq, 
                                               d_sample_rate );
      }
    }

    /* returns relative (with respect to d_center_freq) frequency in Hz of given channel */
    double 
    multi_block::channel_rel_freq(int channel)
    {
      return channel_abs_freq(channel) - d_center_freq;
    }

    double 
    multi_block::channel_abs_freq(int channel)
    {
      return BASE_FREQUENCY + (channel * CHANNEL_WIDTH);
    }

    int
    multi_block::abs_freq_channel(double freq)
    {
      return (int) ((freq - BASE_FREQUENCY) / CHANNEL_WIDTH);
    }
  } /* namespace bluetooth */
} /* namespace gr */

