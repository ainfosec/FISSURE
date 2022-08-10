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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <gnuradio/io_signature.h>
#include "multi_LAP_impl.h"
extern "C"
{
  #include <btbb.h>
}
#include <stdio.h>

namespace gr {
  namespace bluetooth {

    multi_LAP::sptr
    multi_LAP::make(double sample_rate, double center_freq, double squelch_threshold)
    {
      return gnuradio::get_initial_sptr (new multi_LAP_impl(sample_rate, center_freq, squelch_threshold));
    }

    /*
     * The private constructor
     */
    multi_LAP_impl::multi_LAP_impl(double sample_rate, double center_freq, double squelch_threshold)
      : multi_block(sample_rate, center_freq, squelch_threshold),
        gr::sync_block ("bluetooth multi LAP block",
                       gr::io_signature::make (1, 1, sizeof (gr_complex)),
                       gr::io_signature::make (0, 0, 0))
    {
      set_symbol_history(SYMBOLS_PER_BASIC_RATE_SHORTENED_ACCESS_CODE);
	  btbb_init(1);
    }

    /*
     * Our virtual destructor.
     */
    multi_LAP_impl::~multi_LAP_impl()
    {
    }

    int
    multi_LAP_impl::work(int noutput_items,
                         gr_vector_const_void_star &input_items,
                         gr_vector_void_star &output_items)
    {
	  int offset;
	  double freq;
	  char symbols[history()]; //poor estimate but safe
	  btbb_packet *pkt = NULL;
	  int max_ac_errs = 1;

	for (freq = d_low_freq; freq <= d_high_freq; freq += 1e6)
	{
          gr_complex *ch_samples = new gr_complex[noutput_items+10000];
          gr_vector_void_star btch( 1 );
          btch[0] = ch_samples;
          double on_channel_energy, snr;
          int ch_count = channel_samples( freq, input_items, btch, on_channel_energy, history() );

          if (check_snr( freq, on_channel_energy, snr, input_items )) {
            gr_vector_const_void_star cbtch( 1 );
            cbtch[0] = ch_samples;
            int num_symbols = channel_symbols( cbtch, symbols, ch_count );
          
            if (num_symbols >= SYMBOLS_PER_BASIC_RATE_SHORTENED_ACCESS_CODE) {
              /* don't look beyond one slot for ACs */
              int latest_ac = ((num_symbols - SYMBOLS_PER_BASIC_RATE_SHORTENED_ACCESS_CODE) < SYMBOLS_PER_BASIC_RATE_SLOT) ? 
                (num_symbols - SYMBOLS_PER_BASIC_RATE_SHORTENED_ACCESS_CODE) : SYMBOLS_PER_BASIC_RATE_SLOT;
			  offset = btbb_find_ac(symbols, latest_ac, LAP_ANY, max_ac_errs, &pkt);
              if (offset >= 0) {
				// Don't know clkn
				btbb_packet_set_data(pkt, symbols + offset, num_symbols - offset, (freq/1e6)-2402, 0);
                printf("GOT PACKET: ch=%d, LAP=%06x, err=%u at time slot %d\n",
                       btbb_packet_get_channel(pkt), btbb_packet_get_lap(pkt),
					   btbb_packet_get_ac_errors(pkt),
                       (int) (d_cumulative_count / d_samples_per_slot));
              }
            }
          }
          delete [] ch_samples;
	}
	d_cumulative_count += (int) d_samples_per_slot;

	/* 
	 * The runtime system wants to know how many output items we produced, assuming that this is equal
	 * to the number of input items consumed.  We tell it that we produced/consumed one time slot of
	 * input items so that our next run starts one slot later.
	 */
        return (int) d_samples_per_slot;
    }

  } /* namespace bluetooth */
} /* namespace gr */

