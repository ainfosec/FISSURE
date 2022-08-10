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
#include "multi_hopper_impl.h"

namespace gr {
  namespace bluetooth {

    multi_hopper::sptr
    multi_hopper::make(double sample_rate, double center_freq, double squelch_threshold, int LAP, bool aliased, bool tun)
    {
      return gnuradio::get_initial_sptr (new multi_hopper_impl(sample_rate, center_freq, squelch_threshold, LAP, aliased, tun));
    }

    /*
     * The private constructor
     */
    multi_hopper_impl::multi_hopper_impl(double sample_rate, double center_freq, double squelch_threshold, int LAP, bool aliased, bool tun)
      : multi_block(sample_rate, center_freq, squelch_threshold),
        gr::sync_block ("bluetooth multi hopper block",
                       gr::io_signature::make (1, 1, sizeof (gr_complex)),
                       gr::io_signature::make (0, 0, 0))
    {
        d_LAP = LAP;
	d_aliased = aliased;
	d_tun = tun;
	set_symbol_history(SYMBOLS_FOR_BASIC_RATE_HISTORY);
	d_piconet = basic_rate_piconet::make(d_LAP);

	/* Tun interface */
	if(d_tun) {
		strncpy(chan_name, "btbb", sizeof(chan_name)-1);

		if((d_tunfd = mktun(chan_name, d_ether_addr)) == -1) {
			fprintf(stderr, "warning: was not able to open TUN device, "
			  "disabling Wireshark interface\n");
			// throw std::runtime_error("cannot open TUN device");
		}
	}
    }

    /*
     * Our virtual destructor.
     */
    multi_hopper_impl::~multi_hopper_impl()
    {
    }

    int
    multi_hopper_impl::work(int noutput_items,
                            gr_vector_const_void_star &input_items,
                            gr_vector_void_star &output_items)
    {
      int retval, latest_ac;
      uint32_t clkn; /* native (local) clock in 625 us */
      double freq;
      char symbols[history()+40]; //poor estimate but safe

      clkn = (int) (d_cumulative_count / d_samples_per_slot) & 0x7ffffff;

      if (d_piconet->have_clk27()) {
        /* now that we know the clock and UAP, follow along and sniff each time slot on the correct channel */
        hopalong(input_items, symbols, clkn, noutput_items);
      } 
      else {
        for (freq = d_low_freq; freq <= d_high_freq; freq += 1e6) {
          gr_complex ch_samples[noutput_items];
          gr_vector_void_star btch( 1 );
          btch[0] = ch_samples;
          double on_channel_energy, snr;
          int ch_count = channel_samples( freq, input_items, btch, on_channel_energy, history() );
          bool brok = check_snr( freq, on_channel_energy, snr, input_items );
          if (brok) {
            gr_vector_const_void_star cbtch( 1 );
            cbtch[0] = ch_samples;
            int num_symbols = channel_symbols( cbtch, symbols, ch_count );
            
            if (num_symbols >= SYMBOLS_PER_BASIC_RATE_SHORTENED_ACCESS_CODE) {
              /* don't look beyond one slot for ACs */
              latest_ac = ((num_symbols - SYMBOLS_PER_BASIC_RATE_SHORTENED_ACCESS_CODE) < SYMBOLS_PER_BASIC_RATE_SLOT) ? 
                (num_symbols - SYMBOLS_PER_BASIC_RATE_SHORTENED_ACCESS_CODE) : SYMBOLS_PER_BASIC_RATE_SLOT;
              retval = classic_packet::sniff_ac(symbols, latest_ac);
              if(retval > -1) {
                classic_packet::sptr packet = classic_packet::make(
                                                                   &symbols[retval], num_symbols - retval,
                                                                   clkn, freq);
                if (packet->get_LAP() == d_LAP && packet->header_present()) {
                  if (!d_piconet->have_clk6()) {
                    /* working on CLK1-6/UAP discovery */
                    d_piconet->UAP_from_header(packet);
                    if (d_piconet->have_clk6()) {
                      /* got CLK1-6/UAP, start working on CLK1-27 */
                      d_piconet->init_hop_reversal(d_aliased);
                      /* use previously observed packets to eliminate candidates */
                      d_piconet->winnow();
                    }
                  } else {
                    /* continue working on CLK1-27 */
                    /* we need timing information from an additional packet, so run through UAP_from_header() again */
                    d_piconet->UAP_from_header(packet);
                    if (!d_piconet->have_clk6()) {
                      break;
                    }
                    d_piconet->winnow();
                  }
                  break;
                }
              }
            }
          }
        }
      }
      d_cumulative_count += (int) d_samples_per_slot;
        
      /* 
       * The runtime system wants to know how many output items we
       * produced, assuming that this is equal to the number of
       * input items consumed.  We tell it that we produced/consumed
       * one time slot of input items so that our next run starts
       * one slot later.
       */
      return (int) d_samples_per_slot;
    }

    void
    multi_hopper_impl::hopalong(gr_vector_const_void_star &input_items,
                                char *symbols, uint32_t clkn, int noutput_items)
    {
      int ac_index, latest_ac;
      uint32_t clock27 = (clkn + d_piconet->get_offset()) & 0x7ffffff;
      double obs_freq, freq = channel_abs_freq( d_piconet->hop(clock27) );
      if (d_aliased)
        obs_freq = channel_abs_freq( d_piconet->aliased_channel( d_piconet->hop(clock27) ) );
      else
        obs_freq = freq;
      if ((obs_freq >= d_low_freq) && (obs_freq <= d_high_freq)) {
        gr_complex ch_samples[noutput_items];
        gr_vector_void_star btch( 1 );
        btch[0] = ch_samples;
        double on_channel_energy, snr;
        int ch_count = channel_samples( freq, input_items, btch, on_channel_energy, history() );
        bool brok = check_snr( freq, on_channel_energy, snr, input_items );
        if (brok) {
          gr_vector_const_void_star cbtch( 1 );
          cbtch[0] = ch_samples;
          int num_symbols = channel_symbols( cbtch, symbols, ch_count );
          if (num_symbols >= SYMBOLS_PER_BASIC_RATE_SHORTENED_ACCESS_CODE ) {
            latest_ac = ((num_symbols - SYMBOLS_PER_BASIC_RATE_SHORTENED_ACCESS_CODE) < SYMBOLS_PER_BASIC_RATE_SLOT) ? 
              (num_symbols - SYMBOLS_PER_BASIC_RATE_SHORTENED_ACCESS_CODE) : SYMBOLS_PER_BASIC_RATE_SLOT;
            ac_index = classic_packet::sniff_ac(symbols, latest_ac);
            if(ac_index > -1) {
              classic_packet::sptr packet = classic_packet::make(&symbols[ac_index], num_symbols - ac_index, 0, obs_freq);
              if(packet->get_LAP() == d_LAP) {
                printf("clock 0x%07x, channel %2d: ", clock27, packet->get_channel( ));
                if (packet->header_present()) {
                  packet->set_UAP(d_piconet->get_UAP());
                  packet->set_clock(clock27, true);
                  packet->decode();
                  if(packet->got_payload()) {
                    packet->print();
                    if(d_tun) {
                      /* include 9 bytes for meta data & packet header */
                      int length = packet->get_payload_length() + 9;
                      char *data = packet->tun_format();
                      int addr = (packet->get_UAP() << 24) | packet->get_LAP();
                      write_interface(d_tunfd, (unsigned char *)data, length, 0, addr, ETHER_TYPE);
                      free(data);
                    }
                  }
                } else {
                  printf("ID\n");
                  if(d_tun) {
                    int addr = (d_piconet->get_UAP() << 24) | packet->get_LAP();
                    write_interface(d_tunfd, NULL, 0, 0, addr, ETHER_TYPE);
                  }
                }
              }
            }
          }
        }
      }
    }

    

  } /* namespace bluetooth */
} /* namespace gr */

