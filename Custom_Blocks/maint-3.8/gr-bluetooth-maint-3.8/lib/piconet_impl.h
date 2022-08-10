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

#ifndef INCLUDED_BLUETOOTH_GR_BLUETOOTH_PICONET_IMPL_H
#define INCLUDED_BLUETOOTH_GR_BLUETOOTH_PICONET_IMPL_H

#include "gr_bluetooth/piconet.h"
#include "gr_bluetooth/packet.h"
#include <vector>

namespace gr {
  namespace bluetooth {

    class basic_rate_piconet_impl : public basic_rate_piconet {
    private:
      /* number of channels in use */
      static const int CHANNELS = 79;

      /* number of aliased channels received */
      static const int ALIASED_CHANNELS = 25;

      /* maximum number of hops to remember */
      static const int MAX_PATTERN_LENGTH = 1000;

      /* true if using a particular aliased receiver implementation */
      bool d_aliased;

      /* using adaptive frequency hopping (AFH) */
      bool d_afh;

      /* observed pattern that looks like AFH */
      bool d_looks_like_afh;

      /* lower address part (of master's BD_ADDR) */
      uint32_t d_LAP;

      /* upper address part (of master's BD_ADDR) */
      uint8_t d_UAP;

      /* non-significant address part (of master's BD_ADDR) */
      uint16_t d_NAP;

      /* CLK1-27 candidates */
      uint32_t *d_clock_candidates;

      /* these values for hop() can be precalculated */
      int d_b, d_e;

      /* these values for hop() can be precalculated in part (e.g. a1 is the
       * precalculated part of a) */
      int d_a1, d_c1, d_d1;

      /* frequency register bank */
      int d_bank[CHANNELS];

      /* speed up the perm5 function with a lookup table */
      char d_perm_table[0x20][0x20][0x200];

      /* this holds the entire hopping sequence */
      char *d_sequence;

      /* number of candidates for CLK1-27 */
      int d_num_candidates;

      /* have we collected the first packet in a UAP discovery attempt? */
      bool d_got_first_packet;

      /* number of packets observed during one attempt at UAP/clock discovery */
      int d_packets_observed;

      /* total number of packets observed */
      int d_total_packets_observed;

      /* number of observed packets that have been used to winnow the candidates */
      int d_winnowed;

      /* CLK1-6 candidates */
      int d_clock6_candidates[64];

      /* remember patterns of observed hops */
      int d_pattern_indices[MAX_PATTERN_LENGTH];
      uint8_t d_pattern_channels[MAX_PATTERN_LENGTH];

      bool d_hop_reversal_inited;

      /* do all the precalculation that can be done before knowing the address */
      void precalc();

      /* do precalculation that requires the address */
      void address_precalc(int address);

      /* drop-in replacement for perm5() using lookup table */
      int fast_perm(int z, int p_high, int p_low);

      /* 5 bit permutation */
      /* assumes z is constrained to 5 bits, p_high to 5 bits, p_low to 9 bits */
      int perm5(int z, int p_high, int p_low);

      /* generate the complete hopping sequence */
      void gen_hops();

      /* determine channel for a particular hop */
      /* replaced with gen_hops() for a complete sequence but could still come in handy */
      char single_hop(int clock);

      /* create list of initial candidate clock values (hops with same channel as first observed hop) */
      int init_candidates(char channel, int known_clock_bits);

      /* discovery status */
      bool d_have_UAP;
      bool d_have_NAP;
      bool d_have_clk6;
      bool d_have_clk27;

      /* offset between CLKN (local) and CLK of piconet */
      uint32_t d_clk_offset;

      /* local clock (clkn) at time of first packet */
      uint32_t d_first_pkt_time;

    public:
      basic_rate_piconet_impl(uint32_t LAP);
      ~basic_rate_piconet_impl();

      /* initialize the hop reversal process */
      /* returns number of initial candidates for CLK1-27 */
      int init_hop_reversal(bool aliased);

      /* look up channel for a particular hop */
      char hop(int clock);

      /* narrow a list of candidate clock values based on a single observed hop */
      int winnow(int offset, char channel);

      /* narrow a list of candidate clock values based on all observed hops */
      int winnow();

      /* offset between CLKN (local) and CLK of piconet */
      uint32_t get_offset();
      void set_offset(uint32_t offset);

      /* UAP */
      uint8_t get_UAP();
      void set_UAP(uint8_t uap);

      /* NAP */
      uint16_t get_NAP();
      void set_NAP(uint16_t nap);

      /* discovery status */
      bool have_UAP();
      bool have_NAP();
      bool have_clk6();
      bool have_clk27();

      /* use packet headers to determine UAP */
      bool UAP_from_header(classic_packet::sptr packet);

      /* return the observable channel (26-50) for a given channel (0-78) */
      char aliased_channel(char channel);

      /* reset UAP/clock discovery */
      void reset();
    };

    class low_energy_piconet_impl : public low_energy_piconet {
    private:
      uint8_t  d_chan_list[38];
      
    public:
      low_energy_piconet_impl(uint32_t aa);
      ~low_energy_piconet_impl();

      int init_hop_reversal(bool aliased);
      char hop(int clock);
      char aliased_channel(char channel);
      void reset();
      
    };

  } // namespace bluetooth
} // namespace gr

#endif /* INCLUDED_BLUETOOTH_GR_BLUETOOTH_PICONET_IMPL_H */

