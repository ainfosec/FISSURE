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
#include "piconet_impl.h"
#include <stdio.h>

namespace gr {
  namespace bluetooth {

    /* add a packet to the queue */
    void piconet::enqueue(packet::sptr pkt) {
      d_pkt_queue.push_back(pkt);
    }

    /* pull the first packet from the queue (FIFO) */
    packet::sptr piconet::dequeue( ) {
      packet::sptr pkt;
      
      if (d_pkt_queue.size() > 0) {
        pkt = d_pkt_queue.front();
        d_pkt_queue.erase(d_pkt_queue.begin());
      }

      return pkt;
    }

    // ---------------------------------------------------------------------

    basic_rate_piconet::sptr
    basic_rate_piconet::make(uint32_t LAP)
    {
      return basic_rate_piconet::sptr(new basic_rate_piconet_impl(LAP));
    }

    // ---------------------------------------------------------------------

    /*
     * The private constructor
     */
    basic_rate_piconet_impl::basic_rate_piconet_impl(uint32_t LAP)
      : basic_rate_piconet()
    {
      d_LAP = LAP;

      d_got_first_packet = false;
      d_packets_observed = 0;
      d_total_packets_observed = 0;
      d_hop_reversal_inited = false;
      d_afh = false;
      d_looks_like_afh = false;
      d_have_UAP = false;
      d_have_NAP = false;
      d_have_clk6 = false;
      d_have_clk27 = false;
    }

    /*
     * Our virtual destructor.
     */
    basic_rate_piconet_impl::~basic_rate_piconet_impl()
    {
      if(d_hop_reversal_inited) {
        free(d_clock_candidates);
        free(d_sequence);
      }
    }

    /* initialize the hop reversal process */
    int basic_rate_piconet_impl::init_hop_reversal(bool aliased)
    {
      int max_candidates;
      uint32_t clock;

      printf("\nCalculating complete hopping sequence.\n");

      if (aliased) {
        max_candidates = (SEQUENCE_LENGTH / ALIASED_CHANNELS) / 32;
      }
      else {
        max_candidates = (SEQUENCE_LENGTH / CHANNELS) / 32;
      }
		
      /* this can hold twice the approximate number of initial candidates */
      d_clock_candidates = (uint32_t*) malloc(sizeof(uint32_t) * max_candidates);

      /* this holds the entire hopping sequence */
      d_sequence = (char*) malloc(SEQUENCE_LENGTH);

      precalc();
      address_precalc(((d_UAP<<24) | d_LAP) & 0xfffffff);
      gen_hops();
      clock = (d_clk_offset + d_first_pkt_time) & 0x3f;
      d_num_candidates = init_candidates(d_pattern_channels[0], clock);
      d_winnowed = 0;
      d_hop_reversal_inited = true;
      d_have_clk27 = false;
      d_aliased = aliased;

      printf("%d initial CLK1-27 candidates\n", d_num_candidates);

      return d_num_candidates;
    }

    /* do all the precalculation that can be done before knowing the address */
    void basic_rate_piconet_impl::precalc()
    {
      int i;
      int z, p_high, p_low;

      /* populate frequency register bank*/
      for (i = 0; i < CHANNELS; i++)
        d_bank[i] = ((i * 2) % CHANNELS);
      /* actual frequency is 2402 + d_bank[i] MHz */

      /* populate perm_table for all possible inputs */
      for (z = 0; z < 0x20; z++)
        for (p_high = 0; p_high < 0x20; p_high++)
          for (p_low = 0; p_low < 0x200; p_low++)
            d_perm_table[z][p_high][p_low] = perm5(z, p_high, p_low);
    }

    /* do precalculation that requires the address */
    void basic_rate_piconet_impl::address_precalc(int address)
    {
      /* precalculate some of single_hop()/gen_hop()'s variables */
      d_a1 = (address >> 23) & 0x1f;
      d_b = (address >> 19) & 0x0f;
      d_c1 = ((address >> 4) & 0x10) +
        ((address >> 3) & 0x08) +
        ((address >> 2) & 0x04) +
        ((address >> 1) & 0x02) +
        (address & 0x01);
      d_d1 = (address >> 10) & 0x1ff;
      d_e = ((address >> 7) & 0x40) +
        ((address >> 6) & 0x20) +
        ((address >> 5) & 0x10) +
        ((address >> 4) & 0x08) +
        ((address >> 3) & 0x04) +
        ((address >> 2) & 0x02) +
        ((address >> 1) & 0x01);
    }

    /* drop-in replacement for perm5() using lookup table */
    int basic_rate_piconet_impl::fast_perm(int z, int p_high, int p_low)
    {
      return(d_perm_table[z][p_high][p_low]);
    }

    
    /* 5 bit permutation */
    /* assumes z is constrained to 5 bits, p_high to 5 bits, p_low to 9 bits */
    int basic_rate_piconet_impl::perm5(int z, int p_high, int p_low)
    {
      int i, tmp, output, z_bit[5], p[14];
      int index1[] = {0, 2, 1, 3, 0, 1, 0, 3, 1, 0, 2, 1, 0, 1};
      int index2[] = {1, 3, 2, 4, 4, 3, 2, 4, 4, 3, 4, 3, 3, 2};

      /* bits of p_low and p_high are control signals */
      for (i = 0; i < 9; i++)
        p[i] = (p_low >> i) & 0x01;
      for (i = 0; i < 5; i++)
        p[i+9] = (p_high >> i) & 0x01;

      /* bit swapping will be easier with an array of bits */
      for (i = 0; i < 5; i++)
        z_bit[i] = (z >> i) & 0x01;

      /* butterfly operations */
      for (i = 13; i >= 0; i--) {
        /* swap bits according to index arrays if control signal tells us to */
        if (p[i]) {
          tmp = z_bit[index1[i]];
          z_bit[index1[i]] = z_bit[index2[i]];
          z_bit[index2[i]] = tmp;
        }
      }

      /* reconstruct output from rearranged bits */
      output = 0;
      for (i = 0; i < 5; i++)
        output += z_bit[i] << i;

      return(output);
    }

    /* generate the complete hopping sequence */
    void basic_rate_piconet_impl::gen_hops()
    {
      /* a, b, c, d, e, f, x, y1, y2 are variable names used in section 2.6 of the spec */
      /* b is already defined */
      /* e is already defined */
      int a, c, d, f, x;
      int h, i, j, k, c_flipped, perm_in, perm_out;

      /* sequence index = clock >> 1 */
      /* (hops only happen at every other clock value) */
      int index = 0;
      f = 0;

      /* nested loops for optimization (not recalculating every variable with every clock tick) */
      for (h = 0; h < 0x04; h++) { /* clock bits 26-27 */
        for (i = 0; i < 0x20; i++) { /* clock bits 21-25 */
          a = d_a1 ^ i;
          for (j = 0; j < 0x20; j++) { /* clock bits 16-20 */
            c = d_c1 ^ j;
            c_flipped = c ^ 0x1f;
            for (k = 0; k < 0x200; k++) { /* clock bits 7-15 */
              d = d_d1 ^ k;
              for (x = 0; x < 0x20; x++) { /* clock bits 2-6 */
                perm_in = ((x + a) % 32) ^ d_b;
                /* y1 (clock bit 1) = 0, y2 = 0 */
                perm_out = fast_perm(perm_in, c, d);
                d_sequence[index] = d_bank[(perm_out + d_e + f) % CHANNELS];
                if (d_afh) {
                  d_sequence[index + 1] = d_sequence[index];
                } else {
                  /* y1 (clock bit 1) = 1, y2 = 32 */
                  perm_out = fast_perm(perm_in, c_flipped, d);
                  d_sequence[index + 1] = d_bank[(perm_out + d_e + f + 32) % CHANNELS];
                }
                index += 2;
              }
              f += 16;
            }
          }
        }
      }
    }

    /* determine channel for a particular hop */
    /* replaced with gen_hops() for a complete sequence but could still come in handy */
    char basic_rate_piconet_impl::single_hop(int clock)
    {
      int a, c, d, f, x, y1, y2;

      /* following variable names used in section 2.6 of the spec */
      x = (clock >> 2) & 0x1f;
      y1 = (clock >> 1) & 0x01;
      y2 = y1 << 5;
      a = (d_a1 ^ (clock >> 21)) & 0x1f;
      /* b is already defined */
      c = (d_c1 ^ (clock >> 16)) & 0x1f;
      d = (d_d1 ^ (clock >> 7)) & 0x1ff;
      /* e is already defined */
      f = (clock >> 3) & 0x1fffff0;

      /* hop selection */
      return(d_bank[(fast_perm(((x + a) % 32) ^ d_b, (y1 * 0x1f) ^ c, d) + d_e + f + y2) % CHANNELS]);
    }

    /* look up channel for a particular hop */
    char basic_rate_piconet_impl::hop(int clock)
    {
      return d_sequence[clock];
    }

    /* create list of initial candidate clock values (hops with same channel as first observed hop) */
    int basic_rate_piconet_impl::init_candidates(char channel, int known_clock_bits)
    {
      int i;
      int count = 0; /* total number of candidates */
      char observable_channel; /* accounts for aliasing if necessary */

      /* only try clock values that match our known bits */
      for (i = known_clock_bits; i < SEQUENCE_LENGTH; i += 0x40) {
        if (d_aliased)
          observable_channel = aliased_channel(d_sequence[i]);
        else
          observable_channel = d_sequence[i];
        if (observable_channel == channel)
          d_clock_candidates[count++] = i;
        //FIXME ought to throw exception if count gets too big
      }
      return count;
    }
    
    /* narrow a list of candidate clock values based on a single observed hop */
    int basic_rate_piconet_impl::winnow(int offset, char channel)
    {
      int i;
      int new_count = 0; /* number of candidates after winnowing */
      char observable_channel; /* accounts for aliasing if necessary */

      /* check every candidate */
      for (i = 0; i < d_num_candidates; i++) {
        if (d_aliased)
          observable_channel = aliased_channel(d_sequence[(d_clock_candidates[i] + offset) % SEQUENCE_LENGTH]);
        else
          observable_channel = d_sequence[(d_clock_candidates[i] + offset) % SEQUENCE_LENGTH];
        if (observable_channel == channel) {
          /* this candidate matches the latest hop */
          /* blow away old list of candidates with new one */
          /* safe because new_count can never be greater than i */
          d_clock_candidates[new_count++] = d_clock_candidates[i];
        }
      }
      d_num_candidates = new_count;

      if (new_count == 1) {
        d_clk_offset = (d_clock_candidates[0] - d_first_pkt_time)
          & 0x7ffffff;
        d_have_clk27 = true;
        printf("\nAcquired CLK1-27 offset = 0x%07x\n", d_clk_offset);
      } else if (new_count == 0) {
        reset();
      } else {
        printf("%d CLK1-27 candidates remaining\n", new_count);
      }

      return new_count;
    }

    /* narrow a list of candidate clock values based on all observed hops */
    int basic_rate_piconet_impl::winnow()
    {
      int new_count = d_num_candidates;
      int index, last_index;
      uint8_t channel, last_channel;

      for (; d_winnowed < d_packets_observed; d_winnowed++) {
        index = d_pattern_indices[d_winnowed];
        channel = d_pattern_channels[d_winnowed];
        new_count = winnow(index, channel);

        if (d_packets_observed > 0) {
          last_index = d_pattern_indices[d_winnowed - 1];
          last_channel = d_pattern_channels[d_winnowed - 1];
          /*
           * Two packets in a row on the same channel should only
           * happen if adaptive frequency hopping is in use.
           * There can be false positives, though, especially if
           * there is aliasing.
           */
          if (!d_looks_like_afh && (index == last_index + 1)
              && (channel == last_channel))
            d_looks_like_afh = true;
        }
      }
	
      return new_count;
    }

    /* offset between CLKN (local) and CLK of piconet */
    uint32_t basic_rate_piconet_impl::get_offset()
    {
      /* caller should check have_clk6() and/or have_clk27() */
      return d_clk_offset;
    }

    /* set clock offset */
    void basic_rate_piconet_impl::set_offset(uint32_t offset)
    {
      d_clk_offset = offset;
      d_have_clk6 = true;
      d_have_clk27 = true;
    }

    /* UAP */
    uint8_t basic_rate_piconet_impl::get_UAP()
    {
      /* caller should check have_UAP() */
      return d_UAP;
    }

    void basic_rate_piconet_impl::set_UAP(uint8_t uap)
    {
      d_UAP = uap;
      d_have_UAP = true;
    }

    /* NAP */
    uint16_t basic_rate_piconet_impl::get_NAP()
    {
      /* caller should check have_NAP() */
      return d_NAP;
    }

    void basic_rate_piconet_impl::set_NAP(uint16_t nap)
    {
      d_NAP = nap;
      d_have_NAP = true;
    }

    /* discovery status */
    bool basic_rate_piconet_impl::have_UAP()
    {
      return d_have_UAP;
    }

    bool basic_rate_piconet_impl::have_NAP()
    {
      return d_have_NAP;
    }

    bool basic_rate_piconet_impl::have_clk6()
    {
      return d_have_clk6;
    }

    bool basic_rate_piconet_impl::have_clk27()
    {
      return d_have_clk27;
    }

    /* use packet headers to determine UAP */
    bool basic_rate_piconet_impl::UAP_from_header(classic_packet::sptr packet)
    {
      uint8_t UAP;
      int count, retval, first_clock = 0;

      int starting = 0;
      int remaining = 0;
      uint32_t clkn = packet->d_clkn;

      if (!d_got_first_packet)
        d_first_pkt_time = clkn;

      if (d_packets_observed < MAX_PATTERN_LENGTH) {
        d_pattern_indices[d_packets_observed] = clkn - d_first_pkt_time;
        d_pattern_channels[d_packets_observed] = packet->get_channel( );
      } else {
        printf("Oops. More hops than we can remember.\n");
        reset();
        return false; //FIXME ought to throw exception
      }
      d_packets_observed++;
      d_total_packets_observed++;

      /* try every possible first packet clock value */
      for (count = 0; count < 64; count++) {
        /* skip eliminated candidates unless this is our first time through */
        if (d_clock6_candidates[count] > -1 || !d_got_first_packet) {
          /* clock value for the current packet assuming count was the clock of the first packet */
          int clock = (count + clkn - d_first_pkt_time) % 64;
          starting++;
          UAP = packet->try_clock(clock);
          retval = -1;

          /* if this is the first packet: populate the candidate list */
          /* if not: check CRCs if UAPs match */
          if (!d_got_first_packet || UAP == d_clock6_candidates[count])
            retval = packet->crc_check(clock);

          switch(retval) {

          case -1: /* UAP mismatch */
          case 0: /* CRC failure */
            d_clock6_candidates[count] = -1;
            break;

          case 1: /* inconclusive result */
            d_clock6_candidates[count] = UAP;
            /* remember this count because it may be the correct clock of the first packet */
            first_clock = count;
            remaining++;
            break;

          default: /* CRC success */
            printf("Correct CRC! UAP = 0x%x found after %d total packets.\n",
                   UAP, d_total_packets_observed);
            d_clk_offset = (count - (d_first_pkt_time & 0x3f)) & 0x3f;
            d_UAP = UAP;
            d_have_clk6 = true;
            d_have_UAP = true;
            d_total_packets_observed = 0;
            return true;
          }
        }
      }

      d_got_first_packet = true;

      printf("reduced from %d to %d CLK1-6 candidates\n", starting, remaining);

      if (remaining == 1) {
        d_clk_offset = (first_clock - (d_first_pkt_time & 0x3f)) & 0x3f;
        d_UAP = d_clock6_candidates[first_clock];
        d_have_clk6 = true;
        d_have_UAP = true;
        printf("We have a winner! UAP = 0x%x found after %d total packets.\n",
               d_UAP, d_total_packets_observed);
        d_total_packets_observed = 0;
        return true;
      }

      if (remaining == 0)
        reset();

      return false;
    }

    /* return the observable channel (26-50) for a given channel (0-78) */
    char basic_rate_piconet_impl::aliased_channel(char channel)
    {
      return ((channel + 24) % ALIASED_CHANNELS) + 26;
    }

    /* reset UAP/clock discovery */
    void basic_rate_piconet_impl::reset()
    {
      printf("no candidates remaining! starting over . . .\n");

      if(d_hop_reversal_inited) {
        free(d_clock_candidates);
        free(d_sequence);
      }
      d_got_first_packet = false;
      d_packets_observed = 0;
      d_hop_reversal_inited = false;
      d_have_UAP = false;
      d_have_clk6 = false;
      d_have_clk27 = false;

      /*
       * If we have recently observed two packets in a row on the same
       * channel, try AFH next time.  If not, don't.
       */
      d_afh = d_looks_like_afh;
      d_looks_like_afh = false;
    }

    // ---------------------------------------------------------------------

    low_energy_piconet::sptr
    low_energy_piconet::make(const uint32_t aa)
    {
      return low_energy_piconet::sptr(new low_energy_piconet_impl(aa));
    }

    // ---------------------------------------------------------------------

    low_energy_piconet_impl::low_energy_piconet_impl(uint32_t aa) {
      // TODO
    }

    low_energy_piconet_impl::~low_energy_piconet_impl( ) {
      // TODO
    }

    int low_energy_piconet_impl::init_hop_reversal(bool aliased) {
      // TODO
      return -1;
    }

    char low_energy_piconet_impl::hop(int clock) {
      // TODO
      return -1;
    }

    char low_energy_piconet_impl::aliased_channel(char channel) {
      // TODO
      return -1;
    }

    void low_energy_piconet_impl::reset( ) {
      // TODO
    }

  } /* namespace bluetooth */
} /* namespace gr */

