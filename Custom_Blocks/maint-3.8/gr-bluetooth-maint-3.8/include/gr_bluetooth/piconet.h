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


#ifndef INCLUDED_GR_BLUETOOTH_PICONET_H
#define INCLUDED_GR_BLUETOOTH_PICONET_H

#include <gr_bluetooth/api.h>
#include "gr_bluetooth/packet.h"

namespace gr {
  namespace bluetooth {

    class GR_BLUETOOTH_API piconet
    {
    private:
      friend class base_rate_piconet;
      friend class low_energy_piconet;

      /* queue of packets to be decoded */
      std::vector<packet::sptr> d_pkt_queue;

    public:
      typedef boost::shared_ptr<piconet> sptr;

      /* initialize the hop reversal process */
      /* returns number of initial candidates for CLK1-27 */
      virtual int init_hop_reversal(bool aliased) = 0;

      /* look up channel for a particular hop */
      virtual char hop(int clock) = 0;

      /* return the observable channel (26-50) for a given channel (0-78) */
      virtual char aliased_channel(char channel) = 0;

      /* reset UAP/clock discovery */
      virtual void reset() = 0;

      /* add a packet to the queue */
      void enqueue(packet::sptr pkt);

      /* pull the first packet from the queue (FIFO) */
      packet::sptr dequeue();
    };

    class GR_BLUETOOTH_API basic_rate_piconet : public piconet {
    public:
      typedef boost::shared_ptr<basic_rate_piconet> sptr;

      /*!
       * \brief Return a shared_ptr to a new instance of gr::bluetooth::basic_rate_piconet.
       *
       * To avoid accidental use of raw pointers, gr::bluetooth::basic_rate_piconet's
       * constructor is in a private implementation
       * class. gr::bluetooth::basic_rate_piconet::make is the public interface for
       * creating new instances.
       */
      static sptr make(uint32_t LAP);

      /* number of hops in the hopping sequence (i.e. number of possible values of CLK1-27) */
      static const int SEQUENCE_LENGTH = 134217728;

      /* narrow a list of candidate clock values based on a single observed hop */
      virtual int winnow(int offset, char channel) = 0;

      /* narrow a list of candidate clock values based on all observed hops */
      virtual int winnow() = 0;

      /* offset between CLKN (local) and CLK of piconet */
      virtual uint32_t get_offset() = 0;
      virtual void set_offset(uint32_t offset) = 0;

      /* UAP */
      virtual uint8_t get_UAP() = 0;
      virtual void set_UAP(uint8_t uap) = 0;

      /* NAP */
      virtual uint16_t get_NAP() = 0;
      virtual void set_NAP(uint16_t nap) = 0;

      /* use classic_packet headers to determine UAP */
      virtual bool UAP_from_header(classic_packet::sptr packet) = 0;

      /* discovery status */
      virtual bool have_UAP() = 0;
      virtual bool have_NAP() = 0;
      virtual bool have_clk6() = 0;
      virtual bool have_clk27() = 0;

      // -------------------------------------------------------------------

      /* initialize the hop reversal process */
      /* returns number of initial candidates for CLK1-27 */
      virtual int init_hop_reversal(bool aliased) = 0;

      /* look up channel for a particular hop */
      virtual char hop(int clock) = 0;

      /* return the observable channel (26-50) for a given channel (0-78) */
      virtual char aliased_channel(char channel) = 0;

      /* reset UAP/clock discovery */
      virtual void reset() = 0;
    };

    class GR_BLUETOOTH_API low_energy_piconet : public piconet {
    public:
      typedef boost::shared_ptr<low_energy_piconet> sptr;

      /*!
       * \brief Return a shared_ptr to a new instance of gr::bluetooth::low_energy_piconet.
       *
       * To avoid accidental use of raw pointers, gr::bluetooth::low_energy_piconet's
       * constructor is in a private implementation
       * class. gr::bluetooth::low_energy_piconet::make is the public interface for
       * creating new instances.
       */
      static sptr make(const uint32_t aa);

      // -------------------------------------------------------------------

      /* initialize the hop reversal process */
      /* returns number of initial candidates for CLK1-27 */
      virtual int init_hop_reversal(bool aliased) = 0;

      /* look up channel for a particular hop */
      virtual char hop(int clock) = 0;

      /* return the observable channel (26-50) for a given channel (0-78) */
      virtual char aliased_channel(char channel) = 0;

      /* reset alignment discovery */
      virtual void reset() = 0;
    };

  } // namespace bluetooth
} // namespace gr

#endif /* INCLUDED_GR_BLUETOOTH_PICONET_H */

