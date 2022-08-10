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

#ifndef INCLUDED_BLUETOOTH_GR_BLUETOOTH_MULTI_HOPPER_IMPL_H
#define INCLUDED_BLUETOOTH_GR_BLUETOOTH_MULTI_HOPPER_IMPL_H

#include "gr_bluetooth/multi_hopper.h"
#include "gr_bluetooth/piconet.h"
#include "tun.h"

namespace gr {
  namespace bluetooth {

    class multi_hopper_impl : virtual public multi_hopper
    {
    private:
	/* LAP of the target piconet */
	uint32_t d_LAP;

	/* true if using a particular aliasing receiver implementation */
	bool d_aliased;

	/* Using tun for output */
	bool d_tun;

	/* the piconet we are monitoring */
        basic_rate_piconet::sptr d_piconet;

	/*
	 * follow a piconet's hopping sequence and look for packets on the
	 * appropriate channel for each time slot
	 */
	void hopalong(gr_vector_const_void_star &input_items, char *symbols,
			uint32_t clkn, int noutput_items);

	/* Tun stuff */
	int			d_tunfd;	// TUN fd
	char			chan_name[20];  // TUN interface name
	unsigned char		d_ether_addr[ETH_ALEN];
	static const unsigned short ETHER_TYPE = 0xFFF0;

    public:
      multi_hopper_impl(double sample_rate, double center_freq, double squelch_threshold, int LAP, bool aliased, bool tun);
      ~multi_hopper_impl();

      // Where all the action really happens
      int work(int noutput_items,
	       gr_vector_const_void_star &input_items,
	       gr_vector_void_star &output_items);
    };

  } // namespace bluetooth
} // namespace gr

#endif /* INCLUDED_BLUETOOTH_GR_BLUETOOTH_MULTI_HOPPER_IMPL_H */

