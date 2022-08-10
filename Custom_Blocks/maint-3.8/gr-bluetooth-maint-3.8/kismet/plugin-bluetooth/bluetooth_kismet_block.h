/* -*- c++ -*- */
/*
 * Copyright 2008, 2009, 2010 Michael Ossmann
 * Copyright 2007, 2008, 2009 Dominic Spill
 * Copyright 2005, 2006 Free Software Foundation, Inc.
 * 
 * This file is part of gr-bluetooth
 * 
 * gr-bluetooth is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 * 
 * gr-bluetooth is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with gr-bluetooth; see the file COPYING.  If not, write to
 * the Free Software Foundation, Inc., 51 Franklin Street,
 * Boston, MA 02110-1301, USA.
 */

#ifndef INCLUDED_BLUETOOTH_KISMET_BLOCK_H
#define INCLUDED_BLUETOOTH_KSIMET_BLOCK_H

#include <bluetooth_multi_block.h>
#include <bluetooth_packet.h>
#include <pthread.h>
#include <vector>

class bluetooth_kismet_block;
typedef boost::shared_ptr<bluetooth_kismet_block> bluetooth_kismet_block_sptr;

/*!
 * \brief Return a shared_ptr to a new instance of bluetooth_kismet_block.
 */
bluetooth_kismet_block_sptr bluetooth_make_kismet_block(double sample_rate, double center_freq, double squelch_threshold);

/*!
 * \brief Sniff Bluetooth packets.
 * \ingroup block
 */
class bluetooth_kismet_block : public bluetooth_multi_block
{
private:
	// The friend declaration allows bluetooth_make_kismet_block to
	// access the private constructor.
	friend bluetooth_kismet_block_sptr bluetooth_make_kismet_block(double sample_rate, double center_freq, double squelch_threshold);

	/* constructor */
	bluetooth_kismet_block(double sample_rate, double center_freq, double squelch_threshold);

	void enqueue(bluetooth_packet_sptr packet, int channel);

public:
	/* destructor */
	~bluetooth_kismet_block();

	struct usrp_bt_pkt {
		char *data;
		int len;
		int channel;
	};

	pthread_mutex_t packet_lock;

	// Packet storage, locked with packet_lock
	vector<struct usrp_bt_pkt *> packet_queue;

	// Pending packet, locked with packet_lock
	int pending_packet;

	// FD pipes
	int fake_fd[2];

	/* handle input */
	int work(int noutput_items,
		    gr_vector_const_void_star &input_items,
		    gr_vector_void_star &output_items);
};

#endif /* INCLUDED_BLUETOOTH_KISMET_BLOCK_H */
