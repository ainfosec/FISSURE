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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "bluetooth_kismet_block.h"

/*
 * Create a new instance of bluetooth_kismet_block and return
 * a boost shared_ptr.  This is effectively the public constructor.
 */
bluetooth_kismet_block_sptr
bluetooth_make_kismet_block(double sample_rate, double center_freq, double squelch_threshold)
{
  return bluetooth_kismet_block_sptr (new bluetooth_kismet_block(sample_rate, center_freq, squelch_threshold));
}

//private constructor
bluetooth_kismet_block::bluetooth_kismet_block(double sample_rate, double center_freq, double squelch_threshold)
  : bluetooth_multi_block(sample_rate, center_freq, squelch_threshold)
{
	set_symbol_history(68);
	pending_packet = 0;
	fake_fd[0] = -1;
	fake_fd[1] = -1;

	printf("lowest channel: %d, highest channel %d\n", d_low_channel, d_high_channel);
}

//virtual destructor.
bluetooth_kismet_block::~bluetooth_kismet_block ()
{
}

int bluetooth_kismet_block::work(int noutput_items,
			       gr_vector_const_void_star &input_items,
			       gr_vector_void_star &output_items)
{
	int retval, channel;
	char symbols[history()]; //poor estimate but safe

	for (channel = d_low_channel; channel <= d_high_channel; channel++) {
		int num_symbols = channel_symbols(channel, input_items,
				symbols, history() /*+ noutput_items*/);

		/* completely skip this time slot if we didn't break squelch */
		if (num_symbols == 0)
			break;

		if (num_symbols >= 68 ) {
			/* don't look beyond one slot for ACs */
			int latest_ac = (num_symbols - 68) < 625 ? (num_symbols - 68) : 625;
			retval = bluetooth_packet::sniff_ac(symbols, latest_ac);
			if (retval > -1) {
				bluetooth_packet_sptr packet = bluetooth_make_packet(&symbols[retval], num_symbols - retval);
				enqueue(packet, channel);
				//printf("GOT PACKET on channel %d, LAP = %06x at time slot %d\n",
					//channel, (int) packet->get_LAP(), (int) (d_cumulative_count / d_samples_per_slot));
			}
		}
	}
	d_cumulative_count += (int) d_samples_per_slot;

	/* 
	 * The runtime system wants to know how many output items we produced, assuming that this is equal
	 * to the number of input items consumed.  We tell it that we produced/consumed one time slot of
	 * input items so that our next run starts one slot later.
	 */
	return (int) d_samples_per_slot;
}

void bluetooth_kismet_block::enqueue(bluetooth_packet_sptr pkt, int channel)
{
	//FIXME should use tun_format() or similar
	char *data = new char[14];
	int len = 14;
	uint32_t lap = pkt->get_LAP();
	//sleep(1);
	data[0] = data[1] = data[2] = data[3] = data[4] = data[5] = 0x00;
	data[6] = data[7] = data[8] = 0x00;
	data[9] = (lap >> 16) & 0xff;
	data[10] = (lap >> 8) & 0xff;
	data[11] = lap & 0xff;
	data[12] = 0xff;
	data[13] = 0xf0;

	// Lock the packet queue, throw away when there are more than 20 in the queue
	// that haven't been handled, raise the file descriptor hot if we need to
	pthread_mutex_lock(&packet_lock);

	if (packet_queue.size() > 20) {
		// printf("debug - thread packet queue to big\n");
	} else {
		//struct bluetooth_kismet_block::usrp_bt_pkt *rpkt = new bluetooth_kismet_block::usrp_bt_pkt;
		struct usrp_bt_pkt *rpkt = new usrp_bt_pkt;
		rpkt->data = data;
		rpkt->len = len;
		rpkt->channel = channel;

		packet_queue.push_back(rpkt);
		if (pending_packet == 0) {
			// printf("debug - writing to fakefd\n");
			pending_packet = 1;
			write(fake_fd[1], data, 1);
		}

	}
	pthread_mutex_unlock(&packet_lock);
}
