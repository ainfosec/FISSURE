/* -*- c++ -*- */
/*
 * Copyright 2010 Michael Ossmann
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

#include "bluetooth_top_block.h"
#include <gnuradio/io_signature.h>
#include <usrp_source_c.h>

// Shared pointer constructor
bluetooth_top_block_sptr bluetooth_make_top_block()
{
  return gnuradio::get_initial_sptr(new bluetooth_top_block());
}

// Hierarchical block constructor, with no inputs or outputs
bluetooth_top_block::bluetooth_top_block() : 
	gr_top_block("bluetooth_top_block")
{
	//FIXME a lot of this stuff should be configurable
	int which_board = 0;
	unsigned int decimation = 32;
	usrp_source_c_sptr usrp = usrp_make_source_c(which_board, decimation);

	usrp_subdev_spec spec(1,0); // B side daughterboard
	//spec.side = 1;
	//spec.subdev = 1;
	db_base_sptr subdev = usrp->selected_subdev(spec);
	printf("Subdevice name is %s\n", subdev->side_and_name().c_str());
	printf("Subdevice freq range: (%g, %g)\n",
			subdev->freq_min(), subdev->freq_max());

	unsigned int mux = usrp->determine_rx_mux_value(spec);
	mux = usrp->determine_rx_mux_value(spec);
	printf("mux: %#08x\n",  mux);
	usrp->set_mux(mux);

	float gain;
	float gain_min = subdev->gain_min();
	float gain_max = subdev->gain_max();
	//if(gain == -1) {
		gain = (gain_min + gain_max)/2.0;
	//}
	printf("gain: %g\n", gain);
	subdev->set_gain(gain);

	double freq = 2477000000;
	usrp_tune_result r;
	bool ok = usrp->tune(0, subdev, freq, &r); //DDC 0
	if (!ok)
		throw std::runtime_error("Could not set frequency.");

	double sample_rate = 64000000 / decimation;
	double squelch_threshold = -1000;
	sink = bluetooth_make_kismet_block(sample_rate, freq, squelch_threshold);

	connect(usrp, 0, sink, 0);
}
