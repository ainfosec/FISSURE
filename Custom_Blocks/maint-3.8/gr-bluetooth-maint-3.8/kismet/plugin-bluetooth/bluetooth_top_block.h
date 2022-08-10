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

#include <gnuradio/top_block.h>
#include "bluetooth_kismet_block.h"

class bluetooth_top_block;
typedef boost::shared_ptr<bluetooth_top_block> bluetooth_top_block_sptr;
bluetooth_top_block_sptr bluetooth_make_top_block();

class bluetooth_top_block : public gr::top_block
{
private:
	bluetooth_top_block();
	friend bluetooth_top_block_sptr bluetooth_make_top_block();

public:
	bluetooth_kismet_block_sptr sink;
};
