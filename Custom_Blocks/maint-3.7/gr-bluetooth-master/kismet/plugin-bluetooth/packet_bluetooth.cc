/* -*- c++ -*- */
/*
 * Copyright 2010 Michael Ossmann
 * Copyright 2009, 2010 Mike Kershaw
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
#include "config.h"

#include <packetchain.h>
#include <packetsource.h>
#include <endian_magic.h>

#include "packet_bluetooth.h"

// From kismet_bluetooth
extern int pack_comp_bluetooth;

static int debugno = 0;

int kis_bluetooth_dissector(CHAINCALL_PARMS) {
	int offset = 0;

	bluetooth_packinfo *pi = NULL;

	if (in_pack->error)
		return 0;

	kis_datachunk *chunk =
		(kis_datachunk *) in_pack->fetch(_PCM(PACK_COMP_LINKFRAME));

	if (chunk == NULL)
		return 0;

	if (chunk->dlt != KDLT_BLUETOOTH)
		return 0;

	debugno++;

	if (chunk->length < 14) {
		_MSG("Short Bluetooth frame!", MSGFLAG_ERROR);
		in_pack->error = 1;
		return 0;
	}

	pi = new bluetooth_packinfo();

	pi->type = btbb_type_id;
	// this is so not the right way to do this
	pi->lap = chunk->data[9] << 16;
	pi->lap |= chunk->data[10] << 8;
	pi->lap |= chunk->data[11];

	//printf("Bluetooth Packet %d\n", debugno);

	in_pack->insert(pack_comp_bluetooth, pi);

	return 1;
}
