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

#ifndef __PACKETSOURCE_USRP_H__
#define __PACKETSOURCE_USRP_H__

#include "config.h"

#include <packetsource.h>
#include "bluetooth_top_block.h"

#define USE_PACKETSOURCE_USRP

class PacketSource_USRP : public KisPacketSource {
public:
	PacketSource_USRP() {
		fprintf(stderr, "FATAL OOPS: Packetsource_USRP()\n");
		exit(1);
	}

	PacketSource_USRP(GlobalRegistry *in_globalreg) :
		KisPacketSource(in_globalreg) {

	}

	virtual KisPacketSource *CreateSource(GlobalRegistry *in_globalreg,
										  string in_interface,
										  vector<opt_pair> *in_opts) {
		return new PacketSource_USRP(in_globalreg, in_interface, in_opts);
	}

	virtual int AutotypeProbe(string in_device);

	virtual int RegisterSources(Packetsourcetracker *tracker) {
		tracker->RegisterPacketProto("usrp", this, "BLUETOOTH", 0);
		return 1;
	}

	PacketSource_USRP(GlobalRegistry *in_globalreg, string in_interface,
					   vector<opt_pair> *in_opts);

	virtual ~PacketSource_USRP();

	virtual int ParseOptions(vector<opt_pair> *in_opts);

	virtual int OpenSource();
	virtual int CloseSource();

	virtual int FetchChannelCapable() { return 1; }
	virtual int EnableMonitor() { return 1; }
	virtual int DisableMonitor() { return 1; }

	virtual int SetChannel(unsigned int in_ch);

	virtual int FetchDescriptor();
	virtual int Poll();

	unsigned int channel;

protected:
	virtual void FetchRadioData(kis_packet *in_packet) { };

	int btbb_packet_id;

	int thread_active;

	pthread_t cap_thread;

	// Named USB interface
	string usb_dev;

	// GNU Radio flowgraph
	bluetooth_top_block_sptr top_block;
	bluetooth_kismet_block_sptr kblock;

	//struct usb_dev_handle *devhdl;

	// Error from thread
	string thread_error;

	friend void *usrp_cap_thread(void *);

	void packet_callback(char *pkt, int len);
	
};

#endif
