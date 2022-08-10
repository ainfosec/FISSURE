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

#include <vector>

#include <util.h>
#include <messagebus.h>
#include <packet.h>
#include <packetchain.h>
#include <packetsource.h>
#include <packetsourcetracker.h>
#include <timetracker.h>
#include <configfile.h>
#include <plugintracker.h>
#include <globalregistry.h>
#include <dumpfile.h>
#include <pcap.h>

#include "packetsource_usrp.h"
#include "packet_bluetooth.h"

PacketSource_USRP::PacketSource_USRP(GlobalRegistry *in_globalreg, string in_interface,
									   vector<opt_pair> *in_opts) : 
	KisPacketSource(in_globalreg, in_interface, in_opts) {

	thread_active = 0;
	//devhdl = NULL;

	//fake_fd[0] = -1;
	//fake_fd[1] = -1;

	channel = 0;

	btbb_packet_id = globalreg->packetchain->RegisterPacketComponent("BLUETOOTH");
}

PacketSource_USRP::~PacketSource_USRP() {
	CloseSource();
}
	

int PacketSource_USRP::ParseOptions(vector<opt_pair> *in_opts) {
	//if (FetchOpt("device", in_opts) != "") {
		//usb_dev = FetchOpt("usbdev", in_opts);
		//_MSG("USRP Bluetooth using USB device '" + usb_dev + "'", MSGFLAG_INFO);
	//} else {
		_MSG("USRP Bluetooth using first USB device that looks like a USRP",
			 MSGFLAG_INFO);
	//}

	return 1;
}

int PacketSource_USRP::AutotypeProbe(string in_device) {
	// Shortcut like we do on airport
	if (in_device == "usrp") {
		type = "usrp";
		return 1;
	}
}

// Capture thread to fake async io
void *usrp_cap_thread(void *arg) {
	PacketSource_USRP *usrp = (PacketSource_USRP *) arg;

	while (usrp->thread_active > 0)
		usrp->top_block->run();

	usrp->thread_active = -1;
	close(usrp->kblock->fake_fd[1]);
	usrp->kblock->fake_fd[1] = -1;
	pthread_exit((void *) 0);
}

int PacketSource_USRP::OpenSource() {
	//if ((devhdl = usb_open(dev)) == NULL) {
		//_MSG("USRP Bluetooth '" + name + "' failed to open device '" + usb_dev + "': " +
			 //string(strerror(errno)), MSGFLAG_ERROR);
		//return 0;
	//}

	top_block = bluetooth_make_top_block();
	kblock = top_block->sink;

	/* Initialize the pipe, mutex, and reading thread */
	if (pipe(kblock->fake_fd) < 0) {
		_MSG("USRP Bluetooth '" + name + "' failed to make a pipe() (this is really "
			 "weird): " + string(strerror(errno)), MSGFLAG_ERROR);
		//usb_close(devhdl);
		//devhdl = NULL;
		return 0;
	}

	//FIXME move to kblock?
	if (pthread_mutex_init(&(kblock->packet_lock), NULL) < 0) {
		_MSG("USRP Bluetooth '" + name + "' failed to initialize pthread mutex: " +
			 string(strerror(errno)), MSGFLAG_ERROR);
		//usb_close(devhdl);
		//devhdl = NULL;
		return 0;
	}

	/* Launch a capture thread */
	thread_active = 1;
	pthread_create(&cap_thread, NULL, usrp_cap_thread, this);

	return 1;
}

int PacketSource_USRP::CloseSource() {
	void *ret;

	if (thread_active > 0) {
		// Tell the thread to die
		thread_active = 0;
		top_block->stop();

		// Grab it back
		pthread_join(cap_thread, &ret);

		// Kill the mutex
		pthread_mutex_destroy(&(kblock->packet_lock));
	}

	//FIXME delete blocks

	// Close the USB dev
	//if (devhdl) {
		//usb_close(devhdl);
		//devhdl = NULL;
	//}

	if (kblock->fake_fd[0] >= 0) {
		close(kblock->fake_fd[0]);
		kblock->fake_fd[0] = -1;
	}

	if (kblock->fake_fd[1] >= 0) {
		close(kblock->fake_fd[1]);
		kblock->fake_fd[1] = -1;
	}

	return 1;
}

int PacketSource_USRP::SetChannel(unsigned int in_ch) {
	if (in_ch < 0 || in_ch > 78)
		return -1;

	//if (thread_active <= 0 || devhdl == NULL)
	if (thread_active)
		return 0;

	//FIXME actually set the channel

	channel = in_ch;

	return 1;
}

int PacketSource_USRP::FetchDescriptor() {
	// This is as good a place as any to catch a failure
	if (thread_active < 0) {
		_MSG("USRP Bluetooth '" + name + "' capture thread failed: " +
			 thread_error, MSGFLAG_INFO);
		CloseSource();
		return -1;
	}

	return kblock->fake_fd[0];
}

int PacketSource_USRP::Poll() {
	char rx;

	// Consume the junk byte we used to raise the FD high
	read(kblock->fake_fd[0], &rx, 1);

	pthread_mutex_lock(&(kblock->packet_lock));

	kblock->pending_packet = 0;

	for (unsigned int x = 0; x < kblock->packet_queue.size(); x++) {
		kis_packet *newpack = globalreg->packetchain->GeneratePacket();

		newpack->ts.tv_sec = globalreg->timestamp.tv_sec;
		newpack->ts.tv_usec = globalreg->timestamp.tv_usec;

		kis_datachunk *rawchunk = new kis_datachunk;

		rawchunk->length = kblock->packet_queue[x]->len;
		rawchunk->data = new uint8_t[rawchunk->length];
		memcpy(rawchunk->data, kblock->packet_queue[x]->data, rawchunk->length);
		rawchunk->source_id = source_id;

		rawchunk->dlt = KDLT_BLUETOOTH;

		newpack->insert(_PCM(PACK_COMP_LINKFRAME), rawchunk);

		printf("debug - Got packet chan %d len=%d\n", kblock->packet_queue[x]->channel, kblock->packet_queue[x]->len);

		num_packets++;

		kis_ref_capsource *csrc_ref = new kis_ref_capsource;
		csrc_ref->ref_source = this;
		newpack->insert(_PCM(PACK_COMP_KISCAPSRC), csrc_ref);

		globalreg->packetchain->ProcessPacket(newpack);

		// Delete the temp struct and data
		delete kblock->packet_queue[x]->data;
		delete kblock->packet_queue[x];
	}

	// Flush the queue
	kblock->packet_queue.clear();

	//printf("debug - packet queue cleared %d\n", kblock->packet_queue.size());

	pthread_mutex_unlock(&(kblock->packet_lock));

	return 1;
}
