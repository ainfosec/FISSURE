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

#include <config.h>
#include <string>
#include <errno.h>
#include <time.h>

#include <pthread.h>

#include <sstream>
#include <iomanip>

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
#include <netracker.h>
#include <packetdissectors.h>
#include <alertracker.h>
#include <dumpfile_pcap.h>
#include <version.h>

#include "packetsource_usrp.h"
#include "packet_bluetooth.h"
#include "tracker_bluetooth.h"

GlobalRegistry *globalreg = NULL;

int pack_comp_bluetooth;

int bluetooth_unregister(GlobalRegistry *in_globalreg) {
	return 0;
}

int bluetooth_register(GlobalRegistry *in_globalreg) {
	globalreg = in_globalreg;

	globalreg->sourcetracker->AddChannelList("bluetooth:"
			"0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,"
			"20,21,22,23,24,25,26,27,28,29,30,31,32,33,34,35,36,37,38,39,"
			"40,41,42,43,44,45,46,47,48,49,50,51,52,53,54,55,56,57,58,59,"
			"60,61,62,63,64,65,66,67,68,69,70,71,72,73,74,75,76,77,78");

	if (globalreg->sourcetracker->RegisterPacketSource(new PacketSource_USRP(globalreg)) < 0 || globalreg->fatal_condition)
		return -1;

	globalreg->packetchain->RegisterHandler(&kis_bluetooth_dissector, NULL,
											CHAINPOS_LLCDISSECT, 1);

	pack_comp_bluetooth =
		globalreg->packetchain->RegisterPacketComponent("BLUETOOTHFRAME");

	// dumpfile that inherits from the global one
	Dumpfile_Pcap *bluetoothdump;
	bluetoothdump = 
		new Dumpfile_Pcap(globalreg, "pcapbtbb", KDLT_BLUETOOTH,
						  globalreg->pcapdump, NULL, NULL);
	bluetoothdump->SetVolatile(1);

	// Tracker
	Tracker_Bluetooth *trackbtbb = new Tracker_Bluetooth(globalreg);

	return 1;
}

extern "C" {
	int kis_plugin_info(plugin_usrdata *data) {
		data->pl_name = "BLUETOOTH";
		data->pl_version = string(VERSION_MAJOR) + "-" + string(VERSION_MINOR) + "-" +
			string(VERSION_TINY);
		data->pl_description = "Bluetooth protocol plugin";
		data->pl_unloadable = 0; // We can't be unloaded because we defined a source
		data->plugin_register = bluetooth_register;
		data->plugin_unregister = bluetooth_unregister;

		return 1;
	}

	void kis_revision_info(plugin_revision *prev) {
		if (prev->version_api_revision >= 1) {
			prev->version_api_revision = 1;
			prev->major = string(VERSION_MAJOR);
			prev->minor = string(VERSION_MINOR);
			prev->tiny = string(VERSION_TINY);
		}
	}
}
