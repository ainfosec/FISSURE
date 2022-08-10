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

#include <stdio.h>

#include <string>
#include <sstream>

#include <globalregistry.h>
#include <gpscore.h>
#include <kis_panel_plugin.h>
#include <kis_panel_frontend.h>
#include <kis_panel_windows.h>
#include <kis_panel_network.h>
#include <kis_panel_widgets.h>
#include <version.h>

#include "tracker_bluetooth.h"

const char *bluetoothdev_fields[] = {
	"bdaddr", "firsttime",
	"lasttime", "packets",
	GPS_COMMON_FIELDS_TEXT,
	NULL
};

enum bluetooth_sort_type {
	bluetooth_sort_bdaddr,
	bluetooth_sort_firsttime,
	bluetooth_sort_lasttime,
	bluetooth_sort_packets
};

struct bluetooth_data {
	int mi_plugin_bluetooth, mi_showbluetooth;

	int mn_sub_sort, mi_sort_bdaddr, mi_sort_firsttime,
			mi_sort_lasttime, mi_sort_packets;

	map<mac_addr, bluetooth_network *> btdev_map;
	vector<bluetooth_network *> btdev_vec;

	Kis_Scrollable_Table *btdevlist;

	int cliaddref;

	int timerid;

	string asm_bluetoothdev_fields;
	int asm_bluetoothdev_num;

	bluetooth_sort_type sort_type;

	KisPanelPluginData *pdata;
	Kis_Menu *menu;
};

class Bluetooth_Sort_Bdaddr {
public:
	inline bool operator()(bluetooth_network *x, bluetooth_network *y) const {
		return x->bd_addr < y->bd_addr;
	}
};

class Bluetooth_Sort_Firsttime {
public:
	inline bool operator()(bluetooth_network *x, bluetooth_network *y) const {
		return x->first_time < y->first_time;
	}
};

class Bluetooth_Sort_Lasttime {
public:
	inline bool operator()(bluetooth_network *x, bluetooth_network *y) const {
		return x->last_time < y->last_time;
	}
};

class Bluetooth_Sort_Packets {
public:
	inline bool operator()(bluetooth_network *x, bluetooth_network *y) const {
		return x->num_packets < y->num_packets;
	}
};

// Menu events
int Bluetooth_plugin_menu_cb(void *auxptr);
void Bluetooth_show_menu_cb(MENUITEM_CB_PARMS);
void Bluetooth_sort_menu_cb(MENUITEM_CB_PARMS);

// Network events
void BluetoothCliAdd(KPI_ADDCLI_CB_PARMS);
void BluetoothCliConfigured(CLICONF_CB_PARMS);

// List select
int BluetoothDevlistCB(COMPONENT_CALLBACK_PARMS);

// List content timer
int BluetoothTimer(TIMEEVENT_PARMS);

// Details panel
class Bluetooth_Details_Panel : public Kis_Panel {
public:
	Bluetooth_Details_Panel() {
		fprintf(stderr, "FATAL OOPS: Bluetooth_Details_Panel()\n");
		exit(1);
	}

	Bluetooth_Details_Panel(GlobalRegistry *in_globalreg, KisPanelInterface *in_kpf);
	virtual ~Bluetooth_Details_Panel();

	virtual void DrawPanel();
	virtual void ButtonAction(Kis_Panel_Component *in_button);
	virtual void MenuAction(int opt);

	void SetBluetooth(bluetooth_data *in_bt) { bluetooth = in_bt; }
	void SetDetailsNet(bluetooth_network *in_net) { btnet = in_net; }

protected:
	bluetooth_data *bluetooth;
	bluetooth_network *btnet;

	Kis_Panel_Packbox *vbox;
	Kis_Free_Text *btdetailt;

	Kis_Button *closebutton;
};

extern "C" {

int panel_plugin_init(GlobalRegistry *globalreg, KisPanelPluginData *pdata) {
	_MSG("Loading Kismet Bluetooth plugin", MSGFLAG_INFO);

	bluetooth_data *bluetooth = new bluetooth_data;

	pdata->pluginaux = (void *) bluetooth;

	bluetooth->pdata = pdata;

	bluetooth->sort_type = bluetooth_sort_bdaddr;

	bluetooth->asm_bluetoothdev_num = 
		TokenNullJoin(&(bluetooth->asm_bluetoothdev_fields), bluetoothdev_fields);

	bluetooth->mi_plugin_bluetooth =
		pdata->mainpanel->AddPluginMenuItem("Bluetooth", Bluetooth_plugin_menu_cb, pdata);

	bluetooth->btdevlist = new Kis_Scrollable_Table(globalreg, pdata->mainpanel);

	vector<Kis_Scrollable_Table::title_data> titles;
	Kis_Scrollable_Table::title_data t;

	t.width = 17;
	t.title = "BD_ADDR";
	t.alignment = 0;
	titles.push_back(t);

	t.width = 5;
	t.title = "Count";
	t.alignment = 2;
	titles.push_back(t);

	bluetooth->btdevlist->AddTitles(titles);
	bluetooth->btdevlist->SetPreferredSize(0, 10);

	bluetooth->btdevlist->SetHighlightSelected(1);
	bluetooth->btdevlist->SetLockScrollTop(1);
	bluetooth->btdevlist->SetDrawTitles(1);

	bluetooth->btdevlist->SetCallback(COMPONENT_CBTYPE_ACTIVATED, BluetoothDevlistCB, bluetooth);

	pdata->mainpanel->AddComponentVec(bluetooth->btdevlist, 
									  (KIS_PANEL_COMP_DRAW | KIS_PANEL_COMP_EVT |
									   KIS_PANEL_COMP_TAB));
	pdata->mainpanel->FetchNetBox()->Pack_After_Named("KIS_MAIN_NETLIST",
													  bluetooth->btdevlist, 1, 0);

	bluetooth->menu = pdata->kpinterface->FetchMainPanel()->FetchMenu();
	int mn_view = bluetooth->menu->FindMenu("View");

	pdata->kpinterface->FetchMainPanel()->AddViewSeparator();
	bluetooth->mi_showbluetooth = bluetooth->menu->AddMenuItem("Bluetooth", mn_view, 0);
	bluetooth->menu->SetMenuItemCallback(bluetooth->mi_showbluetooth, Bluetooth_show_menu_cb, 
									  bluetooth);

	pdata->kpinterface->FetchMainPanel()->AddSortSeparator();
	int mn_sort = bluetooth->menu->FindMenu("Sort");
	bluetooth->mn_sub_sort = bluetooth->menu->AddSubMenuItem("Bluetooth", mn_sort, 0);
	bluetooth->mi_sort_bdaddr = 
		bluetooth->menu->AddMenuItem("BD_ADDR", bluetooth->mn_sub_sort, 0);
	bluetooth->mi_sort_firsttime = 
		bluetooth->menu->AddMenuItem("First Time", bluetooth->mn_sub_sort, 0);
	bluetooth->mi_sort_lasttime = 
		bluetooth->menu->AddMenuItem("Last Time", bluetooth->mn_sub_sort, 0);
	bluetooth->mi_sort_packets = 
		bluetooth->menu->AddMenuItem("Times Seen", bluetooth->mn_sub_sort, 0);

	bluetooth->menu->SetMenuItemCallback(bluetooth->mi_sort_bdaddr, Bluetooth_sort_menu_cb, 
									  bluetooth);
	bluetooth->menu->SetMenuItemCallback(bluetooth->mi_sort_firsttime, Bluetooth_sort_menu_cb, 
									  bluetooth);
	bluetooth->menu->SetMenuItemCallback(bluetooth->mi_sort_lasttime, Bluetooth_sort_menu_cb, 
									  bluetooth);
	bluetooth->menu->SetMenuItemCallback(bluetooth->mi_sort_packets, Bluetooth_sort_menu_cb, 
									  bluetooth);

	string opt = StrLower(pdata->kpinterface->prefs->FetchOpt("PLUGIN_BLUETOOTH_SHOW"));
	if (opt == "true" || opt == "") {
		bluetooth->btdevlist->Show();
		bluetooth->menu->SetMenuItemChecked(bluetooth->mi_showbluetooth, 1);

		bluetooth->menu->EnableMenuItem(bluetooth->mi_sort_bdaddr);
		bluetooth->menu->EnableMenuItem(bluetooth->mi_sort_firsttime);
		bluetooth->menu->EnableMenuItem(bluetooth->mi_sort_lasttime);
		bluetooth->menu->EnableMenuItem(bluetooth->mi_sort_packets);

	} else {
		bluetooth->btdevlist->Hide();
		bluetooth->menu->SetMenuItemChecked(bluetooth->mi_showbluetooth, 0);

		bluetooth->menu->DisableMenuItem(bluetooth->mi_sort_bdaddr);
		bluetooth->menu->DisableMenuItem(bluetooth->mi_sort_firsttime);
		bluetooth->menu->DisableMenuItem(bluetooth->mi_sort_lasttime);
		bluetooth->menu->DisableMenuItem(bluetooth->mi_sort_packets);
	}

	opt = pdata->kpinterface->prefs->FetchOpt("PLUGIN_BLUETOOTH_SORT");
	if (opt == "bdaddr") {
		bluetooth->menu->SetMenuItemChecked(bluetooth->mi_sort_bdaddr, 1);
		bluetooth->sort_type = bluetooth_sort_bdaddr;
	} else if (opt == "firsttime") {
		bluetooth->menu->SetMenuItemChecked(bluetooth->mi_sort_firsttime, 1);
		bluetooth->sort_type = bluetooth_sort_firsttime;
	} else if (opt == "lasttime") {
		bluetooth->menu->SetMenuItemChecked(bluetooth->mi_sort_lasttime, 1);
		bluetooth->sort_type = bluetooth_sort_lasttime;
	} else if (opt == "packets") {
		bluetooth->menu->SetMenuItemChecked(bluetooth->mi_sort_packets, 1);
		bluetooth->sort_type = bluetooth_sort_packets;
	} else {
		bluetooth->menu->SetMenuItemChecked(bluetooth->mi_sort_bdaddr, 1);
		bluetooth->sort_type = bluetooth_sort_bdaddr;
	}

	// Register the timer event for populating the array
	bluetooth->timerid = 
		globalreg->timetracker->RegisterTimer(SERVER_TIMESLICES_SEC, NULL,
											  1, &BluetoothTimer, bluetooth);

	// Do this LAST.  The configure event is responsible for clearing out the
	// list on reconnect, but MAY be called immediately upon being registered
	// if the client is already valid.  We have to have made all the other
	// bits first before it's valid to call this
	bluetooth->cliaddref =
		pdata->kpinterface->Add_NetCli_AddCli_CB(BluetoothCliAdd, (void *) bluetooth);

	return 1;
}

// Plugin version control
void kis_revision_info(panel_plugin_revision *prev) {
	if (prev->version_api_revision >= 1) {
		prev->version_api_revision = 1;
		prev->major = string(VERSION_MAJOR);
		prev->minor = string(VERSION_MINOR);
		prev->tiny = string(VERSION_TINY);
	}
}

}

int Bluetooth_plugin_menu_cb(void *auxptr) {
	KisPanelPluginData *pdata = (KisPanelPluginData *) auxptr;

	pdata->kpinterface->RaiseAlert("Bluetooth",
			"Bluetooth UI " + string(VERSION_MAJOR) + "-" + string(VERSION_MINOR) + "-" +
				string(VERSION_TINY) + "\n"
			"\n"
			"Display Bluetooth/802.15.1 devices found by the\n"
			"Kismet Bluetooth (gr-bluetooth) plugin\n");
	return 1;
}

void Bluetooth_show_menu_cb(MENUITEM_CB_PARMS) {
	bluetooth_data *bluetooth = (bluetooth_data *) auxptr;

	if (bluetooth->pdata->kpinterface->prefs->FetchOpt("PLUGIN_BLUETOOTH_SHOW") == "true" ||
		bluetooth->pdata->kpinterface->prefs->FetchOpt("PLUGIN_BLUETOOTH_SHOW") == "") {

		bluetooth->pdata->kpinterface->prefs->SetOpt("PLUGIN_BLUETOOTH_SHOW", "false", 1);

		bluetooth->btdevlist->Hide();

		bluetooth->menu->DisableMenuItem(bluetooth->mi_sort_bdaddr);
		bluetooth->menu->DisableMenuItem(bluetooth->mi_sort_firsttime);
		bluetooth->menu->DisableMenuItem(bluetooth->mi_sort_lasttime);
		bluetooth->menu->DisableMenuItem(bluetooth->mi_sort_packets);

		bluetooth->menu->SetMenuItemChecked(bluetooth->mi_showbluetooth, 0);
	} else {
		bluetooth->pdata->kpinterface->prefs->SetOpt("PLUGIN_BLUETOOTH_SHOW", "true", 1);

		bluetooth->btdevlist->Show();

		bluetooth->menu->EnableMenuItem(bluetooth->mi_sort_bdaddr);
		bluetooth->menu->EnableMenuItem(bluetooth->mi_sort_firsttime);
		bluetooth->menu->EnableMenuItem(bluetooth->mi_sort_lasttime);
		bluetooth->menu->EnableMenuItem(bluetooth->mi_sort_packets);

		bluetooth->menu->SetMenuItemChecked(bluetooth->mi_showbluetooth, 1);
	}

	return;
}

void Bluetooth_sort_menu_cb(MENUITEM_CB_PARMS) {
	bluetooth_data *bluetooth = (bluetooth_data *) auxptr;

	bluetooth->menu->SetMenuItemChecked(bluetooth->mi_sort_bdaddr, 0);
	bluetooth->menu->SetMenuItemChecked(bluetooth->mi_sort_firsttime, 0);
	bluetooth->menu->SetMenuItemChecked(bluetooth->mi_sort_lasttime, 0);
	bluetooth->menu->SetMenuItemChecked(bluetooth->mi_sort_packets, 0);

	if (menuitem == bluetooth->mi_sort_bdaddr) {
		bluetooth->menu->SetMenuItemChecked(bluetooth->mi_sort_bdaddr, 1);
		bluetooth->pdata->kpinterface->prefs->SetOpt("PLUGIN_BLUETOOTH_SORT", "bdaddr", 
												  globalreg->timestamp.tv_sec);
		bluetooth->sort_type = bluetooth_sort_bdaddr;
	} else if (menuitem == bluetooth->mi_sort_firsttime) {
		bluetooth->menu->SetMenuItemChecked(bluetooth->mi_sort_firsttime, 1);
		bluetooth->pdata->kpinterface->prefs->SetOpt("PLUGIN_BLUETOOTH_SORT", "firsttime", 
												  globalreg->timestamp.tv_sec);
		bluetooth->sort_type = bluetooth_sort_firsttime;
	} else if (menuitem == bluetooth->mi_sort_lasttime) {
		bluetooth->menu->SetMenuItemChecked(bluetooth->mi_sort_lasttime, 1);
		bluetooth->pdata->kpinterface->prefs->SetOpt("PLUGIN_BLUETOOTH_SORT", "lasttime", 
												  globalreg->timestamp.tv_sec);
		bluetooth->sort_type = bluetooth_sort_lasttime;
	} else if (menuitem == bluetooth->mi_sort_packets) {
		bluetooth->menu->SetMenuItemChecked(bluetooth->mi_sort_packets, 1);
		bluetooth->pdata->kpinterface->prefs->SetOpt("PLUGIN_BLUETOOTH_SORT", "packets", 
												  globalreg->timestamp.tv_sec);
		bluetooth->sort_type = bluetooth_sort_packets;
	}
}

void BluetoothProtoBTBBDEV(CLIPROTO_CB_PARMS) {
	bluetooth_data *bluetooth = (bluetooth_data *) auxptr;

	if (proto_parsed->size() < bluetooth->asm_bluetoothdev_num) {
		_MSG("Invalid BTBBDEV sentence from server", MSGFLAG_INFO);
		return;
	}

	int fnum = 0;

	bluetooth_network *btn = NULL;

	mac_addr ma;

	ma = mac_addr((*proto_parsed)[fnum++].word);

	if (ma.error) {
		return;
	}

	map<mac_addr, bluetooth_network *>::iterator bti;
	string tstr;
	unsigned int tuint;
	float tfloat;
	unsigned long tulong;

	if ((bti = bluetooth->btdev_map.find(ma)) == bluetooth->btdev_map.end()) {
		btn = new bluetooth_network;
		btn->bd_addr = ma;

		bluetooth->btdev_map[ma] = btn;

		bluetooth->btdev_vec.push_back(btn);
	} else {
		btn = bti->second;
	}

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%u", &tuint) != 1) {
		return;
	}
	btn->first_time = tuint;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%u", &tuint) != 1) {
		return;
	}
	btn->last_time = tuint;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%u", &tuint) != 1) {
		return;
	}
	btn->num_packets = tuint;

	// Only apply fixed value if we weren't before, never degrade
	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%u", &tuint) != 1) {
		return;
	}
	if (btn->gpsdata.gps_valid == 0)
		btn->gpsdata.gps_valid = tuint;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%f", &tfloat) != 1) 
		return;
	btn->gpsdata.min_lat = tfloat;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%f", &tfloat) != 1) 
		return;
	btn->gpsdata.min_lon = tfloat;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%f", &tfloat) != 1) 
		return;
	btn->gpsdata.min_alt = tfloat;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%f", &tfloat) != 1) 
		return;
	btn->gpsdata.min_spd = tfloat;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%f", &tfloat) != 1) 
		return;
	btn->gpsdata.max_lat = tfloat;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%f", &tfloat) != 1) 
		return;
	btn->gpsdata.max_lon = tfloat;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%f", &tfloat) != 1) 
		return;
	btn->gpsdata.max_alt = tfloat;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%f", &tfloat) != 1) 
		return;
	btn->gpsdata.max_spd = tfloat;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%f", &tfloat) != 1) 
		return;
	btn->gpsdata.aggregate_lat = tfloat;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%f", &tfloat) != 1) 
		return;
	btn->gpsdata.aggregate_lon = tfloat;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%f", &tfloat) != 1) 
		return;
	btn->gpsdata.aggregate_alt = tfloat;

	if (sscanf((*proto_parsed)[fnum++].word.c_str(), "%lu", &tulong) != 1) 
		return;
	btn->gpsdata.aggregate_points = tulong;
}

void BluetoothCliConfigured(CLICONF_CB_PARMS) {
	bluetooth_data *bluetooth = (bluetooth_data *) auxptr;

	// Wipe the scanlist
	bluetooth->btdevlist->Clear();

	if (kcli->RegisterProtoHandler("BTBBDEV", bluetooth->asm_bluetoothdev_fields,
								   BluetoothProtoBTBBDEV, auxptr) < 0) {
		_MSG("Could not register BTBBDEV protocol with remote server", MSGFLAG_ERROR);

		globalreg->panel_interface->RaiseAlert("No Bluetooth protocol",
				"The Bluetooth UI was unable to register the required\n"
				"BTBBDEV protocol.  Either it is unavailable\n"
				"(you didn't load the Bluetooth server plugin) or you\n"
				"are using an older server plugin.\n");
		return;
	}
}

void BluetoothCliAdd(KPI_ADDCLI_CB_PARMS) {
	if (add == 0)
		return;

	netcli->AddConfCallback(BluetoothCliConfigured, 1, auxptr);
}

int BluetoothTimer(TIMEEVENT_PARMS) {
	bluetooth_data *bluetooth = (bluetooth_data *) parm;

	// This isn't efficient at all.. but pull the current line, re-sort the 
	// data vector, clear the display, recreate the strings in the table, 
	// re-insert them, and reset the position to the stored one

	vector<string> current_row = bluetooth->btdevlist->GetSelectedData();

	mac_addr current_bdaddr;

	if (current_row.size() >= 1) 
		current_bdaddr = mac_addr(current_row[0]);

	vector<string> add_row;

	switch (bluetooth->sort_type) {
		case bluetooth_sort_bdaddr:
			stable_sort(bluetooth->btdev_vec.begin(), bluetooth->btdev_vec.end(),
						Bluetooth_Sort_Bdaddr());
			break;
		case bluetooth_sort_firsttime:
			stable_sort(bluetooth->btdev_vec.begin(), bluetooth->btdev_vec.end(),
						Bluetooth_Sort_Firsttime());
			break;
		case bluetooth_sort_lasttime:
			stable_sort(bluetooth->btdev_vec.begin(), bluetooth->btdev_vec.end(),
						Bluetooth_Sort_Lasttime());
			break;
		case bluetooth_sort_packets:
			stable_sort(bluetooth->btdev_vec.begin(), bluetooth->btdev_vec.end(),
						Bluetooth_Sort_Packets());
			break;
		default:
			break;
	}

	bluetooth->btdevlist->Clear();

	for (unsigned int x = 0; x < bluetooth->btdev_vec.size(); x++) {
		add_row.clear();

		add_row.push_back(bluetooth->btdev_vec[x]->bd_addr.Mac2String());
		add_row.push_back(IntToString(bluetooth->btdev_vec[x]->num_packets));

		bluetooth->btdevlist->AddRow(x, add_row);

		if (bluetooth->btdev_vec[x]->bd_addr == current_bdaddr)
			bluetooth->btdevlist->SetSelected(x);
	}

	return 1;
}

int BluetoothDevlistCB(COMPONENT_CALLBACK_PARMS) {
	bluetooth_data *bluetooth = (bluetooth_data *) aux;
	int selected = 0;

	if (bluetooth->btdev_map.size() == 0) {
		globalreg->panel_interface->RaiseAlert("No Bluetooth devices",
			"No bluetooth devices, can only show details\n"
			"once a device has been found.\n");
		return 1;
	}

	if ((selected = bluetooth->btdevlist->GetSelected()) < 0 ||
			   selected > bluetooth->btdev_vec.size()) {
		globalreg->panel_interface->RaiseAlert("No Bluetooth device selected",
			"No Bluetooth device selected in the Bluetooth list, can\n"
			"only show details once a device has been selected.\n");
		return 1;
	}

	Bluetooth_Details_Panel *dp = 
		new Bluetooth_Details_Panel(globalreg, globalreg->panel_interface);
	dp->SetBluetooth(bluetooth);
	dp->SetDetailsNet(bluetooth->btdev_vec[selected]);
	globalreg->panel_interface->AddPanel(dp);

	return 1;
}

int Bluetooth_Details_ButtonCB(COMPONENT_CALLBACK_PARMS) {
	((Bluetooth_Details_Panel *) aux)->ButtonAction(component);
}

Bluetooth_Details_Panel::Bluetooth_Details_Panel(GlobalRegistry *in_globalreg,
										   KisPanelInterface *in_intf) :
	Kis_Panel(in_globalreg, in_intf) {

	SetTitle("Bluetooth Details");

	btdetailt = new Kis_Free_Text(globalreg, this);
	AddComponentVec(btdetailt, (KIS_PANEL_COMP_DRAW | KIS_PANEL_COMP_EVT |
								KIS_PANEL_COMP_TAB));
	btdetailt->Show();

	closebutton = new Kis_Button(globalreg, this);
	closebutton->SetText("Close");
	closebutton->SetCallback(COMPONENT_CBTYPE_ACTIVATED, Bluetooth_Details_ButtonCB, this);
	AddComponentVec(closebutton, (KIS_PANEL_COMP_DRAW | KIS_PANEL_COMP_EVT |
								  KIS_PANEL_COMP_TAB));
	closebutton->Show();

	vbox = new Kis_Panel_Packbox(globalreg, this);
	vbox->SetPackV();
	vbox->SetHomogenous(0);
	vbox->SetSpacing(0);

	vbox->Pack_End(btdetailt, 1, 0);
	vbox->Pack_End(closebutton, 0, 0);
	AddComponentVec(vbox, KIS_PANEL_COMP_DRAW);

	vbox->Show();

	SetActiveComponent(btdetailt);

	main_component = vbox;

	Position(WIN_CENTER(LINES, COLS));
}

Bluetooth_Details_Panel::~Bluetooth_Details_Panel() {

}

void Bluetooth_Details_Panel::DrawPanel() {
	vector<string> td;

	int selected;

	if (bluetooth == NULL) {
		td.push_back("Bluetooth details panel draw event happened before bluetooth");
		td.push_back("known, something is busted internally, report this");
	} else if (btnet == NULL) {
		td.push_back("No Bluetooth piconet selected");
	} else {
		td.push_back(AlignString("BD_ADDR: ", ' ', 2, 16) + btnet->bd_addr.Mac2String());
		td.push_back(AlignString("Count: ", ' ', 2, 16) + IntToString(btnet->num_packets));
		td.push_back(AlignString("First Seen: ", ' ', 2, 16) +
					string(ctime((const time_t *) 
								 &(btnet->first_time)) + 4).substr(0, 15));
		td.push_back(AlignString("Last Seen: ", ' ', 2, 16) +
					string(ctime((const time_t *) 
								 &(btnet->last_time)) + 4).substr(0, 15));
	}

	btdetailt->SetText(td);

	Kis_Panel::DrawPanel();
}

void Bluetooth_Details_Panel::ButtonAction(Kis_Panel_Component *in_button) {
	if (in_button == closebutton) {
		globalreg->panel_interface->KillPanel(this);
	}
}

void Bluetooth_Details_Panel::MenuAction(int opt) {

}

