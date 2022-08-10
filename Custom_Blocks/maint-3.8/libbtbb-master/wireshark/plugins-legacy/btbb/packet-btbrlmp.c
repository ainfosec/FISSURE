/* packet-btbrlmp.c
 * Routines for Bluetooth LMP dissection
 * Copyright 2009, Michael Ossmann <mike@ossmann.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#else
#include <wireshark/config.h>
#endif

#include <wireshark/config.h> /* needed for epan/gcc-4.x */
#include <epan/packet.h>
#include <epan/prefs.h>

/* LMP opcodes */
#define LMP_NAME_REQ                     1
#define LMP_NAME_RES                     2
#define LMP_ACCEPTED                     3
#define LMP_NOT_ACCEPTED                 4
#define LMP_CLKOFFSET_REQ                5
#define LMP_CLKOFFSET_RES                6
#define LMP_DETACH                       7
#define LMP_IN_RAND                      8
#define LMP_COMB_KEY                     9
#define LMP_UNIT_KEY                     10
#define LMP_AU_RAND                      11
#define LMP_SRES                         12
#define LMP_TEMP_RAND                    13
#define LMP_TEMP_KEY                     14
#define LMP_ENCRYPTION_MODE_REQ          15
#define LMP_ENCRYPTION_KEY_SIZE_REQ      16
#define LMP_START_ENCRYPTION_REQ         17
#define LMP_STOP_ENCRYPTION_REQ          18
#define LMP_SWITCH_REQ                   19
#define LMP_HOLD                         20
#define LMP_HOLD_REQ                     21
#define LMP_SNIFF_REQ                    23
#define LMP_UNSNIFF_REQ                  24
#define LMP_PARK_REQ                     25
#define LMP_SET_BROADCAST_SCAN_WINDOW    27
#define LMP_MODIFY_BEACON                28
#define LMP_UNPARK_BD_ADDR_REQ           29
#define LMP_UNPARK_PM_ADDR_REQ           30
#define LMP_INCR_POWER_REQ               31
#define LMP_DECR_POWER_REQ               32
#define LMP_MAX_POWER                    33
#define LMP_MIN_POWER                    34
#define LMP_AUTO_RATE                    35
#define LMP_PREFERRED_RATE               36
#define LMP_VERSION_REQ                  37
#define LMP_VERSION_RES                  38
#define LMP_FEATURES_REQ                 39
#define LMP_FEATURES_RES                 40
#define LMP_QUALITY_OF_SERVICE           41
#define LMP_QUALITY_OF_SERVICE_REQ       42
#define LMP_SCO_LINK_REQ                 43
#define LMP_REMOVE_SCO_LINK_REQ          44
#define LMP_MAX_SLOT                     45
#define LMP_MAX_SLOT_REQ                 46
#define LMP_TIMING_ACCURACY_REQ          47
#define LMP_TIMING_ACCURACY_RES          48
#define LMP_SETUP_COMPLETE               49
#define LMP_USE_SEMI_PERMANENT_KEY       50
#define LMP_HOST_CONNECTION_REQ          51
#define LMP_SLOT_OFFSET                  52
#define LMP_PAGE_MODE_REQ                53
#define LMP_PAGE_SCAN_MODE_REQ           54
#define LMP_SUPERVISION_TIMEOUT          55
#define LMP_TEST_ACTIVATE                56
#define LMP_TEST_CONTROL                 57
#define LMP_ENCRYPTION_KEY_SIZE_MASK_REQ 58
#define LMP_ENCRYPTION_KEY_SIZE_MASK_RES 59
#define LMP_SET_AFH                      60
#define LMP_ENCAPSULATED_HEADER          61
#define LMP_ENCAPSULATED_PAYLOAD         62
#define LMP_SIMPLE_PAIRING_CONFIRM       63
#define LMP_SIMPLE_PAIRING_NUMBER        64
#define LMP_DHKEY_CHECK                  65
#define LMP_ESCAPE_1                     124
#define LMP_ESCAPE_2                     125
#define LMP_ESCAPE_3                     126
#define LMP_ESCAPE_4                     127

/* LMP extended opcodes */
#define LMP_ACCEPTED_EXT               1
#define LMP_NOT_ACCEPTED_EXT           2
#define LMP_FEATURES_REQ_EXT           3
#define LMP_FEATURES_RES_EXT           4
#define LMP_PACKET_TYPE_TABLE_REQ      11
#define LMP_ESCO_LINK_REQ              12
#define LMP_REMOVE_ESCO_LINK_REQ       13
#define LMP_CHANNEL_CLASSIFICATION_REQ 16
#define LMP_CHANNEL_CLASSIFICATION     17
#define LMP_SNIFF_SUBRATING_REQ        21
#define LMP_SNIFF_SUBRATING_RES        22
#define LMP_PAUSE_ENCRYPTION_REQ       23
#define LMP_RESUME_ENCRYPTION_REQ      24
#define LMP_IO_CAPABILITY_REQ          25
#define LMP_IO_CAPABILITY_RES          26
#define LMP_NUMERIC_COMPARISON_FAILED  27
#define LMP_PASSKEY_FAILED             28
#define LMP_OOB_FAILED                 29
#define LMP_KEYPRESS_NOTIFICATION      30
#define LMP_POWER_CONTROL_REQ          31
#define LMP_POWER_CONTROL_RES          32

/* initialize the protocol and registered fields */
static int proto_btbrlmp = -1;
static int hf_lmp_accscheme = -1;
static int hf_lmp_afhchmap = -1;
static int hf_lmp_afhclass = -1;
static int hf_lmp_afhinst = -1;
static int hf_lmp_afhmaxintvl = -1;
static int hf_lmp_afhminintvl = -1;
static int hf_lmp_afhmode = -1;
static int hf_lmp_afhrptmode = -1;
static int hf_lmp_airmode = -1;
static int hf_lmp_araddr = -1;
static int hf_lmp_authreqs = -1;
static int hf_lmp_authres = -1;
static int hf_lmp_bdaddr = -1;
static int hf_lmp_bdaddr1 = -1;
static int hf_lmp_bdaddr2 = -1;
static int hf_lmp_bsw = -1;
static int hf_lmp_clkoffset = -1;
static int hf_lmp_commit = -1;
static int hf_lmp_confirm = -1;
static int hf_lmp_compid = -1;
static int hf_lmp_cryptmode = -1;
static int hf_lmp_daccess = -1;
static int hf_lmp_db = -1;
static int hf_lmp_dbsleep = -1;
static int hf_lmp_deltab = -1;
static int hf_lmp_desco = -1;
static int hf_lmp_drift = -1;
static int hf_lmp_dsco = -1;
static int hf_lmp_dsniff = -1;
static int hf_lmp_encdata = -1;
static int hf_lmp_enclen = -1;
static int hf_lmp_encmaj = -1;
static int hf_lmp_encmin = -1;
static int hf_lmp_eop = -1;
static int hf_lmp_eopinre = -1;
static int hf_lmp_escolenms = -1;
static int hf_lmp_escolensm = -1;
static int hf_lmp_escotypems = -1;
static int hf_lmp_escotypesm = -1;
static int hf_lmp_err = -1;
static int hf_lmp_escohdl = -1;
static int hf_lmp_escoltaddr = -1;
static int hf_lmp_features = -1;
static int hf_lmp_fpage = -1;
static int hf_lmp_htime = -1;
static int hf_lmp_hinst = -1;
static int hf_lmp_hopmode = -1;
static int hf_lmp_iocaps = -1;
static int hf_lmp_jitter = -1;
static int hf_lmp_key = -1;
static int hf_lmp_keysz = -1;
static int hf_lmp_ksmask = -1;
static int hf_lmp_ltaddr1 = -1;
static int hf_lmp_ltaddr2 = -1;
static int hf_lmp_ltaddr3 = -1;
static int hf_lmp_ltaddr4 = -1;
static int hf_lmp_ltaddr5 = -1;
static int hf_lmp_ltaddr6 = -1;
static int hf_lmp_ltaddr7 = -1;
static int hf_lmp_maccess = -1;
static int hf_lmp_maxslots = -1;
static int hf_lmp_maxsp = -1;
static int hf_lmp_maxss = -1;
static int hf_lmp_minsmt = -1;
static int hf_lmp_naccslots = -1;
static int hf_lmp_namefrag = -1;
static int hf_lmp_namelen = -1;
static int hf_lmp_nameoffset = -1;
static int hf_lmp_nb = -1;
static int hf_lmp_nbc = -1;
static int hf_lmp_nbsleep = -1;
static int hf_lmp_negstate = -1;
static int hf_lmp_nonce = -1;
static int hf_lmp_nottype = -1;
static int hf_lmp_npoll = -1;
static int hf_lmp_oobauthdata = -1;
static int hf_lmp_op = -1;
static int hf_lmp_opinre = -1;
static int hf_lmp_pagesch = -1;
static int hf_lmp_pcmode = -1;
static int hf_lmp_pkttype = -1;
static int hf_lmp_pkttypetbl = -1;
static int hf_lmp_pmaddr = -1;
static int hf_lmp_pmaddr1 = -1;
static int hf_lmp_pmaddr2 = -1;
static int hf_lmp_pmaddr3 = -1;
static int hf_lmp_pmaddr4 = -1;
static int hf_lmp_pmaddr5 = -1;
static int hf_lmp_pmaddr6 = -1;
static int hf_lmp_pmaddr7 = -1;
static int hf_lmp_pollintvl = -1;
static int hf_lmp_pollper = -1;
static int hf_lmp_pssettings = -1;
static int hf_lmp_pwradjreq = -1;
static int hf_lmp_pwradjres = -1;
static int hf_lmp_pwradj_8dpsk = -1;
static int hf_lmp_pwradj_dqpsk = -1;
static int hf_lmp_pwradj_gfsk = -1;
static int hf_lmp_rand = -1;
static int hf_lmp_rate = -1;
static int hf_lmp_rate_fec = -1;
static int hf_lmp_rate_size = -1;
static int hf_lmp_rate_type = -1;
static int hf_lmp_rate_edrsize = -1;
static int hf_lmp_rxfreq = -1;
static int hf_lmp_scohdl = -1;
static int hf_lmp_scopkt = -1;
static int hf_lmp_slotoffset = -1;
static int hf_lmp_sniffatt = -1;
static int hf_lmp_sniffsi = -1;
static int hf_lmp_sniffto = -1;
static int hf_lmp_subversnr = -1;
static int hf_lmp_suptimeout = -1;
static int hf_lmp_swinst = -1;
static int hf_lmp_taccess = -1;
static int hf_lmp_tb = -1;
static int hf_lmp_tesco = -1;
static int hf_lmp_testlen = -1;
static int hf_lmp_testscen = -1;
static int hf_lmp_tid = -1;
static int hf_lmp_timectrl = -1;
static int hf_lmp_time_change = -1;
static int hf_lmp_time_init = -1;
static int hf_lmp_time_accwin = -1;
static int hf_lmp_tsco = -1;
static int hf_lmp_tsniff = -1;
static int hf_lmp_txfreq = -1;
static int hf_lmp_versnr = -1;
static int hf_lmp_wesco = -1;

/* timing control flags */
static const int *timectrl_fields[] = {
	&hf_lmp_time_change,
	&hf_lmp_time_init,
	&hf_lmp_time_accwin,
	/* bits 3-7 reserved */
	NULL
};

static const true_false_string time_change = {
	"timing change",
	"no timing change"
};

static const true_false_string time_init = {
	"use initialization 2",
	"use initialization 1"
};

static const true_false_string time_accwin = {
	"no access window",
	"access window"
};

static const true_false_string fec = {
	"do not use FEC",
	"use FEC"
};

static const true_false_string tid = {
	"transaction initiated by slave",
	"transaction initiated by master"
};

/* short LMP opcodes */
static const value_string opcode[] = {
	{ LMP_NAME_REQ, "LMP_name_req" },
	{ LMP_NAME_RES, "LMP_name_res" },
	{ LMP_ACCEPTED, "LMP_accepted" },
	{ LMP_NOT_ACCEPTED, "LMP_not_accepted" },
	{ LMP_CLKOFFSET_REQ, "LMP_clkoffset_req" },
	{ LMP_CLKOFFSET_RES, "LMP_clkoffset_res" },
	{ LMP_DETACH, "LMP_detach" },
	{ LMP_IN_RAND, "LMP_in_rand" },
	{ LMP_COMB_KEY, "LMP_comb_key" },
	{ LMP_UNIT_KEY, "LMP_unit_key" },
	{ LMP_AU_RAND, "LMP_au_rand" },
	{ LMP_SRES, "LMP_sres" },
	{ LMP_TEMP_RAND, "LMP_temp_rand" },
	{ LMP_TEMP_KEY, "LMP_temp_key" },
	{ LMP_ENCRYPTION_MODE_REQ, "LMP_encryption_mode_req" },
	{ LMP_ENCRYPTION_KEY_SIZE_REQ, "LMP_encryption_key_size_req" },
	{ LMP_START_ENCRYPTION_REQ, "LMP_start_encryption_req" },
	{ LMP_STOP_ENCRYPTION_REQ, "LMP_stop_encryption_req" },
	{ LMP_SWITCH_REQ, "LMP_switch_req" },
	{ LMP_HOLD, "LMP_hold" },
	{ LMP_HOLD_REQ, "LMP_hold_req" },
	{ LMP_SNIFF_REQ, "LMP_sniff_req" },
	{ LMP_UNSNIFF_REQ, "LMP_unsniff_req" },
	{ LMP_PARK_REQ, "LMP_park_req" },
	{ LMP_SET_BROADCAST_SCAN_WINDOW, "LMP_set_broadcast_scan_window" },
	{ LMP_MODIFY_BEACON, "LMP_modify_beacon" },
	{ LMP_UNPARK_BD_ADDR_REQ, "LMP_unpark_BD_ADDR_req" },
	{ LMP_UNPARK_PM_ADDR_REQ, "LMP_unpark_PM_ADDR_req" },
	{ LMP_INCR_POWER_REQ, "LMP_incr_power_req" },
	{ LMP_DECR_POWER_REQ, "LMP_decr_power_req" },
	{ LMP_MAX_POWER, "LMP_max_power" },
	{ LMP_MIN_POWER, "LMP_min_power" },
	{ LMP_AUTO_RATE, "LMP_auto_rate" },
	{ LMP_PREFERRED_RATE, "LMP_preferred_rate" },
	{ LMP_VERSION_REQ, "LMP_version_req" },
	{ LMP_VERSION_RES, "LMP_version_res" },
	{ LMP_FEATURES_REQ, "LMP_features_req" },
	{ LMP_FEATURES_RES, "LMP_features_res" },
	{ LMP_QUALITY_OF_SERVICE, "LMP_quality_of_service" },
	{ LMP_QUALITY_OF_SERVICE_REQ, "LMP_quality_of_service_req" },
	{ LMP_SCO_LINK_REQ, "LMP_SCO_link_req" },
	{ LMP_REMOVE_SCO_LINK_REQ, "LMP_remove_SCO_link_req" },
	{ LMP_MAX_SLOT, "LMP_max_slot" },
	{ LMP_MAX_SLOT_REQ, "LMP_max_slot_req" },
	{ LMP_TIMING_ACCURACY_REQ, "LMP_timing_accuracy_req" },
	{ LMP_TIMING_ACCURACY_RES, "LMP_timing_accuracy_res" },
	{ LMP_SETUP_COMPLETE, "LMP_setup_complete" },
	{ LMP_USE_SEMI_PERMANENT_KEY, "LMP_use_semi_permanent_key" },
	{ LMP_HOST_CONNECTION_REQ, "LMP_host_connection_req" },
	{ LMP_SLOT_OFFSET, "LMP_slot_offset" },
	{ LMP_PAGE_MODE_REQ, "LMP_page_mode_req" },
	{ LMP_PAGE_SCAN_MODE_REQ, "LMP_page_scan_mode_req" },
	{ LMP_SUPERVISION_TIMEOUT, "LMP_supervision_timeout" },
	{ LMP_TEST_ACTIVATE, "LMP_test_activate" },
	{ LMP_TEST_CONTROL, "LMP_test_control" },
	{ LMP_ENCRYPTION_KEY_SIZE_MASK_REQ, "LMP_encryption_key_size_mask_req" },
	{ LMP_ENCRYPTION_KEY_SIZE_MASK_RES, "LMP_encryption_key_size_mask_res" },
	{ LMP_SET_AFH, "LMP_set_AFH" },
	{ LMP_ENCAPSULATED_HEADER, "LMP_encapsulated_header" },
	{ LMP_ENCAPSULATED_PAYLOAD, "LMP_encapsulated_payload" },
	{ LMP_SIMPLE_PAIRING_CONFIRM, "LMP_Simple_Pairing_Confirm" },
	{ LMP_SIMPLE_PAIRING_NUMBER, "LMP_Simple_Pairing_Number" },
	{ LMP_DHKEY_CHECK, "LMP_DHkey_Check" },
	{ LMP_ESCAPE_1, "Escape 1" },
	{ LMP_ESCAPE_2, "Escape 2" },
	{ LMP_ESCAPE_3, "Escape 3" },
	{ LMP_ESCAPE_4, "Escape 4" },
	{ 0, NULL }
};

/* extended LMP opcodes */
static const value_string ext_opcode[] = {
	{ LMP_ACCEPTED_EXT, "LMP_accepted_ext" },
	{ LMP_NOT_ACCEPTED_EXT, "LMP_not_accepted_ext" },
	{ LMP_FEATURES_REQ_EXT, "LMP_features_req_ext" },
	{ LMP_FEATURES_RES_EXT, "LMP_features_res_ext" },
	{ LMP_PACKET_TYPE_TABLE_REQ, "LMP_packet_type_table_req" },
	{ LMP_ESCO_LINK_REQ, "LMP_eSCO_link_req" },
	{ LMP_REMOVE_ESCO_LINK_REQ, "LMP_remove_eSCO_link_req" },
	{ LMP_CHANNEL_CLASSIFICATION_REQ, "LMP_channel_classification_req" },
	{ LMP_CHANNEL_CLASSIFICATION, "LMP_channel_classification" },
	{ LMP_SNIFF_SUBRATING_REQ, "LMP_sniff_subrating_req" },
	{ LMP_SNIFF_SUBRATING_RES, "LMP_sniff_subrating_res" },
	{ LMP_PAUSE_ENCRYPTION_REQ, "LMP_pause_encryption_req" },
	{ LMP_RESUME_ENCRYPTION_REQ, "LMP_resume_encryption_req" },
	{ LMP_IO_CAPABILITY_REQ, "LMP_IO_Capability_req" },
	{ LMP_IO_CAPABILITY_RES, "LMP_IO_Capability_res" },
	{ LMP_NUMERIC_COMPARISON_FAILED, "LMP_numeric_comparison_failed" },
	{ LMP_PASSKEY_FAILED, "LMP_passkey_failed" },
	{ LMP_OOB_FAILED, "LMP_oob_failed" },
	{ LMP_KEYPRESS_NOTIFICATION, "LMP_keypress_notification" },
	{ LMP_POWER_CONTROL_REQ, "LMP_power_control_req" },
	{ LMP_POWER_CONTROL_RES, "LMP_power_control_res" },
	{ 0, NULL }
};

/* LMP error codes */
static const value_string error_code[] = {
	{ 0x00, "Success" },
	{ 0x01, "Unknown HCI Command" },
	{ 0x02, "Unknown Connection Identifier" },
	{ 0x03, "Hardware Failure" },
	{ 0x04, "Page Timeout" },
	{ 0x05, "Authentication Failure" },
	{ 0x06, "PIN or Key Missing" },
	{ 0x07, "Memory Capacity Exceeded" },
	{ 0x08, "Connection Timeout" },
	{ 0x09, "Connection Limit Exceeded" },
	{ 0x0A, "Synchronous Connection Limit To A Device Exceeded" },
	{ 0x0B, "ACL Connection Already Exists" },
	{ 0x0C, "Command Disallowed" },
	{ 0x0D, "Connection Rejected due to Limited Resources" },
	{ 0x0E, "Connection Rejected Due To Security Reasons" },
	{ 0x0F, "Connection Rejected due to Unacceptable BD_ADDR" },
	{ 0x10, "Connection Accept Timeout Exceeded" },
	{ 0x11, "Unsupported Feature or Parameter Value" },
	{ 0x12, "Invalid HCI Command Parameters" },
	{ 0x13, "Remote User Terminated Connection" },
	{ 0x14, "Remote Device Terminated Connection due to Low Resources" },
	{ 0x15, "Remote Device Terminated Connection due to Power Off" },
	{ 0x16, "Connection Terminated By Local Host" },
	{ 0x17, "Repeated Attempts" },
	{ 0x18, "Pairing Not Allowed" },
	{ 0x19, "Unknown LMP PDU" },
	{ 0x1A, "Unsupported Remote Feature / Unsupported LMP Feature" },
	{ 0x1B, "SCO Offset Rejected" },
	{ 0x1C, "SCO Interval Rejected" },
	{ 0x1D, "SCO Air Mode Rejected" },
	{ 0x1E, "Invalid LMP Parameters" },
	{ 0x1F, "Unspecified Error" },
	{ 0x20, "Unsupported LMP Parameter Value" },
	{ 0x21, "Role Change Not Allowed" },
	{ 0x22, "LMP Response Timeout" },
	{ 0x23, "LMP Error Transaction Collision" },
	{ 0x24, "LMP PDU Not Allowed" },
	{ 0x25, "Encryption Mode Not Acceptable" },
	{ 0x26, "Link Key Can Not be Changed" },
	{ 0x27, "Requested QoS Not Supported" },
	{ 0x28, "Instant Passed" },
	{ 0x29, "Pairing With Unit Key Not Supported" },
	{ 0x2A, "Different Transaction Collision" },
	{ 0x2B, "Reserved" },
	{ 0x2C, "QoS Unacceptable Parameter" },
	{ 0x2D, "QoS Rejected" },
	{ 0x2E, "Channel Classification Not Supported" },
	{ 0x2F, "Insufficient Security" },
	{ 0x30, "Parameter Out Of Mandatory Range" },
	{ 0x31, "Reserved" },
	{ 0x32, "Role Switch Pending" },
	{ 0x33, "Reserved" },
	{ 0x34, "Reserved Slot Violation" },
	{ 0x35, "Role Switch Failed" },
	{ 0x36, "Extended Inquiry Response Too Large" },
	{ 0x37, "Secure Simple Pairing Not Supported By Host." },
	{ 0x38, "Host Busy - Pairing" },
	{ 0x39, "Connection Rejected due to No Suitable Channel Found" },
	{ 0, NULL }
};

static const value_string encryption_mode[] = {
	{ 0, "no encryption" },
	{ 1, "encryption" },
	{ 2, "encryption" },
	/* 3 - 255 reserved */
	{ 0, NULL }
};

static const value_string access_scheme[] = {
	{ 0, "polling technique" },
	/* 1 - 15 reserved */
	{ 0, NULL }
};

static const value_string packet_size[] = {
	{ 0, "no packet-size preference available" },
	{ 1, "use 1-slot packets" },
	{ 2, "use 3-slot packets" },
	{ 3, "use 5-slot packets" },
	{ 0, NULL }
};

static const value_string edr_type[] = {
	{ 0, "use DM1 packets" },
	{ 1, "use 2 Mbps packets" },
	{ 2, "use 3 Mbps packets" },
	/* 3 reserved */
	{ 0, NULL }
};

static const value_string versnr[] = {
	{ 0, "Bluetooth Core Specification 1.0b" },
	{ 1, "Bluetooth Core Specification 1.1" },
	{ 2, "Bluetooth Core Specification 1.2" },
	{ 3, "Bluetooth Core Specification 2.0 + EDR" },
	{ 4, "Bluetooth Core Specification 2.1 + EDR" },
	{ 5, "Bluetooth Core Specification 3.0 + HS" },
	/* 6 - 255 reserved */
	{ 0, NULL }
};

static const value_string compid[] = {
	{ 0, "Ericsson Technology Licensing" },
	{ 1, "Nokia Mobile Phones" },
	{ 2, "Intel Corp." },
	{ 3, "IBM Corp." },
	{ 4, "Toshiba Corp." },
	{ 5, "3Com" },
	{ 6, "Microsoft" },
	{ 7, "Lucent" },
	{ 8, "Motorola" },
	{ 9, "Infineon Technologies AG" },
	{ 10, "Cambridge Silicon Radio" },
	{ 11, "Silicon Wave" },
	{ 12, "Digianswer A/S" },
	{ 13, "Texas Instruments Inc." },
	{ 14, "Parthus Technologies Inc." },
	{ 15, "Broadcom Corporation" },
	{ 16, "Mitel Semiconductor" },
	{ 17, "Widcomm, Inc." },
	{ 18, "Zeevo, Inc." },
	{ 19, "Atmel Corporation" },
	{ 20, "Mitsubishi Electric Corporation" },
	{ 21, "RTX Telecom A/S" },
	{ 22, "KC Technology Inc." },
	{ 23, "Newlogic" },
	{ 24, "Transilica, Inc." },
	{ 25, "Rohde & Schwarz GmbH & Co. KG" },
	{ 26, "TTPCom Limited" },
	{ 27, "Signia Technologies, Inc." },
	{ 28, "Conexant Systems Inc." },
	{ 29, "Qualcomm" },
	{ 30, "Inventel" },
	{ 31, "AVM Berlin" },
	{ 32, "BandSpeed, Inc." },
	{ 33, "Mansella Ltd" },
	{ 34, "NEC Corporation" },
	{ 35, "WavePlus Technology Co., Ltd." },
	{ 36, "Alcatel" },
	{ 37, "Philips Semiconductors" },
	{ 38, "C Technologies" },
	{ 39, "Open Interface" },
	{ 40, "R F Micro Devices" },
	{ 41, "Hitachi Ltd" },
	{ 42, "Symbol Technologies, Inc." },
	{ 43, "Tenovis" },
	{ 44, "Macronix International Co. Ltd." },
	{ 45, "GCT Semiconductor" },
	{ 46, "Norwood Systems" },
	{ 47, "MewTel Technology Inc." },
	{ 48, "ST Microelectronics" },
	{ 49, "Synopsys" },
	{ 50, "Red-M (Communications) Ltd" },
	{ 51, "Commil Ltd" },
	{ 52, "Computer Access Technology Corporation (CATC)" },
	{ 53, "Eclipse (HQ Espana) S.L." },
	{ 54, "Renesas Technology Corp." },
	{ 55, "Mobilian Corporation" },
	{ 56, "Terax" },
	{ 57, "Integrated System Solution Corp." },
	{ 58, "Matsushita Electric Industrial Co., Ltd." },
	{ 59, "Gennum Corporation" },
	{ 60, "Research In Motion" },
	{ 61, "IPextreme, Inc." },
	{ 62, "Systems and Chips, Inc" },
	{ 63, "Bluetooth SIG, Inc" },
	{ 64, "Seiko Epson Corporation" },
	{ 65, "Integrated Silicon Solution Taiwan, Inc." },
	{ 66, "CONWISE Technology Corporation Ltd" },
	{ 67, "PARROT SA" },
	{ 68, "Socket Mobile" },
	{ 69, "Atheros Communications, Inc." },
	{ 70, "MediaTek, Inc." },
	{ 71, "Bluegiga (tentative)" },
	{ 72, "Marvell Technology Group Ltd." },
	{ 73, "3DSP Corporation" },
	{ 74, "Accel Semiconductor Ltd." },
	{ 75, "Continental Automotive Systems" },
	{ 76, "Apple, Inc." },
	{ 77, "Staccato Communications, Inc." },
	{ 78, "Avago Technologies" },
	{ 79, "APT Ltd." },
	{ 80, "SiRF Technology, Inc." },
	{ 81, "Tzero Technologies, Inc." },
	{ 82, "J&M Corporation" },
	{ 83, "Free2move AB" },
	/* 84 - 65534 reserved */
	{ 65535, "test" },
	{ 0, NULL }
};

static const value_string sco_packet[] = {
	{ 0, "HV1" },
	{ 1, "HV2" },
	{ 2, "HV3" },
	/* 3 - 255 reserved */
	{ 0, NULL }
};

static const value_string air_mode[] = {
	{ 0, "mu-law log" },
	{ 1, "A-law log" },
	{ 2, "CVSD" },
	{ 3, "transparent data" },
	/* 4 - 255 reserved */
	{ 0, NULL }
};

static const value_string paging_scheme[] = {
	{ 0, "mandatory scheme" },
	/* 1 - 255 reserved */
	{ 0, NULL }
};

static const value_string paging_scheme_settings[] = {
	/* for mandatory scheme: */
	{ 0, "R0" },
	{ 1, "R1" },
	{ 2, "R2" },
	/* 3 - 255 reserved */
	{ 0, NULL }
};

static const value_string afh_mode[] = {
	{ 0, "AFH disabled" },
	{ 1, "AFH enabled" },
	/* 2 - 255 reserved */
	{ 0, NULL }
};

static const value_string features_page[] = {
	{ 0, "standard features" },
	/* 1 - 255 other feature pages */
	{ 0, NULL }
};

static const value_string packet_type_table[] = {
	{ 0, "1 Mbps only" },
	{ 1, "2/3 Mbps" },
	/* 2 - 255 reserved */
	{ 0, NULL }
};

static const value_string negotiation_state[] = {
	{ 0, "Initiate negotiation" },
	{ 1, "The latest received set of negotiable parameters were possible but these parameters are preferred." },
	{ 2, "The latest received set of negotiable parameters would cause a reserved slot violation." },
	{ 3, "The latest received set of negotiable parameters would cause a latency violation." },
	{ 4, "The latest received set of negotiable parameters are not supported." },
	/* 5 - 255 reserved */
	{ 0, NULL }
};

static const value_string afh_reporting_mode[] = {
	{ 0, "AFH reporting disabled" },
	{ 1, "AFH reporting enabled" },
	/* 2 - 255 reserved */
	{ 0, NULL }
};

static const value_string io_capabilities[] = {
	{ 0, "Display Only" },
	{ 1, "Display Yes/No" },
	{ 2, "Keyboard Only" },
	{ 3, "No Input/No Output" },
	/* 4 - 255 reserved */
	{ 0, NULL }
};

static const value_string oob_auth_data[] = {
	{ 0, "No OOB Authentication Data received" },
	{ 1, "OOB Authentication Data received" },
	/* 2 - 255 reserved */
	{ 0, NULL }
};

static const value_string auth_requirements[] = {
	{ 0x00, "MITM Protection Not Required - No Bonding" },
	{ 0x01, "MITM Protection Required - No Bonding" },
	{ 0x02, "MITM Protection Not Required - Dedicated Bonding" },
	{ 0x03, "MITM Protection Required - Dedicated Bonding" },
	{ 0x04, "MITM Protection Not Required - General Bonding" },
	{ 0x05, "MITM Protection Required - General Bonding" },
	/* 0x06 - 0xff reserved */
	{ 0, NULL }
};

static const value_string power_adjust_req[] = {
	{ 0, "decrement power one step" },
	{ 1, "increment power one step" },
	{ 2, "increase to maximum power" },
	/* 3 - 255 reserved */
	{ 0, NULL }
};

static const value_string power_adjust_res[] = {
	{ 0, "not supported" },
	{ 1, "changed one step (not min or max)" },
	{ 2, "max power" },
	{ 3, "min power" },
	/* 4 - 255 reserved */
	{ 0, NULL }
};

static const value_string test_scenario[] = {
	{ 0, "Pause Test Mode" },
	{ 1, "Transmitter test - 0 pattern" },
	{ 2, "Transmitter test - 1 pattern" },
	{ 3, "Transmitter test - 1010 pattern" },
	{ 4, "Pseudorandom bit sequence" },
	{ 5, "Closed Loop Back - ACL packets" },
	{ 6, "Closed Loop Back - Synchronous packets" },
	{ 7, "ACL Packets without whitening" },
	{ 8, "Synchronous Packets without whitening" },
	{ 9, "Transmitter test - 1111 0000 pattern" },
	/* 10 - 254 reserved */
	{ 255, "Exit Test Mode" },
	{ 0, NULL }
};

static const value_string hopping_mode[] = {
	{ 0, "RX/TX on single frequency" },
	{ 1, "Normal hopping" },
	/* 2 - 255 reserved */
	{ 0, NULL }
};

static const value_string power_control_mode[] = {
	{ 0, "fixed TX output power" },
	{ 1, "adaptive power control" },
	/* 2 - 255 reserved */
	{ 0, NULL }
};

static const value_string esco_packet_type[] = {
	{ 0x00, "NULL/POLL" },
	{ 0x07, "EV3" },
	{ 0x0C, "EV4" },
	{ 0x0D, "EV5" },
	{ 0x26, "2-EV3" },
	{ 0x2C, "2-EV5" },
	{ 0x37, "3-EV3" },
	{ 0x3D, "3-EV5" },
	/* other values reserved */
	{ 0, NULL }
};

static const value_string notification_value[] = {
	{ 0, "passkey entry started" },
	{ 1, "passkey digit entered" },
	{ 2, "passkey digit erased" },
	{ 3, "passkey cleared" },
	{ 4, "passkey entry completed" },
	/* 5 - 255 reserved */
	{ 0, NULL }
};

/* initialize the subtree pointers */
static gint ett_lmp = -1;
static gint ett_lmp_pwradjres = -1;
static gint ett_lmp_rate = -1;
static gint ett_lmp_timectrl = -1;

/* LMP PDUs with short opcodes */

void
dissect_name_req(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 2);
	DISSECTOR_ASSERT(tvb_length_remaining(tvb, offset) >= 1);

	proto_tree_add_item(tree, hf_lmp_nameoffset, tvb, offset, 1, ENC_NA);
}

void
dissect_name_res(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 17);
	DISSECTOR_ASSERT(tvb_length_remaining(tvb, offset) >= 16);

	proto_tree_add_item(tree, hf_lmp_nameoffset, tvb, offset, 1, ENC_NA);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_namelen, tvb, offset, 1, ENC_NA);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_namefrag, tvb, offset, 14, ENC_ASCII|ENC_NA);
}

void
dissect_accepted(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 2);
	DISSECTOR_ASSERT(tvb_length_remaining(tvb, offset) >= 1);

	proto_tree_add_item(tree, hf_lmp_opinre, tvb, offset, 1, ENC_NA);
}

void
dissect_not_accepted(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 3);
	DISSECTOR_ASSERT(tvb_length_remaining(tvb, offset) >= 2);

	proto_tree_add_item(tree, hf_lmp_opinre, tvb, offset, 1, ENC_NA);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_err, tvb, offset, 1, ENC_NA);
}

void
dissect_clkoffset_req(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 1);
}

void
dissect_clkoffset_res(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 3);
	DISSECTOR_ASSERT(tvb_length_remaining(tvb, offset) >= 2);

	proto_tree_add_item(tree, hf_lmp_clkoffset, tvb, offset, 2, ENC_LITTLE_ENDIAN);
}

void
dissect_detach(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 2);
	DISSECTOR_ASSERT(tvb_length_remaining(tvb, offset) >= 1);

	proto_tree_add_item(tree, hf_lmp_err, tvb, offset, 1, ENC_NA);
}

void
dissect_in_rand(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 17);
	DISSECTOR_ASSERT(tvb_length_remaining(tvb, offset) >= 16);

	proto_tree_add_item(tree, hf_lmp_rand, tvb, offset, 16, ENC_NA);
}

void
dissect_comb_key(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 17);
	DISSECTOR_ASSERT(tvb_length_remaining(tvb, offset) >= 16);

	proto_tree_add_item(tree, hf_lmp_rand, tvb, offset, 16, ENC_NA);
}

void
dissect_unit_key(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 17);
	DISSECTOR_ASSERT(tvb_length_remaining(tvb, offset) >= 16);

	proto_tree_add_item(tree, hf_lmp_key, tvb, offset, 16, ENC_NA);
}

void
dissect_au_rand(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 17);
	DISSECTOR_ASSERT(tvb_length_remaining(tvb, offset) >= 16);

	proto_tree_add_item(tree, hf_lmp_rand, tvb, offset, 16, ENC_NA);
}

void
dissect_sres(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 5);
	DISSECTOR_ASSERT(tvb_length_remaining(tvb, offset) >= 4);

	proto_tree_add_item(tree, hf_lmp_authres, tvb, offset, 4, ENC_NA);
}

void
dissect_temp_rand(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 17);
	DISSECTOR_ASSERT(tvb_length_remaining(tvb, offset) >= 16);

	proto_tree_add_item(tree, hf_lmp_rand, tvb, offset, 16, ENC_NA);
}

void
dissect_temp_key(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 17);
	DISSECTOR_ASSERT(tvb_length_remaining(tvb, offset) >= 16);

	proto_tree_add_item(tree, hf_lmp_key, tvb, offset, 16, ENC_NA);
}

void
dissect_encryption_mode_req(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 2);
	DISSECTOR_ASSERT(tvb_length_remaining(tvb, offset) >= 1);

	proto_tree_add_item(tree, hf_lmp_cryptmode, tvb, offset, 1, ENC_LITTLE_ENDIAN);
}

void
dissect_encryption_key_size_req(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 2);
	DISSECTOR_ASSERT(tvb_length_remaining(tvb, offset) >= 1);

	proto_tree_add_item(tree, hf_lmp_keysz, tvb, offset, 1, ENC_LITTLE_ENDIAN);
}

void
dissect_start_encryption_req(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 17);
	DISSECTOR_ASSERT(tvb_length_remaining(tvb, offset) >= 16);

	proto_tree_add_item(tree, hf_lmp_rand, tvb, offset, 16, ENC_NA);
}

void
dissect_stop_encryption_req(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 1);
}

void
dissect_switch_req(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 5);
	DISSECTOR_ASSERT(tvb_length_remaining(tvb, offset) >= 4);

	proto_tree_add_item(tree, hf_lmp_swinst, tvb, offset, 4, ENC_LITTLE_ENDIAN);
}

void
dissect_hold(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 7);
	DISSECTOR_ASSERT(tvb_length_remaining(tvb, offset) >= 6);

	proto_tree_add_item(tree, hf_lmp_htime, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;

	proto_tree_add_item(tree, hf_lmp_hinst, tvb, offset, 4, ENC_LITTLE_ENDIAN);
}

void
dissect_hold_req(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 7);
	DISSECTOR_ASSERT(tvb_length_remaining(tvb, offset) >= 6);

	proto_tree_add_item(tree, hf_lmp_htime, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;

	proto_tree_add_item(tree, hf_lmp_hinst, tvb, offset, 4, ENC_LITTLE_ENDIAN);
}

void
dissect_sniff_req(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 10);
	DISSECTOR_ASSERT(tvb_length_remaining(tvb, offset) >= 9);

	proto_tree_add_bitmask(tree, tvb, offset, hf_lmp_timectrl,
			ett_lmp_timectrl, timectrl_fields, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_dsniff, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;

	proto_tree_add_item(tree, hf_lmp_tsniff, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;

	proto_tree_add_item(tree, hf_lmp_sniffatt, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;

	proto_tree_add_item(tree, hf_lmp_sniffto, tvb, offset, 2, ENC_LITTLE_ENDIAN);
}

void
dissect_unsniff_req(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 1);
}

void
dissect_park_req(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 17);
	DISSECTOR_ASSERT(tvb_length_remaining(tvb, offset) >= 16);

	proto_tree_add_bitmask(tree, tvb, offset, hf_lmp_timectrl,
			ett_lmp_timectrl, timectrl_fields, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_db, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;

	proto_tree_add_item(tree, hf_lmp_tb, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;

	proto_tree_add_item(tree, hf_lmp_nb, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_deltab, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_pmaddr, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_araddr, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_nbsleep, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_dbsleep, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_daccess, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_taccess, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_naccslots, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_npoll, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_maccess, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_lmp_accscheme, tvb, offset, 1, ENC_NA);
}

void
dissect_set_broadcast_scan_window(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	int db_present;

	DISSECTOR_ASSERT(tvb_length_remaining(tvb, offset) >= 1);

	proto_tree_add_bitmask(tree, tvb, offset, hf_lmp_timectrl,
			ett_lmp_timectrl, timectrl_fields, ENC_LITTLE_ENDIAN);

	/* bit0 of timing control flags indicates presence of db */
	db_present = tvb_get_guint8(tvb, offset) & 0x01;
	offset += 1;

	if (db_present) {
		DISSECTOR_ASSERT(len == 6);
		DISSECTOR_ASSERT(tvb_length_remaining(tvb, offset) >= 4);

		proto_tree_add_item(tree, hf_lmp_db, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		offset += 2;
	} else {
		DISSECTOR_ASSERT(len == 4);
		DISSECTOR_ASSERT(tvb_length_remaining(tvb, offset) >= 2);
	}

	proto_tree_add_item(tree, hf_lmp_bsw, tvb, offset, 2, ENC_LITTLE_ENDIAN);
}

void
dissect_modify_beacon(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	int db_present;

	DISSECTOR_ASSERT(tvb_length_remaining(tvb, offset) >= 1);

	proto_tree_add_bitmask(tree, tvb, offset, hf_lmp_timectrl,
			ett_lmp_timectrl, timectrl_fields, ENC_LITTLE_ENDIAN);

	/* bit0 of timing control flags indicates presence of db */
	db_present = tvb_get_guint8(tvb, offset) & 0x01;
	offset += 1;

	if (db_present) {
		DISSECTOR_ASSERT(len == 13);
		DISSECTOR_ASSERT(tvb_length_remaining(tvb, offset) >= 11);

		proto_tree_add_item(tree, hf_lmp_db, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		offset += 2;
	} else {
		DISSECTOR_ASSERT(len == 11);
		DISSECTOR_ASSERT(tvb_length_remaining(tvb, offset) >= 9);
	}

	proto_tree_add_item(tree, hf_lmp_tb, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;

	proto_tree_add_item(tree, hf_lmp_nb, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_deltab, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_daccess, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_taccess, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_naccslots, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_npoll, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_maccess, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_lmp_accscheme, tvb, offset, 1, ENC_NA);
}

void
dissect_unpark_bd_addr_req(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	int db_present;
	proto_item *item;

	DISSECTOR_ASSERT(tvb_length_remaining(tvb, offset) >= 1);

	proto_tree_add_bitmask(tree, tvb, offset, hf_lmp_timectrl,
			ett_lmp_timectrl, timectrl_fields, ENC_LITTLE_ENDIAN);

	/* bit0 of timing control flags indicates presence of db */
	db_present = tvb_get_guint8(tvb, offset) & 0x01;
	offset += 1;

	if (db_present) {
		DISSECTOR_ASSERT(len == 17);
		DISSECTOR_ASSERT(tvb_length_remaining(tvb, offset) >= 15);

		proto_tree_add_item(tree, hf_lmp_db, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		offset += 2;
	} else {
		DISSECTOR_ASSERT(len == 15);
		DISSECTOR_ASSERT(tvb_length_remaining(tvb, offset) >= 13);
	}

	proto_tree_add_item(tree, hf_lmp_ltaddr1, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_lmp_ltaddr2, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_bdaddr1, tvb, offset, 6, ENC_LITTLE_ENDIAN);
	offset += 6;

	proto_tree_add_item(tree, hf_lmp_bdaddr2, tvb, offset, 6, ENC_LITTLE_ENDIAN);
	offset += 6;
}

void
dissect_unpark_pm_addr_req(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	int db_present;

	DISSECTOR_ASSERT(tvb_length_remaining(tvb, offset) >= 1);

	proto_tree_add_bitmask(tree, tvb, offset, hf_lmp_timectrl,
			ett_lmp_timectrl, timectrl_fields, ENC_LITTLE_ENDIAN);

	/* bit0 of timing control flags indicates presence of db */
	db_present = tvb_get_guint8(tvb, offset) & 0x01;
	offset += 1;

	if (db_present) {
		DISSECTOR_ASSERT(len == 15);
		DISSECTOR_ASSERT(tvb_length_remaining(tvb, offset) >= 13);

		proto_tree_add_item(tree, hf_lmp_db, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		offset += 2;
	} else {
		DISSECTOR_ASSERT(len == 13);
		DISSECTOR_ASSERT(tvb_length_remaining(tvb, offset) >= 11);
	}

	proto_tree_add_item(tree, hf_lmp_ltaddr1, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_lmp_ltaddr2, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_pmaddr1, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_pmaddr2, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_ltaddr3, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_lmp_ltaddr4, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_pmaddr3, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_pmaddr4, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_ltaddr5, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_lmp_ltaddr6, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_pmaddr5, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_pmaddr6, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_ltaddr7, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_pmaddr7, tvb, offset, 1, ENC_LITTLE_ENDIAN);
}

void
dissect_incr_power_req(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 2);

	/* skipping one byte "for future use" */
}

void
dissect_decr_power_req(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 2);

	/* skipping one byte "for future use" */
}

void
dissect_max_power(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 1);
}

void
dissect_min_power(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 1);
}

void
dissect_auto_rate(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 1);
}

void
dissect_preferred_rate(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	proto_item *rate_item;
	proto_tree *rate_tree;

	DISSECTOR_ASSERT(len == 2);
	DISSECTOR_ASSERT(tvb_length_remaining(tvb, offset) >= 1);

	rate_item = proto_tree_add_item(tree, hf_lmp_rate, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	rate_tree = proto_item_add_subtree(rate_item, ett_lmp_rate);

	proto_tree_add_item(rate_tree, hf_lmp_rate_fec, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(rate_tree, hf_lmp_rate_size, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(rate_tree, hf_lmp_rate_type, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(rate_tree, hf_lmp_rate_edrsize, tvb, offset, 1, ENC_LITTLE_ENDIAN);
}

void
dissect_version_req(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 6);
	DISSECTOR_ASSERT(tvb_length_remaining(tvb, offset) >= 5);

	proto_tree_add_item(tree, hf_lmp_versnr, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_compid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;

	proto_tree_add_item(tree, hf_lmp_subversnr, tvb, offset, 2, ENC_LITTLE_ENDIAN);
}

void
dissect_version_res(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 6);
	DISSECTOR_ASSERT(tvb_length_remaining(tvb, offset) >= 5);

	proto_tree_add_item(tree, hf_lmp_versnr, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_compid, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;

	proto_tree_add_item(tree, hf_lmp_subversnr, tvb, offset, 2, ENC_LITTLE_ENDIAN);
}

void
dissect_features_req(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 9);
	DISSECTOR_ASSERT(tvb_length_remaining(tvb, offset) >= 8);

	proto_tree_add_item(tree, hf_lmp_features, tvb, offset, 8, ENC_NA);
}

void
dissect_features_res(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 9);
	DISSECTOR_ASSERT(tvb_length_remaining(tvb, offset) >= 8);

	proto_tree_add_item(tree, hf_lmp_features, tvb, offset, 8, ENC_NA);
}

void
dissect_quality_of_service(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 4);
	DISSECTOR_ASSERT(tvb_length_remaining(tvb, offset) >= 3);

	proto_tree_add_item(tree, hf_lmp_pollintvl, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;

	proto_tree_add_item(tree, hf_lmp_nbc, tvb, offset, 1, ENC_LITTLE_ENDIAN);
}

void
dissect_quality_of_service_req(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 4);
	DISSECTOR_ASSERT(tvb_length_remaining(tvb, offset) >= 3);

	proto_tree_add_item(tree, hf_lmp_pollintvl, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;

	proto_tree_add_item(tree, hf_lmp_nbc, tvb, offset, 1, ENC_LITTLE_ENDIAN);
}

void
dissect_sco_link_req(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 7);
	DISSECTOR_ASSERT(tvb_length_remaining(tvb, offset) >= 6);

	proto_tree_add_item(tree, hf_lmp_scohdl, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_bitmask(tree, tvb, offset, hf_lmp_timectrl,
			ett_lmp_timectrl, timectrl_fields, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_dsco, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_tsco, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_scopkt, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_airmode, tvb, offset, 1, ENC_LITTLE_ENDIAN);
}

void
dissect_remove_sco_link_req(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 3);
	DISSECTOR_ASSERT(tvb_length_remaining(tvb, offset) >= 2);

	proto_tree_add_item(tree, hf_lmp_scohdl, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_err, tvb, offset, 1, ENC_NA);
}

void
dissect_max_slot(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 2);
	DISSECTOR_ASSERT(tvb_length_remaining(tvb, offset) >= 1);

	proto_tree_add_item(tree, hf_lmp_maxslots, tvb, offset, 1, ENC_LITTLE_ENDIAN);
}

void
dissect_max_slot_req(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 2);
	DISSECTOR_ASSERT(tvb_length_remaining(tvb, offset) >= 1);

	proto_tree_add_item(tree, hf_lmp_maxslots, tvb, offset, 1, ENC_LITTLE_ENDIAN);
}

void
dissect_timing_accuracy_req(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 1);
}

void
dissect_timing_accuracy_res(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 3);
	DISSECTOR_ASSERT(tvb_length_remaining(tvb, offset) >= 2);

	proto_tree_add_item(tree, hf_lmp_drift, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_jitter, tvb, offset, 1, ENC_LITTLE_ENDIAN);
}

void
dissect_setup_complete(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 1);
}

void
dissect_use_semi_permanent_key(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 1);
}

void
dissect_host_connection_req(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 1);
}

void
dissect_slot_offset(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 9);
	DISSECTOR_ASSERT(tvb_length_remaining(tvb, offset) >= 8);

	proto_tree_add_item(tree, hf_lmp_slotoffset, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;

	proto_tree_add_item(tree, hf_lmp_bdaddr, tvb, offset, 6, ENC_LITTLE_ENDIAN);
}

void
dissect_page_mode_req(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 3);
	DISSECTOR_ASSERT(tvb_length_remaining(tvb, offset) >= 2);

	proto_tree_add_item(tree, hf_lmp_pagesch, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_pssettings, tvb, offset, 1, ENC_LITTLE_ENDIAN);
}

void
dissect_page_scan_mode_req(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 3);
	DISSECTOR_ASSERT(tvb_length_remaining(tvb, offset) >= 2);

	proto_tree_add_item(tree, hf_lmp_pagesch, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_pssettings, tvb, offset, 1, ENC_LITTLE_ENDIAN);
}

void
dissect_supervision_timeout(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 3);
	DISSECTOR_ASSERT(tvb_length_remaining(tvb, offset) >= 2);

	proto_tree_add_item(tree, hf_lmp_suptimeout, tvb, offset, 2, ENC_LITTLE_ENDIAN);
}

void
dissect_test_activate(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 1);
}

void
dissect_test_control(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 10);
	DISSECTOR_ASSERT(tvb_length_remaining(tvb, offset) >= 9);

	/* FIXME these fields should all be XORed with 0x55. . . */

	proto_tree_add_item(tree, hf_lmp_testscen, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_hopmode, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_txfreq, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_rxfreq, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_pcmode, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_pollper, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_pkttype, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_testlen, tvb, offset, 2, ENC_LITTLE_ENDIAN);
}

void
dissect_encryption_key_size_mask_req(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 1);
}

void
dissect_encryption_key_size_mask_res(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 3);
	DISSECTOR_ASSERT(tvb_length_remaining(tvb, offset) >= 2);

	proto_tree_add_item(tree, hf_lmp_ksmask, tvb, offset, 2, ENC_LITTLE_ENDIAN);
}

void
dissect_set_afh(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 16);
	DISSECTOR_ASSERT(tvb_length_remaining(tvb, offset) >= 15);

	proto_tree_add_item(tree, hf_lmp_afhinst, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 4;

	proto_tree_add_item(tree, hf_lmp_afhmode, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_afhchmap, tvb, offset, 10, ENC_NA);
}

void
dissect_encapsulated_header(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 4);
	DISSECTOR_ASSERT(tvb_length_remaining(tvb, offset) >= 3);

	proto_tree_add_item(tree, hf_lmp_encmaj, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_encmin, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_enclen, tvb, offset, 1, ENC_LITTLE_ENDIAN);
}

void
dissect_encapsulated_payload(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 17);
	DISSECTOR_ASSERT(tvb_length_remaining(tvb, offset) >= 16);

	proto_tree_add_item(tree, hf_lmp_encdata, tvb, offset, 16, ENC_NA);
}

void
dissect_simple_pairing_confirm(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 17);
	DISSECTOR_ASSERT(tvb_length_remaining(tvb, offset) >= 16);

	proto_tree_add_item(tree, hf_lmp_commit, tvb, offset, 16, ENC_NA);
}

void
dissect_simple_pairing_number(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 17);
	DISSECTOR_ASSERT(tvb_length_remaining(tvb, offset) >= 16);

	proto_tree_add_item(tree, hf_lmp_nonce, tvb, offset, 16, ENC_NA);
}

void
dissect_dhkey_check(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 17);
	DISSECTOR_ASSERT(tvb_length_remaining(tvb, offset) >= 16);

	proto_tree_add_item(tree, hf_lmp_confirm, tvb, offset, 16, ENC_NA);
}

/* LMP PDUs with extended opcodes */

void
dissect_accepted_ext(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 4);
	DISSECTOR_ASSERT(tvb_length_remaining(tvb, offset) >= 2);

	proto_tree_add_item(tree, hf_lmp_opinre, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_eopinre, tvb, offset, 1, ENC_LITTLE_ENDIAN);
}

void
dissect_not_accepted_ext(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 4);
	DISSECTOR_ASSERT(tvb_length_remaining(tvb, offset) >= 2);

	proto_tree_add_item(tree, hf_lmp_opinre, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_eopinre, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_err, tvb, offset, 1, ENC_NA);
}

void
dissect_features_req_ext(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 12);
	DISSECTOR_ASSERT(tvb_length_remaining(tvb, offset) >= 10);

	proto_tree_add_item(tree, hf_lmp_fpage, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_maxsp, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	/*
	 * extended features might need to be different from hf_lmp_features
	 * if hf_lmp_features is broken out
	 */
	proto_tree_add_item(tree, hf_lmp_features, tvb, offset, 8, ENC_NA);
}

void
dissect_features_res_ext(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 12);
	DISSECTOR_ASSERT(tvb_length_remaining(tvb, offset) >= 10);

	proto_tree_add_item(tree, hf_lmp_fpage, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_maxsp, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	/*
	 * extended features might need to be different from hf_lmp_features
	 * if hf_lmp_features is broken out
	 */
	proto_tree_add_item(tree, hf_lmp_features, tvb, offset, 8, ENC_NA);
}

void
dissect_packet_type_table_req(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 3);
	DISSECTOR_ASSERT(tvb_length_remaining(tvb, offset) >= 1);

	proto_tree_add_item(tree, hf_lmp_pkttypetbl, tvb, offset, 1, ENC_LITTLE_ENDIAN);
}

void
dissect_esco_link_req(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 16);
	DISSECTOR_ASSERT(tvb_length_remaining(tvb, offset) >= 14);

	proto_tree_add_item(tree, hf_lmp_escohdl, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_escoltaddr, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_bitmask(tree, tvb, offset, hf_lmp_timectrl,
			ett_lmp_timectrl, timectrl_fields, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_desco, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_tesco, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_wesco, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_escotypems, tvb, offset, 1, ENC_NA);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_escotypesm, tvb, offset, 1, ENC_NA);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_escolenms, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;

	proto_tree_add_item(tree, hf_lmp_escolensm, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;

	proto_tree_add_item(tree, hf_lmp_airmode, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_negstate, tvb, offset, 1, ENC_LITTLE_ENDIAN);
}

void
dissect_remove_esco_link_req(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 4);
	DISSECTOR_ASSERT(tvb_length_remaining(tvb, offset) >= 2);

	proto_tree_add_item(tree, hf_lmp_escohdl, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_err, tvb, offset, 1, ENC_NA);
}

void
dissect_channel_classification_req(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 7);
	DISSECTOR_ASSERT(tvb_length_remaining(tvb, offset) >= 5);

	proto_tree_add_item(tree, hf_lmp_afhrptmode, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_afhminintvl, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;

	proto_tree_add_item(tree, hf_lmp_afhmaxintvl, tvb, offset, 2, ENC_LITTLE_ENDIAN);
}

void
dissect_channel_classification(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 12);
	DISSECTOR_ASSERT(tvb_length_remaining(tvb, offset) >= 10);

	proto_tree_add_item(tree, hf_lmp_afhclass, tvb, offset, 10, ENC_NA);
}

void
dissect_sniff_subrating_req(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 9);
	DISSECTOR_ASSERT(tvb_length_remaining(tvb, offset) >= 7);

	proto_tree_add_item(tree, hf_lmp_maxss, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_minsmt, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;

	proto_tree_add_item(tree, hf_lmp_sniffsi, tvb, offset, 2, ENC_LITTLE_ENDIAN);
}

void
dissect_sniff_subrating_res(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 9);
	DISSECTOR_ASSERT(tvb_length_remaining(tvb, offset) >= 7);

	proto_tree_add_item(tree, hf_lmp_maxss, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_minsmt, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;

	proto_tree_add_item(tree, hf_lmp_sniffsi, tvb, offset, 2, ENC_LITTLE_ENDIAN);
}

void
dissect_pause_encryption_req(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 2);
}

void
dissect_resume_encryption_req(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 2);
}

void
dissect_io_capability_req(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 5);
	DISSECTOR_ASSERT(tvb_length_remaining(tvb, offset) >= 3);

	proto_tree_add_item(tree, hf_lmp_iocaps, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_oobauthdata, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_authreqs, tvb, offset, 1, ENC_LITTLE_ENDIAN);
}

void
dissect_io_capability_res(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 5);
	DISSECTOR_ASSERT(tvb_length_remaining(tvb, offset) >= 3);

	proto_tree_add_item(tree, hf_lmp_iocaps, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_oobauthdata, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	proto_tree_add_item(tree, hf_lmp_authreqs, tvb, offset, 1, ENC_LITTLE_ENDIAN);
}

void
dissect_numeric_comparison_failed(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 2);
}

void
dissect_passkey_failed(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 2);
}

void
dissect_oob_failed(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 2);
}

void
dissect_keypress_notification(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 3);
	DISSECTOR_ASSERT(tvb_length_remaining(tvb, offset) >= 1);

	proto_tree_add_item(tree, hf_lmp_nottype, tvb, offset, 1, ENC_LITTLE_ENDIAN);
}

void
dissect_power_control_req(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	DISSECTOR_ASSERT(len == 3);
	DISSECTOR_ASSERT(tvb_length_remaining(tvb, offset) >= 1);

	proto_tree_add_item(tree, hf_lmp_pwradjreq, tvb, offset, 1, ENC_LITTLE_ENDIAN);
}

void
dissect_power_control_res(proto_tree *tree, tvbuff_t *tvb, int offset, int len)
{
	proto_item *pa_item;
	proto_tree *pa_tree;

	DISSECTOR_ASSERT(len == 3);
	DISSECTOR_ASSERT(tvb_length_remaining(tvb, offset) >= 1);

	pa_item = proto_tree_add_item(tree, hf_lmp_pwradjres, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	pa_tree = proto_item_add_subtree(pa_item, ett_lmp_pwradjres);

	proto_tree_add_item(pa_tree, hf_lmp_pwradj_gfsk, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(pa_tree, hf_lmp_pwradj_dqpsk, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(pa_tree, hf_lmp_pwradj_8dpsk, tvb, offset, 1, ENC_LITTLE_ENDIAN);
}

/* Link Manager Protocol */
static void
dissect_btbrlmp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item *lmp_item;
	proto_tree *lmp_tree;
	int offset;
	int len;
	int op;     /* opcode */
	int eop;    /* extended opcode */

	offset = 0;
	len = tvb_length(tvb);

	DISSECTOR_ASSERT(len >= 1);

	/* make entries in protocol column and info column on summary display */
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "LMP");

	/* clear the info column first just in case of type fetching failure. */
	col_clear(pinfo->cinfo, COL_INFO);

	op = tvb_get_guint8(tvb, offset) >> 1;

	if (op == LMP_ESCAPE_4) {
		DISSECTOR_ASSERT(len >= 2);

		eop = tvb_get_guint8(tvb, offset + 1);

		col_add_str(pinfo->cinfo, COL_INFO, val_to_str(eop,
			opcode, "Unknown Extended Opcode (%d)"));
	} else {
		col_add_str(pinfo->cinfo, COL_INFO, val_to_str(op,
			opcode, "Unknown Opcode (%d)"));
	}

	/* see if we are being asked for details */
	if (!tree)
		return;

	lmp_item = proto_tree_add_item(tree, proto_btbrlmp, tvb, offset, -1, ENC_NA);
	lmp_tree = proto_item_add_subtree(lmp_item, ett_lmp);

	proto_tree_add_item(lmp_tree, hf_lmp_tid, tvb, offset, 1, ENC_LITTLE_ENDIAN);

	proto_tree_add_item(lmp_tree, hf_lmp_op, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	switch (op) {
	case LMP_NAME_REQ:
		dissect_name_req(lmp_tree, tvb, offset, len);
		break;
	case LMP_NAME_RES:
		dissect_name_res(lmp_tree, tvb, offset, len);
		break;
	case LMP_ACCEPTED:
		dissect_accepted(lmp_tree, tvb, offset, len);
		break;
	case LMP_NOT_ACCEPTED:
		dissect_not_accepted(lmp_tree, tvb, offset, len);
		break;
	case LMP_CLKOFFSET_REQ:
		dissect_clkoffset_req(lmp_tree, tvb, offset, len);
		break;
	case LMP_CLKOFFSET_RES:
		dissect_clkoffset_res(lmp_tree, tvb, offset, len);
		break;
	case LMP_DETACH:
		dissect_detach(lmp_tree, tvb, offset, len);
		break;
	case LMP_IN_RAND:
		dissect_in_rand(lmp_tree, tvb, offset, len);
		break;
	case LMP_COMB_KEY:
		dissect_comb_key(lmp_tree, tvb, offset, len);
		break;
	case LMP_UNIT_KEY:
		dissect_unit_key(lmp_tree, tvb, offset, len);
		break;
	case LMP_AU_RAND:
		dissect_au_rand(lmp_tree, tvb, offset, len);
		break;
	case LMP_SRES:
		dissect_sres(lmp_tree, tvb, offset, len);
		break;
	case LMP_TEMP_RAND:
		dissect_temp_rand(lmp_tree, tvb, offset, len);
		break;
	case LMP_TEMP_KEY:
		dissect_temp_key(lmp_tree, tvb, offset, len);
		break;
	case LMP_ENCRYPTION_MODE_REQ:
		dissect_encryption_mode_req(lmp_tree, tvb, offset, len);
		break;
	case LMP_ENCRYPTION_KEY_SIZE_REQ:
		dissect_encryption_key_size_req(lmp_tree, tvb, offset, len);
		break;
	case LMP_START_ENCRYPTION_REQ:
		dissect_start_encryption_req(lmp_tree, tvb, offset, len);
		break;
	case LMP_STOP_ENCRYPTION_REQ:
		dissect_stop_encryption_req(lmp_tree, tvb, offset, len);
		break;
	case LMP_SWITCH_REQ:
		dissect_switch_req(lmp_tree, tvb, offset, len);
		break;
	case LMP_HOLD:
		dissect_hold(lmp_tree, tvb, offset, len);
		break;
	case LMP_HOLD_REQ:
		dissect_hold_req(lmp_tree, tvb, offset, len);
		break;
	case LMP_SNIFF_REQ:
		dissect_sniff_req(lmp_tree, tvb, offset, len);
		break;
	case LMP_UNSNIFF_REQ:
		dissect_unsniff_req(lmp_tree, tvb, offset, len);
		break;
	case LMP_PARK_REQ:
		dissect_park_req(lmp_tree, tvb, offset, len);
		break;
	case LMP_SET_BROADCAST_SCAN_WINDOW:
		dissect_set_broadcast_scan_window(lmp_tree, tvb, offset, len);
		break;
	case LMP_MODIFY_BEACON:
		dissect_modify_beacon(lmp_tree, tvb, offset, len);
		break;
	case LMP_UNPARK_BD_ADDR_REQ:
		dissect_unpark_bd_addr_req(lmp_tree, tvb, offset, len);
		break;
	case LMP_UNPARK_PM_ADDR_REQ:
		dissect_unpark_pm_addr_req(lmp_tree, tvb, offset, len);
		break;
	case LMP_INCR_POWER_REQ:
		dissect_incr_power_req(lmp_tree, tvb, offset, len);
		break;
	case LMP_DECR_POWER_REQ:
		dissect_decr_power_req(lmp_tree, tvb, offset, len);
		break;
	case LMP_MAX_POWER:
		dissect_max_power(lmp_tree, tvb, offset, len);
		break;
	case LMP_MIN_POWER:
		dissect_min_power(lmp_tree, tvb, offset, len);
		break;
	case LMP_AUTO_RATE:
		dissect_auto_rate(lmp_tree, tvb, offset, len);
		break;
	case LMP_PREFERRED_RATE:
		dissect_preferred_rate(lmp_tree, tvb, offset, len);
		break;
	case LMP_VERSION_REQ:
		dissect_version_req(lmp_tree, tvb, offset, len);
		break;
	case LMP_VERSION_RES:
		dissect_version_res(lmp_tree, tvb, offset, len);
		break;
	case LMP_FEATURES_REQ:
		dissect_features_req(lmp_tree, tvb, offset, len);
		break;
	case LMP_FEATURES_RES:
		dissect_features_res(lmp_tree, tvb, offset, len);
		break;
	case LMP_QUALITY_OF_SERVICE:
		dissect_quality_of_service(lmp_tree, tvb, offset, len);
		break;
	case LMP_QUALITY_OF_SERVICE_REQ:
		dissect_quality_of_service_req(lmp_tree, tvb, offset, len);
		break;
	case LMP_SCO_LINK_REQ:
		dissect_sco_link_req(lmp_tree, tvb, offset, len);
		break;
	case LMP_REMOVE_SCO_LINK_REQ:
		dissect_remove_sco_link_req(lmp_tree, tvb, offset, len);
		break;
	case LMP_MAX_SLOT:
		dissect_max_slot(lmp_tree, tvb, offset, len);
		break;
	case LMP_MAX_SLOT_REQ:
		dissect_max_slot_req(lmp_tree, tvb, offset, len);
		break;
	case LMP_TIMING_ACCURACY_REQ:
		dissect_timing_accuracy_req(lmp_tree, tvb, offset, len);
		break;
	case LMP_TIMING_ACCURACY_RES:
		dissect_timing_accuracy_res(lmp_tree, tvb, offset, len);
		break;
	case LMP_SETUP_COMPLETE:
		dissect_setup_complete(lmp_tree, tvb, offset, len);
		break;
	case LMP_USE_SEMI_PERMANENT_KEY:
		dissect_use_semi_permanent_key(lmp_tree, tvb, offset, len);
		break;
	case LMP_HOST_CONNECTION_REQ:
		dissect_host_connection_req(lmp_tree, tvb, offset, len);
		break;
	case LMP_SLOT_OFFSET:
		dissect_slot_offset(lmp_tree, tvb, offset, len);
		break;
	case LMP_PAGE_MODE_REQ:
		dissect_page_mode_req(lmp_tree, tvb, offset, len);
		break;
	case LMP_PAGE_SCAN_MODE_REQ:
		dissect_page_scan_mode_req(lmp_tree, tvb, offset, len);
		break;
	case LMP_SUPERVISION_TIMEOUT:
		dissect_supervision_timeout(lmp_tree, tvb, offset, len);
		break;
	case LMP_TEST_ACTIVATE:
		dissect_test_activate(lmp_tree, tvb, offset, len);
		break;
	case LMP_TEST_CONTROL:
		dissect_test_control(lmp_tree, tvb, offset, len);
		break;
	case LMP_ENCRYPTION_KEY_SIZE_MASK_REQ:
		dissect_encryption_key_size_mask_req(lmp_tree, tvb, offset, len);
		break;
	case LMP_ENCRYPTION_KEY_SIZE_MASK_RES:
		dissect_encryption_key_size_mask_res(lmp_tree, tvb, offset, len);
		break;
	case LMP_SET_AFH:
		dissect_set_afh(lmp_tree, tvb, offset, len);
		break;
	case LMP_ENCAPSULATED_HEADER:
		dissect_encapsulated_header(lmp_tree, tvb, offset, len);
		break;
	case LMP_ENCAPSULATED_PAYLOAD:
		dissect_encapsulated_payload(lmp_tree, tvb, offset, len);
		break;
	case LMP_SIMPLE_PAIRING_CONFIRM:
		dissect_simple_pairing_confirm(lmp_tree, tvb, offset, len);
		break;
	case LMP_SIMPLE_PAIRING_NUMBER:
		dissect_simple_pairing_number(lmp_tree, tvb, offset, len);
		break;
	case LMP_DHKEY_CHECK:
		dissect_dhkey_check(lmp_tree, tvb, offset, len);
		break;
	case LMP_ESCAPE_1:
		break;
	case LMP_ESCAPE_2:
		break;
	case LMP_ESCAPE_3:
		break;
	case LMP_ESCAPE_4:
		/* extended opcode */
		DISSECTOR_ASSERT(len >= 2);
		proto_tree_add_item(lmp_tree, hf_lmp_eop, tvb, offset, 1, ENC_NA);
		offset += 1;

		switch (eop) {
		case LMP_ACCEPTED_EXT:
			dissect_accepted_ext(lmp_tree, tvb, offset, len);
			break;
		case LMP_NOT_ACCEPTED_EXT:
			dissect_not_accepted_ext(lmp_tree, tvb, offset, len);
			break;
		case LMP_FEATURES_REQ_EXT:
			dissect_features_req_ext(lmp_tree, tvb, offset, len);
			break;
		case LMP_FEATURES_RES_EXT:
			dissect_features_res_ext(lmp_tree, tvb, offset, len);
			break;
		case LMP_PACKET_TYPE_TABLE_REQ:
			dissect_packet_type_table_req(lmp_tree, tvb, offset, len);
			break;
		case LMP_ESCO_LINK_REQ:
			dissect_esco_link_req(lmp_tree, tvb, offset, len);
			break;
		case LMP_REMOVE_ESCO_LINK_REQ:
			dissect_remove_esco_link_req(lmp_tree, tvb, offset, len);
			break;
		case LMP_CHANNEL_CLASSIFICATION_REQ:
			dissect_channel_classification_req(lmp_tree, tvb, offset, len);
			break;
		case LMP_CHANNEL_CLASSIFICATION:
			dissect_channel_classification(lmp_tree, tvb, offset, len);
			break;
		case LMP_SNIFF_SUBRATING_REQ:
			dissect_sniff_subrating_req(lmp_tree, tvb, offset, len);
			break;
		case LMP_SNIFF_SUBRATING_RES:
			dissect_sniff_subrating_res(lmp_tree, tvb, offset, len);
			break;
		case LMP_PAUSE_ENCRYPTION_REQ:
			dissect_pause_encryption_req(lmp_tree, tvb, offset, len);
			break;
		case LMP_RESUME_ENCRYPTION_REQ:
			dissect_resume_encryption_req(lmp_tree, tvb, offset, len);
			break;
		case LMP_IO_CAPABILITY_REQ:
			dissect_io_capability_req(lmp_tree, tvb, offset, len);
			break;
		case LMP_IO_CAPABILITY_RES:
			dissect_io_capability_res(lmp_tree, tvb, offset, len);
			break;
		case LMP_NUMERIC_COMPARISON_FAILED:
			dissect_numeric_comparison_failed(lmp_tree, tvb, offset, len);
			break;
		case LMP_PASSKEY_FAILED:
			dissect_passkey_failed(lmp_tree, tvb, offset, len);
			break;
		case LMP_OOB_FAILED:
			dissect_oob_failed(lmp_tree, tvb, offset, len);
			break;
		case LMP_KEYPRESS_NOTIFICATION:
			dissect_keypress_notification(lmp_tree, tvb, offset, len);
			break;
		case LMP_POWER_CONTROL_REQ:
			dissect_power_control_req(lmp_tree, tvb, offset, len);
			break;
		case LMP_POWER_CONTROL_RES:
			dissect_power_control_res(lmp_tree, tvb, offset, len);
			break;
		default:
			break;
		}
	default:
		break;
	}
};

/* register the protocol with Wireshark */
void
proto_register_btbrlmp(void)
{

	/* list of fields */
	static hf_register_info hf[] = {
		{ &hf_lmp_accscheme,
			{ "Access Scheme", "btbrlmp.accscheme",
			FT_UINT8, BASE_DEC, VALS(access_scheme), 0xf0,
			NULL, HFILL }
		},
		{ &hf_lmp_afhchmap,
			{ "AFH Channel Map", "btbrlmp.afhchmap",
			/* could break out individual channels but long */
			FT_BYTES, BASE_NONE, NULL, 0x0,
			"Adaptive Frequency Hopping Channel Map", HFILL }
		},
		{ &hf_lmp_afhclass,
			{ "AFH Channel Classification", "btbrlmp.afhclass",
			/* could break out individual channels but long */
			FT_BYTES, BASE_NONE, NULL, 0x0,
			"Adaptive Frequency Hopping Channel Classification", HFILL }
		},
		{ &hf_lmp_afhinst,
			{ "AFH Instant", "btbrlmp.afhinst",
			FT_UINT32, BASE_HEX, NULL, 0x0,
			"Adaptive Frequency Hopping Instant (slot)", HFILL }
		},
		{ &hf_lmp_afhmaxintvl,
			{ "AFH Max Interval", "btbrlmp.maxintvl",
			FT_UINT16, BASE_HEX, NULL, 0x0,
			"Adaptive Maximum Interval in slots", HFILL }
		},
		{ &hf_lmp_afhminintvl,
			{ "AFH Min Interval", "btbrlmp.minintvl",
			FT_UINT16, BASE_HEX, NULL, 0x0,
			"Adaptive Minimum Interval in slots", HFILL }
		},
		{ &hf_lmp_afhmode,
			{ "AFH Mode", "btbrlmp.afhmode",
			FT_UINT8, BASE_DEC, VALS(afh_mode), 0x0,
			"Adaptive Frequency Hopping Mode", HFILL }
		},
		{ &hf_lmp_afhrptmode,
			{ "AFH Reporting Mode", "btbrlmp.afhrptmode",
			FT_UINT8, BASE_DEC, VALS(afh_reporting_mode), 0x0,
			"Adaptive Frequency Hopping Reporting Mode", HFILL }
		},
		{ &hf_lmp_airmode,
			{ "Air Mode", "btbrlmp.airmode",
			FT_UINT8, BASE_HEX, VALS(air_mode), 0x0,
			NULL, HFILL }
		},
		{ &hf_lmp_araddr,
			{ "AR_ADDR", "btbrlmp.araddr",
			FT_UINT8, BASE_HEX, NULL, 0xfe,
			NULL, HFILL }
		},
		{ &hf_lmp_authreqs,
			{ "Authentication Requirements", "btbrlmp.authreqs",
			FT_UINT8, BASE_HEX, VALS(auth_requirements), 0xf0,
			NULL, HFILL }
		},
		{ &hf_lmp_authres,
			{ "Authentication Response", "btbrlmp.authres",
			FT_BYTES, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_lmp_bdaddr,
			{ "BD_ADDR", "btbrlmp.bdaddr",
			FT_UINT64, BASE_HEX, NULL, 0x0000ffffffffffff,
			NULL, HFILL }
		},
		{ &hf_lmp_bdaddr1,
			{ "BD_ADDR 1", "btbrlmp.bdaddr",
			FT_UINT64, BASE_HEX, NULL, 0x0000ffffffffffff,
			NULL, HFILL }
		},
		{ &hf_lmp_bdaddr2,
			{ "BD_ADDR2", "btbrlmp.bdaddr",
			FT_UINT64, BASE_HEX, NULL, 0x0000ffffffffffff,
			"BD_ADDR 2", HFILL }
		},
		{ &hf_lmp_bsw,
			{ "Broadcast Scan Window", "btbrlmp.bsw",
			FT_UINT16, BASE_HEX, NULL, 0x0,
			"Broadcast Scan Window in slots", HFILL }
		},
		{ &hf_lmp_clkoffset,
			{ "Clock Offset", "btbrlmp.clkoffset",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"Clock Offset in units of 1.25 ms", HFILL }
		},
		{ &hf_lmp_commit,
			{ "Commitment Value", "btbrlmp.commit",
			FT_BYTES, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_lmp_confirm,
			{ "Confirmation Value", "btbrlmp.confirm",
			FT_BYTES, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_lmp_compid,
			{ "Company ID", "btbrlmp.compid",
			FT_UINT16, BASE_DEC, VALS(compid), 0x0,
			NULL, HFILL }
		},
		{ &hf_lmp_cryptmode,
			{ "Encryption Mode", "btbrlmp.cryptmode",
			FT_UINT8, BASE_DEC, VALS(encryption_mode), 0x0,
			NULL, HFILL }
		},
		{ &hf_lmp_daccess,
			{ "Daccess", "btbrlmp.daccess",
			FT_UINT8, BASE_HEX, NULL, 0x0,
			"Daccess in slots", HFILL }
		},
		{ &hf_lmp_db,
			{ "Db", "btbrlmp.db",
			FT_UINT16, BASE_HEX, NULL, 0x0,
			"Db in slots", HFILL }
		},
		{ &hf_lmp_dbsleep,
			{ "Dbsleep", "btbrlmp.dbsleep",
			FT_UINT8, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_lmp_deltab,
			{ "Deltab", "btbrlmp.deltab",
			FT_UINT8, BASE_HEX, NULL, 0x0,
			"Deltab in slots", HFILL }
		},
		{ &hf_lmp_desco,
			{ "Desco", "btbrlmp.desco",
			FT_UINT8, BASE_HEX, NULL, 0x0,
			"Desco in slots", HFILL }
		},
		{ &hf_lmp_drift,
			{ "Drift", "btbrlmp.drift",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"Drift in ppm", HFILL }
		},
		{ &hf_lmp_dsco,
			{ "Dsco", "btbrlmp.dsco",
			FT_UINT8, BASE_HEX, NULL, 0x0,
			"Dsco in slots", HFILL }
		},
		{ &hf_lmp_dsniff,
			{ "Dsniff", "btbrlmp.dsniff",
			FT_UINT16, BASE_HEX, NULL, 0x0,
			"Dsniff in slots", HFILL }
		},
		{ &hf_lmp_encdata,
			{ "Encapsulated Data", "btbrlmp.encdata",
			FT_BYTES, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_lmp_enclen,
			{ "Encapsulated Length", "btbrlmp.enclen",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_lmp_encmaj,
			{ "Encapsulated Major Type", "btbrlmp.encmaj",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_lmp_encmin,
			{ "Encapsulated Minor Type", "btbrlmp.encmin",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_lmp_eop,
			{ "Extended Opcode", "btbrlmp.eop",
			FT_UINT8, BASE_DEC, VALS(ext_opcode), 0x0,
			NULL, HFILL }
		},
		{ &hf_lmp_eopinre,
			{ "In Response To", "btbrlmp.eopinre",
			FT_UINT8, BASE_DEC, VALS(ext_opcode), 0x0,
			"Extended Opcode this is in response to", HFILL }
		},
		{ &hf_lmp_escolenms,
			{ "Packet Length M -> S", "btbrlmp.escolenms",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"Packet Length in bytes Master to Slave", HFILL }
		},
		{ &hf_lmp_escolensm,
			{ "Packet Length S -> M", "btbrlmp.escolensm",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"Packet Length in bytes Slave to Master", HFILL }
		},
		{ &hf_lmp_escotypems,
			{ "eSCO Packet Type M -> S", "btbrlmp.escotypems",
			FT_UINT8, BASE_HEX, VALS(esco_packet_type), 0x0,
			"eSCO Packet Type Master to Slave", HFILL }
		},
		{ &hf_lmp_escotypesm,
			{ "eSCO Packet Type S -> M", "btbrlmp.escotypesm",
			FT_UINT8, BASE_HEX, VALS(esco_packet_type), 0x0,
			"eSCO Packet Type Slave to Master", HFILL }
		},
		{ &hf_lmp_err,
			{ "Error Code", "btbrlmp.err",
			FT_UINT8, BASE_HEX, VALS(error_code), 0x0,
			NULL, HFILL }
		},
		{ &hf_lmp_escohdl,
			{ "eSCO Handle", "btbrlmp.escohdl",
			FT_UINT8, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_lmp_escoltaddr,
			{ "eSCO LT_ADDR", "btbrlmp.escoltaddr",
			FT_UINT8, BASE_HEX, NULL, 0x0,
			"eSCO Logical Transport Address", HFILL }
		},
		{ &hf_lmp_features,
			{ "Features", "btbrlmp.features",
			/* could break out individual features but long */
			FT_BYTES, BASE_NONE, NULL, 0x0,
			"Feature Mask", HFILL }
		},
		{ &hf_lmp_fpage,
			{ "Features Page", "btbrlmp.fpage",
			FT_UINT8, BASE_DEC, VALS(features_page), 0x0,
			NULL, HFILL }
		},
		{ &hf_lmp_htime,
			{ "Hold Time", "btbrlmp.htime",
			FT_UINT16, BASE_HEX, NULL, 0x0,
			"Hold Time in slots", HFILL }
		},
		{ &hf_lmp_hinst,
			{ "Hold Instant", "btbrlmp.hinst",
			FT_UINT32, BASE_HEX, NULL, 0x0,
			"Hold Instant (slot)", HFILL }
		},
		{ &hf_lmp_hopmode,
			{ "Hopping Mode", "btbrlmp.hopmode",
			FT_UINT8, BASE_DEC, VALS(hopping_mode), 0x0,
			NULL, HFILL }
		},
		{ &hf_lmp_iocaps,
			{ "IO Capabilities", "btbrlmp.iocaps",
			FT_UINT8, BASE_DEC, VALS(io_capabilities), 0x0,
			"Input/Output Capabilities", HFILL }
		},
		{ &hf_lmp_jitter,
			{ "Jitter", "btbrlmp.jitter",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"Jitter in microseconds", HFILL }
		},
		{ &hf_lmp_key,
			{ "Key", "btbrlmp.key",
			FT_BYTES, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_lmp_keysz,
			{ "Key Size", "btbrlmp.keysz",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"Key Size in bytes", HFILL }
		},
		{ &hf_lmp_ksmask,
			{ "Key Size Mask", "btbrlmp.ksmask",
			FT_UINT16, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_lmp_ltaddr1,
			{ "LT_ADDR 1", "btbrlmp.ltaddr",
			FT_UINT8, BASE_HEX, NULL, 0x0f,
			"Logical Transport Address 1", HFILL }
		},
		{ &hf_lmp_ltaddr2,
			{ "LT_ADDR 2", "btbrlmp.ltaddr",
			FT_UINT8, BASE_HEX, NULL, 0xf0,
			"Logical Transport Address 2", HFILL }
		},
		{ &hf_lmp_ltaddr3,
			{ "LT_ADDR 3", "btbrlmp.ltaddr",
			FT_UINT8, BASE_HEX, NULL, 0x0f,
			"Logical Transport Address 3", HFILL }
		},
		{ &hf_lmp_ltaddr4,
			{ "LT_ADDR 4", "btbrlmp.ltaddr",
			FT_UINT8, BASE_HEX, NULL, 0xf0,
			"Logical Transport Address 4", HFILL }
		},
		{ &hf_lmp_ltaddr5,
			{ "LT_ADDR 5", "btbrlmp.ltaddr",
			FT_UINT8, BASE_HEX, NULL, 0x0f,
			"Logical Transport Address 5", HFILL }
		},
		{ &hf_lmp_ltaddr6,
			{ "LT_ADDR 6", "btbrlmp.ltaddr",
			FT_UINT8, BASE_HEX, NULL, 0xf0,
			"Logical Transport Address 6", HFILL }
		},
		{ &hf_lmp_ltaddr7,
			{ "LT_ADDR 7", "btbrlmp.ltaddr",
			FT_UINT8, BASE_HEX, NULL, 0x0f,
			"Logical Transport Address 7", HFILL }
		},
		{ &hf_lmp_maccess,
			{ "Maccess", "btbrlmp.maccess",
			FT_UINT8, BASE_HEX, NULL, 0x0f,
			"Number of access windows", HFILL }
		},
		{ &hf_lmp_maxslots,
			{ "Max Slots", "btbrlmp.maxslots",
			FT_UINT8, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_lmp_maxsp,
			{ "Max Supported Page", "btbrlmp.maxsp",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"Highest extended features page with non-zero bit", HFILL }
		},
		{ &hf_lmp_maxss,
			{ "Max Sniff Subrate", "btbrlmp.maxss",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_lmp_minsmt,
			{ "Min Sniff Mode Timeout", "btbrlmp.minsmt",
			FT_UINT16, BASE_HEX, NULL, 0x0,
			"Min Sniff Mode Timeout in slots", HFILL }
		},
		{ &hf_lmp_naccslots,
			{ "Nacc-slots", "btbrlmp.naccslots",
			FT_UINT8, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_lmp_namefrag,
			{ "Name Fragment", "btbrlmp.namefrag",
			FT_STRING, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_lmp_namelen,
			{ "Name Length", "btbrlmp.namelen",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"Name Length in bytes", HFILL }
		},
		{ &hf_lmp_nameoffset,
			{ "Name Offset", "btbrlmp.nameoffset",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"Name Offset in bytes", HFILL }
		},
		{ &hf_lmp_nb,
			{ "Nb", "btbrlmp.nb",
			FT_UINT8, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_lmp_nbc,
			{ "Nbc", "btbrlmp.nbc",
			FT_UINT8, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_lmp_nbsleep,
			{ "Nbsleep", "btbrlmp.nbsleep",
			FT_UINT8, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_lmp_negstate,
			{ "Negotiation State", "btbrlmp.negstate",
			FT_UINT8, BASE_DEC, VALS(negotiation_state), 0x0,
			NULL, HFILL }
		},
		{ &hf_lmp_nonce,
			{ "Nonce Value", "btbrlmp.nonce",
			FT_BYTES, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_lmp_nottype,
			{ "Notification Type", "btbrlmp.nottype",
			FT_UINT8, BASE_DEC, VALS(notification_value), 0x0,
			NULL, HFILL }
		},
		{ &hf_lmp_npoll,
			{ "Npoll", "btbrlmp.npoll",
			FT_UINT8, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_lmp_oobauthdata,
			{ "OOB Authentication Data", "btbrlmp.oobauthdata",
			FT_UINT8, BASE_DEC, VALS(oob_auth_data), 0xfe,
			NULL, HFILL }
		},
		{ &hf_lmp_op,
			{ "Opcode", "btbrlmp.op",
			FT_UINT8, BASE_DEC, VALS(opcode), 0xfe,
			NULL, HFILL }
		},
		{ &hf_lmp_opinre,
			{ "In Response To", "btbrlmp.opinre",
			FT_UINT8, BASE_DEC, VALS(opcode), 0x7f,
			"Opcode this is in response to", HFILL }
		},
		{ &hf_lmp_pagesch,
			{ "Paging Scheme", "btbrlmp.pagesch",
			FT_UINT8, BASE_DEC, VALS(paging_scheme), 0x0,
			NULL, HFILL }
		},
		{ &hf_lmp_pcmode,
			{ "Power Control Mode", "btbrlmp.pcmode",
			FT_UINT8, BASE_DEC, VALS(power_control_mode), 0x0,
			NULL, HFILL }
		},
		{ &hf_lmp_pkttype,
			{ "Packet Type", "btbrlmp.pkttype",
			/* FIXME break out further */
			FT_UINT8, BASE_HEX, NULL, 0x0,
			"Packet Type", HFILL }
		},
		{ &hf_lmp_pkttypetbl,
			{ "Packet Type Table", "btbrlmp.pkttypetbl",
			FT_UINT8, BASE_DEC, VALS(packet_type_table), 0x0,
			NULL, HFILL }
		},
		{ &hf_lmp_pmaddr,
			{ "PM_ADDR", "btbrlmp.pmaddr",
			FT_UINT8, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_lmp_pmaddr1,
			{ "PM_ADDR 1", "btbrlmp.pmaddr1",
			FT_UINT8, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_lmp_pmaddr2,
			{ "PM_ADDR 2", "btbrlmp.pmaddr2",
			FT_UINT8, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_lmp_pmaddr3,
			{ "PM_ADDR 3", "btbrlmp.pmaddr3",
			FT_UINT8, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_lmp_pmaddr4,
			{ "PM_ADDR 4", "btbrlmp.pmaddr4",
			FT_UINT8, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_lmp_pmaddr5,
			{ "PM_ADDR 5", "btbrlmp.pmaddr5",
			FT_UINT8, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_lmp_pmaddr6,
			{ "PM_ADDR 6", "btbrlmp.pmaddr6",
			FT_UINT8, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_lmp_pmaddr7,
			{ "PM_ADDR 7", "btbrlmp.pmaddr7",
			FT_UINT8, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_lmp_pollintvl,
			{ "Poll Interval", "btbrlmp.pollintvl",
			FT_UINT16, BASE_HEX, NULL, 0x0,
			"Poll Interval in slots", HFILL }
		},
		{ &hf_lmp_pollper,
			{ "Poll Period", "btbrlmp.pollper",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"Poll Period in units of 1.25 ms", HFILL }
		},
		{ &hf_lmp_pssettings,
			{ "Paging Scheme Settings", "btbrlmp.pssettings",
			FT_UINT8, BASE_DEC, VALS(paging_scheme_settings), 0x0,
			NULL, HFILL }
		},
		{ &hf_lmp_pwradjreq,
			{ "Power Adjustment Request", "btbrlmp.pwradjreq",
			FT_UINT8, BASE_DEC, VALS(power_adjust_req), 0x0,
			NULL, HFILL }
		},
		{ &hf_lmp_pwradjres,
			{ "Power Adjustment Response", "btbrlmp.pwradjres",
			FT_UINT8, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_lmp_pwradj_8dpsk,
			{ "8DPSK", "btbrlmp.pwradj_8dpsk",
			FT_UINT8, BASE_DEC, VALS(power_adjust_res), 0x30,
			"8DPSK Power Adjustment Response", HFILL }
		},
		{ &hf_lmp_pwradj_dqpsk,
			{ "DQPSK", "btbrlmp.pwradj_dqpsk",
			FT_UINT8, BASE_DEC, VALS(power_adjust_res), 0x0C,
			"DQPSK Power Adjustment Response", HFILL }
		},
		{ &hf_lmp_pwradj_gfsk,
			{ "GFSK", "btbrlmp.pwradj_gfsk",
			FT_UINT8, BASE_DEC, VALS(power_adjust_res), 0x03,
			"GFSK Power Adjustment Response", HFILL }
		},
		{ &hf_lmp_rand,
			{ "Random Number", "btbrlmp.rand",
			FT_BYTES, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_lmp_rate,
			{ "Data Rate", "btbrlmp.rate",
			FT_UINT8, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_lmp_rate_fec,
			{ "FEC", "btbrlmp.rate.fec",
			FT_BOOLEAN, BASE_DEC, TFS(&fec), 0x01,
			"Forward Error Correction", HFILL }
		},
		{ &hf_lmp_rate_size,
			{ "Packet Size", "btbrlmp.rate.size",
			FT_UINT8, BASE_HEX, VALS(packet_size), 0x06,
			"Basic Rate Packet Size", HFILL }
		},
		{ &hf_lmp_rate_type,
			{ "EDR Type", "btbrlmp.rate.type",
			FT_UINT8, BASE_HEX, VALS(edr_type), 0x18,
			"Enhanced Data Rate type", HFILL }
		},
		{ &hf_lmp_rate_edrsize,
			{ "EDR Size", "btbrlmp.rate.edrsize",
			FT_UINT8, BASE_HEX, VALS(packet_size), 0x60,
			"Enhanced Data Rate packet size", HFILL }
		},
		{ &hf_lmp_rxfreq,
			{ "RX Frequency", "btbrlmp.rxfreq",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"Receive Frequency in MHz above 2402", HFILL }
		},
		{ &hf_lmp_scohdl,
			{ "SCO Handle", "btbrlmp.scohdl",
			FT_UINT8, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_lmp_scopkt,
			{ "SCO Packet", "btbrlmp.scopkt",
			FT_UINT8, BASE_DEC, VALS(sco_packet), 0x0,
			NULL, HFILL }
		},
		{ &hf_lmp_slotoffset,
			{ "Slot Offset", "btbrlmp.slotoffset",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"Slot Offset in microseconds", HFILL }
		},
		{ &hf_lmp_sniffatt,
			{ "Sniff Attempt", "btbrlmp.sniffatt",
			FT_UINT16, BASE_HEX, NULL, 0x0,
			"Number of receive slots", HFILL }
		},
		{ &hf_lmp_sniffsi,
			{ "Sniff Subrating Instant", "btbrlmp.sniffsi",
			FT_UINT32, BASE_HEX, NULL, 0x0,
			"Sniff Subrating Instant (slot)", HFILL }
		},
		{ &hf_lmp_sniffto,
			{ "Sniff Timeout", "btbrlmp.sniffto",
			FT_UINT16, BASE_HEX, NULL, 0x0,
			"Number of receive slots", HFILL }
		},
		{ &hf_lmp_subversnr,
			{ "SubVersNr", "btbrlmp.subversnr",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"SubVersion", HFILL }
		},
		{ &hf_lmp_suptimeout,
			{ "Supervision Timeout", "btbrlmp.suptimeout",
			FT_UINT16, BASE_HEX, NULL, 0x0,
			"Supervision Timeout in slots", HFILL }
		},
		{ &hf_lmp_swinst,
			{ "Switch Instant", "btbrlmp.swinst",
			FT_UINT32, BASE_HEX, NULL, 0x0,
			"Switch Instant (slot)", HFILL }
		},
		{ &hf_lmp_taccess,
			{ "Taccess", "btbrlmp.taccess",
			FT_UINT8, BASE_HEX, NULL, 0x0,
			"Taccess in slots", HFILL }
		},
		{ &hf_lmp_tb,
			{ "Tb", "btbrlmp.tb",
			FT_UINT16, BASE_HEX, NULL, 0x0,
			"Tb in slots", HFILL }
		},
		{ &hf_lmp_tesco,
			{ "Tesco", "btbrlmp.tesco",
			FT_UINT8, BASE_HEX, NULL, 0x0,
			"Tesco in slots", HFILL }
		},
		{ &hf_lmp_testlen,
			{ "Test Length", "btbrlmp.testlen",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"Length of test sequence in bytes", HFILL }
		},
		{ &hf_lmp_testscen,
			{ "Test Scenario", "btbrlmp.testscen",
			FT_UINT8, BASE_DEC, VALS(test_scenario), 0x0,
			NULL, HFILL }
		},
		{ &hf_lmp_tid,
			{ "TID", "btbrlmp.tid",
			FT_BOOLEAN, BASE_DEC, TFS(&tid), 0x01,
			"Transaction ID", HFILL }
		},
		{ &hf_lmp_timectrl,
			{ "Timing Control Flags", "btbrlmp.timectrl",
			FT_UINT8, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_lmp_time_change,
			{ "Timing Change", "btbrlmp.time.change",
			FT_BOOLEAN, 8, TFS(&time_change), 0x01,
			NULL, HFILL }
		},
		{ &hf_lmp_time_init,
			{ "Initialization", "btbrlmp.time.init",
			FT_BOOLEAN, 8, TFS(&time_init), 0x02,
			NULL, HFILL }
		},
		{ &hf_lmp_time_accwin,
			{ "Access Window", "btbrlmp.time.accwin",
			FT_BOOLEAN, 8, TFS(&time_accwin), 0x04,
			NULL, HFILL }
		},
		{ &hf_lmp_tsco,
			{ "Tsco", "btbrlmp.tsco",
			FT_UINT8, BASE_HEX, NULL, 0x0,
			"Tsco in slots", HFILL }
		},
		{ &hf_lmp_tsniff,
			{ "Tsniff", "btbrlmp.tsniff",
			FT_UINT16, BASE_HEX, NULL, 0x0,
			"Tsniff in slots", HFILL }
		},
		{ &hf_lmp_txfreq,
			{ "TX Frequency", "btbrlmp.txfreq",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"Transmit Frequency in MHz above 2402", HFILL }
		},
		{ &hf_lmp_versnr,
			{ "VersNr", "btbrlmp.versnr",
			FT_UINT8, BASE_DEC, VALS(versnr), 0x0,
			"Version", HFILL }
		},
		{ &hf_lmp_wesco,
			{ "Wesco", "btbrlmp.wesco",
			FT_UINT8, BASE_HEX, NULL, 0x0,
			"Number of slots in retransmission window", HFILL }
		},
	};

	/* protocol subtree arrays */
	static gint *ett[] = {
		&ett_lmp,
		&ett_lmp_pwradjres,
		&ett_lmp_rate,
		&ett_lmp_timectrl,
	};

	/* register the protocol name and description */
	proto_btbrlmp = proto_register_protocol(
		"Bluetooth BR Link Manager Protocol",	/* full name */
		"btbrlmp",		/* short name */
		"btbrlmp"			/* abbreviation (e.g. for filters) */
		);

	register_dissector("btbrlmp", dissect_btbrlmp, proto_btbrlmp);

	/* register the header fields and subtrees used */
	proto_register_field_array(proto_btbrlmp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_btbrlmp(void)
{
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
