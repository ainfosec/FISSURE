/* packet-btle.c
 * Routines for Bluetooth Low Energy dissection
 * Copyright 2013, Mike Ryan, mikeryan /at/ isecpartners /dot/ com
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
# include "config.h"
#endif

#include <wireshark/config.h> /* needed for epan/gcc-4.x */
#include <epan/packet.h>
#include <epan/prefs.h>

/* function prototypes */
void proto_reg_handoff_btle(void);

/* initialize the protocol and registered fields */
static int proto_btle = -1;
static int hf_btle_pkthdr = -1;
static int hf_btle_aa = -1;
static int hf_btle_type = -1;
static int hf_btle_randomized_tx = -1;
static int hf_btle_randomized_rx = -1;
static int hf_btle_length = -1;
static int hf_btle_adv_addr = -1;
static int hf_btle_adv_data = -1;
static int hf_btle_init_addr = -1;
static int hf_btle_scan_addr = -1;
static int hf_btle_scan_rsp_data = -1;
static int hf_btle_connect = -1;
static int hf_btle_connect_aa = -1;
static int hf_btle_crc_init = -1;
static int hf_btle_win_size = -1;
static int hf_btle_win_offset = -1;
static int hf_btle_interval = -1;
static int hf_btle_latency = -1;
static int hf_btle_timeout = -1;
static int hf_btle_data = -1;
static int hf_btle_data_llid = -1;
static int hf_btle_data_nesn = -1;
static int hf_btle_data_sn = -1;
static int hf_btle_data_md = -1;
static int hf_btle_data_rfu = -1;
static int hf_btle_ll_control_opcode = -1;
static int hf_btle_ll_control_data = -1;
static int hf_btle_ll_control_ll_enc_req = -1;
static int hf_btle_ll_control_ll_enc_req_rand = -1;
static int hf_btle_ll_control_ll_enc_req_ediv = -1;
static int hf_btle_ll_control_ll_enc_req_skdm = -1;
static int hf_btle_ll_control_ll_enc_req_ivm = -1;
static int hf_btle_ll_control_ll_enc_rsp = -1;
static int hf_btle_ll_control_ll_enc_rsp_skds = -1;
static int hf_btle_ll_control_ll_enc_rsp_ivs = -1;
static int hf_btle_crc = -1;

static const value_string packet_types[] = {
	{ 0x0, "ADV_IND" },
	{ 0x1, "ADV_DIRECT_IND" },
	{ 0x2, "ADV_NONCONN_IND" },
	{ 0x3, "SCAN_REQ" },
	{ 0x4, "SCAN_RSP" },
	{ 0x5, "CONNECT_REQ" },
	{ 0x6, "ADV_SCAN_IND" },
	{ 0, NULL }
};

static const value_string llid_codes[] = {
	{ 0x0, "undefined" },
	{ 0x1, "Continuation fragment of an L2CAP message" },
	{ 0x2, "Start of an L2CAP message or no fragmentation" },
	{ 0x3, "LL Control PDU" },
	{ 0, NULL }
};

static const value_string ll_control_opcodes[] = {
	{ 0x00, "LL_CONNECTION_UPDATE_REQ" },
	{ 0x01, "LL_CHANNEL_MAP_REQ" },
	{ 0x02, "LL_TERMINATE_IND" },
	{ 0x03, "LL_ENC_REQ" },
	{ 0x04, "LL_ENC_RSP" },
	{ 0x05, "LL_START_ENC_REQ" },
	{ 0x06, "LL_START_ENC_RSP" },
	{ 0x07, "LL_UNKNOWN_RSP" },
	{ 0x08, "LL_FEATURE_REQ" },
	{ 0x09, "LL_FEATURE_RSP" },
	{ 0x0A, "LL_PAUSE_ENC_REQ" },
	{ 0x0B, "LL_PAUSE_ENC_RSP" },
	{ 0x0C, "LL_VERSION_IND" },
	{ 0x0D, "LL_REJECT_IND" },
	{ 0, NULL }
};

static const guint32 ADV_AA = 0x8e89bed6;

/* initialize the subtree pointers */
static gint ett_btle = -1;
static gint ett_btle_pkthdr = -1;
static gint ett_btle_connect = -1;
static gint ett_btle_data = -1;
static gint ett_ll_enc_req = -1;
static gint ett_ll_enc_rsp = -1;

/* subdissectors */
static dissector_handle_t btl2cap_handle = NULL;

void
dissect_adv_ind_or_nonconn_or_scan(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int offset, int datalen)
{
	const guint8 *adv_addr;

	DISSECTOR_ASSERT(tvb_length_remaining(tvb, offset) >= 1);

	adv_addr = tvb_get_ptr(tvb, offset, 6);
	SET_ADDRESS(&pinfo->src, AT_ETHER, 6, adv_addr);

	proto_tree_add_ether(tree, hf_btle_adv_addr, tvb, offset, 6, adv_addr);
	proto_tree_add_item(tree, hf_btle_adv_data, tvb, offset + 6, datalen, TRUE);
}

void
dissect_adv_direct_ind(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int offset)
{
	const guint8 *adv_addr, *init_addr;

	DISSECTOR_ASSERT(tvb_length_remaining(tvb, offset) >= 1);

	adv_addr = tvb_get_ptr(tvb, offset, 6);
	SET_ADDRESS(&pinfo->src, AT_ETHER, 6, adv_addr);
	init_addr = tvb_get_ptr(tvb, offset+6, 6);
	SET_ADDRESS(&pinfo->dst, AT_ETHER, 6, init_addr);

	proto_tree_add_ether(tree, hf_btle_adv_addr, tvb, offset, 6, adv_addr);
	proto_tree_add_ether(tree, hf_btle_init_addr, tvb, offset + 6, 6, init_addr);
}

void
dissect_scan_req(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int offset)
{
	const guint8 *scan_addr, *adv_addr;

	DISSECTOR_ASSERT(tvb_length_remaining(tvb, offset) >= 1);

	scan_addr = tvb_get_ptr(tvb, offset, 6);
	SET_ADDRESS(&pinfo->src, AT_ETHER, 6, scan_addr);
	adv_addr = tvb_get_ptr(tvb, offset+6, 6);
	SET_ADDRESS(&pinfo->dst, AT_ETHER, 6, adv_addr);

	proto_tree_add_ether(tree, hf_btle_scan_addr, tvb, offset, 6, scan_addr);
	proto_tree_add_ether(tree, hf_btle_adv_addr, tvb, offset+6, 6, adv_addr);
}

void
dissect_scan_rsp(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int offset, int datalen)
{
	const guint8 *adv_addr;

	DISSECTOR_ASSERT(tvb_length_remaining(tvb, offset) >= 1);

	adv_addr = tvb_get_ptr(tvb, offset, 6);
	SET_ADDRESS(&pinfo->src, AT_ETHER, 6, adv_addr);

	proto_tree_add_ether(tree, hf_btle_adv_addr, tvb, offset, 6, adv_addr);
	proto_tree_add_item(tree, hf_btle_scan_rsp_data, tvb, offset + 6, datalen, TRUE);
}

void
dissect_connect_req(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int offset)
{
	proto_item *connect_item;
	proto_tree *connect_tree;
	const guint8 *adv_addr, *init_addr;


	DISSECTOR_ASSERT(tvb_length_remaining(tvb, offset) >= 1);

	init_addr = tvb_get_ptr(tvb, offset, 6);
	SET_ADDRESS(&pinfo->src, AT_ETHER, 6, init_addr);
	adv_addr = tvb_get_ptr(tvb, offset+6, 6);
	SET_ADDRESS(&pinfo->dst, AT_ETHER, 6, adv_addr);

	proto_tree_add_ether(tree, hf_btle_init_addr, tvb, offset, 6, init_addr);
	proto_tree_add_ether(tree, hf_btle_adv_addr, tvb, offset + 6, 6, adv_addr);
	offset += 12;

	connect_item = proto_tree_add_item(tree, hf_btle_connect, tvb, offset, 22, TRUE);
	connect_tree = proto_item_add_subtree(connect_item, ett_btle_connect);

	proto_tree_add_item(connect_tree, hf_btle_connect_aa,	tvb, offset+ 0, 4, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(connect_tree, hf_btle_crc_init,		tvb, offset+ 4, 3, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(connect_tree, hf_btle_win_size,		tvb, offset+ 7, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(connect_tree, hf_btle_win_offset,	tvb, offset+ 8, 2, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(connect_tree, hf_btle_interval,		tvb, offset+10, 2, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(connect_tree, hf_btle_latency,		tvb, offset+12, 2, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(connect_tree, hf_btle_timeout,		tvb, offset+14, 2, ENC_LITTLE_ENDIAN);
}

void
dissect_ll_enc_req(proto_tree *tree, tvbuff_t *tvb, int offset)
{
	proto_item *ll_enc_req_item;
	proto_tree *ll_enc_req_tree;

	ll_enc_req_item = proto_tree_add_item(tree, hf_btle_ll_control_ll_enc_req, tvb, offset + 1, 22, TRUE);
	ll_enc_req_tree = proto_item_add_subtree(ll_enc_req_item, ett_ll_enc_req);

	proto_tree_add_item(ll_enc_req_tree, hf_btle_ll_control_ll_enc_req_rand, tvb, offset + 1,  8, TRUE);
	proto_tree_add_item(ll_enc_req_tree, hf_btle_ll_control_ll_enc_req_ediv, tvb, offset + 9,  2, TRUE);
	proto_tree_add_item(ll_enc_req_tree, hf_btle_ll_control_ll_enc_req_skdm, tvb, offset + 11, 8, TRUE);
	proto_tree_add_item(ll_enc_req_tree, hf_btle_ll_control_ll_enc_req_ivm,  tvb, offset + 19, 4, TRUE);
}

void
dissect_ll_enc_rsp(proto_tree *tree, tvbuff_t *tvb, int offset)
{
	proto_item *ll_enc_rsp_item;
	proto_tree *ll_enc_rsp_tree;

	ll_enc_rsp_item = proto_tree_add_item(tree, hf_btle_ll_control_ll_enc_rsp, tvb, offset + 1, 12, TRUE);
	ll_enc_rsp_tree = proto_item_add_subtree(ll_enc_rsp_item, ett_ll_enc_rsp);

	proto_tree_add_item(ll_enc_rsp_tree, hf_btle_ll_control_ll_enc_rsp_skds, tvb, offset + 1, 8, TRUE);
	proto_tree_add_item(ll_enc_rsp_tree, hf_btle_ll_control_ll_enc_rsp_ivs,  tvb, offset + 9, 4, TRUE);
}

void
dissect_ll_control(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int offset, guint8 length)
{
	guint8 ll_control_opcode;

	proto_tree_add_item(tree, hf_btle_ll_control_opcode, tvb, offset, 1, ENC_NA);

	ll_control_opcode = tvb_get_guint8(tvb, offset);
	if (ll_control_opcode <= 0x0d) {
		col_add_fstr(pinfo->cinfo, COL_INFO, "LL Control PDU: %s",
				ll_control_opcodes[ll_control_opcode].strptr);

		switch (ll_control_opcode) {
			case 0x03: // LL_ENC_REQ
				dissect_ll_enc_req(tree, tvb, offset);
				break;
			case 0x04: // LL_ENC_RSP
				dissect_ll_enc_rsp(tree, tvb, offset);
				break;
			default:
				if (length > 1)
					proto_tree_add_item(tree, hf_btle_ll_control_data, tvb, offset + 1, length-1, TRUE);
				break;
		}
	} else {
		col_set_str(pinfo->cinfo, COL_INFO, "LL Control PDU: unknown");
		if (length > 1)
			proto_tree_add_item(tree, hf_btle_ll_control_data, tvb, offset + 1, length-1, TRUE);
	}
}

/* dissect a packet */
static void
dissect_btle(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item *btle_item, *pkthdr_item, *data_item;
	proto_tree *btle_tree, *pkthdr_tree, *data_tree;
	int offset;
	guint32 aa;
	guint8 type, length;
	guint8 llid;
	tvbuff_t *pld_tvb;

	/*
	 * FIXME
	 * I have no idea what this does, but the L2CAP dissector segfaults
	 * without it.
	 */
	guint16 fake_acl_data;

#if 0
	/* sanity check: length */
	if (tvb_length(tvb) > 0 && tvb_length(tvb) < 9)
		/* bad length: look for a different dissector */
		return 0;
#endif

	/* make entries in protocol column and info column on summary display */
	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "Bluetooth LE");

	aa = tvb_get_letohl(tvb, 0);

	// advertising packet
	if (aa == ADV_AA) {
		type = tvb_get_guint8(tvb, 4) & 0xf;
		length = tvb_get_guint8(tvb, 5) & 0x3f;

		/* see if we are being asked for details */
		if (tree) {

			/* create display subtree for the protocol */
			offset = 0;
			btle_item = proto_tree_add_item(tree, proto_btle, tvb, offset, -1, TRUE);
			btle_tree = proto_item_add_subtree(btle_item, ett_btle);

			proto_tree_add_item(btle_tree, hf_btle_aa, tvb, offset, 4, TRUE);
			offset += 4;

			/* packet header */
			pkthdr_item = proto_tree_add_item(btle_tree, hf_btle_pkthdr, tvb, offset, 2, ENC_LITTLE_ENDIAN);
			pkthdr_tree = proto_item_add_subtree(pkthdr_item, ett_btle_pkthdr);

			proto_tree_add_bits_item(pkthdr_tree, hf_btle_randomized_rx, tvb, offset * 8, 1, TRUE);
			proto_tree_add_bits_item(pkthdr_tree, hf_btle_randomized_tx, tvb, offset * 8 + 1, 1, TRUE);
			proto_tree_add_bits_item(pkthdr_tree, hf_btle_type, tvb, offset * 8 + 4, 4, TRUE);
			offset += 1;

			proto_tree_add_item(pkthdr_tree, hf_btle_length, tvb, offset, 1, TRUE);
			offset += 1;

			if (check_col(pinfo->cinfo, COL_INFO)) {
				if (type <= 0x6) {
					col_set_str(pinfo->cinfo, COL_INFO, packet_types[type].strptr);
				} else {
					col_set_str(pinfo->cinfo, COL_INFO, "Unknown");
				}
			}

			/* payload */
			switch (type) {
			case 0x0: // ADV_IND
			case 0x2: // ADV_NONCONN_IND
			case 0x6: // ADV_SCAN_IND
				dissect_adv_ind_or_nonconn_or_scan(btle_tree, tvb, pinfo, offset, length - 6);
				break;
			case 0x1: // ADV_DIRECT_IND
				dissect_adv_direct_ind(btle_tree, tvb, pinfo, offset);
				break;
			case 0x3:
				dissect_scan_req(btle_tree, tvb, pinfo, offset);
				break;
			case 0x4: // SCAN_RSP
				dissect_scan_rsp(btle_tree, tvb, pinfo, offset, length - 6);
				break;
			case 0x5: // CONNECT_REQ
				dissect_connect_req(btle_tree, tvb, pinfo, offset);
				break;
			default:
				break;
			}

			offset += length;
			proto_tree_add_item(btle_tree, hf_btle_crc, tvb, offset, 3, TRUE);
		}
	}

	// data PDU
	else {
		if (tree) {
			col_set_str(pinfo->cinfo, COL_INFO, "Data");

			length = tvb_get_guint8(tvb, 5) & 0x1f;

			/* create display subtree for the protocol */
			offset = 0;
			btle_item = proto_tree_add_item(tree, proto_btle, tvb, offset, -1, TRUE);
			btle_tree = proto_item_add_subtree(btle_item, ett_btle);

			proto_tree_add_item(btle_tree, hf_btle_aa, tvb, offset, 4, TRUE);
			offset += 4;

			// data PDU header
			data_item = proto_tree_add_item(btle_tree, hf_btle_data, tvb, offset, 2, TRUE);
			data_tree = proto_item_add_subtree(data_item, ett_btle_data);

			proto_tree_add_item(data_tree, hf_btle_data_rfu, tvb, offset, 1, ENC_NA);
			proto_tree_add_item(data_tree, hf_btle_data_md, tvb, offset, 1, ENC_NA);
			proto_tree_add_item(data_tree, hf_btle_data_sn, tvb, offset, 1, ENC_NA);
			proto_tree_add_item(data_tree, hf_btle_data_nesn, tvb, offset, 1, ENC_NA);
			proto_tree_add_item(data_tree, hf_btle_data_llid, tvb, offset, 1, ENC_NA);
			llid = tvb_get_guint8(tvb, offset) & 0x3;
			offset += 1;

			proto_tree_add_item(data_tree, hf_btle_length, tvb, offset, 1, TRUE);
			offset += 1;

			// LL control PDU
			if (llid == 0x3) {
				dissect_ll_control(btle_tree, tvb, pinfo, offset, length);
			}

			// L2CAP
			else if (llid == 0x1 || llid == 0x2) {
				if (length > 0 && btl2cap_handle) {
					pinfo->private_data = &fake_acl_data;
					pld_tvb = tvb_new_subset(tvb, offset, length, length);
					call_dissector(btl2cap_handle, pld_tvb, pinfo, btle_tree);
				}
				else if (length == 0) {
					col_set_str(pinfo->cinfo, COL_INFO, "Empty Data PDU");
				}
			}

			offset += length;

			proto_tree_add_item(btle_tree, hf_btle_crc, tvb, offset, 3, TRUE);
		}
	}

	return;
}

/* register the protocol with Wireshark */
void
proto_register_btle(void)
{

	/* list of fields */
	static hf_register_info hf[] = {
		{ &hf_btle_aa,
			{ "Access Address", "btle.aa",
			FT_UINT32, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},

		{ &hf_btle_pkthdr,
			{ "Packet Header", "btle.pkthdr",
			FT_NONE, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},

		{ &hf_btle_type,
			{ "TYPE", "btle.type",
			FT_UINT8, BASE_HEX, VALS(packet_types), 0x0,
			"Packet Type", HFILL }
		},
		{ &hf_btle_randomized_tx,
			{ "Randomized TX Address", "btle.randomized_tx",
			FT_BOOLEAN, BASE_NONE, TFS(&tfs_yes_no), 0x0,
			NULL, HFILL }
		},
		{ &hf_btle_randomized_rx,
			{ "Randomized RX Address", "btle.randomized_rx",
			FT_BOOLEAN, BASE_NONE, TFS(&tfs_yes_no), 0x0,
			NULL, HFILL }
		},
		{ &hf_btle_length,
			{ "Length", "btle.length",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_btle_adv_addr,
			{ "Advertising Address", "btle.adv_addr",
			FT_ETHER, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_btle_init_addr,
			{ "Init Address", "btle.init_addr",
			FT_ETHER, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_btle_scan_addr,
			{ "Scan Address", "btle.scan_addr",
			FT_ETHER, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_btle_adv_data,
			{ "Advertising Data", "btle.adv_data",
			FT_BYTES, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_btle_scan_rsp_data,
			{ "Scan Response Data", "btle.scan_rsp_data",
			FT_BYTES, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},

		// connection packet fields
		{ &hf_btle_connect,
			{ "Connection Request", "btle.connect",
			FT_NONE, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_btle_connect_aa,
			{ "Connection AA", "btle.connect.aa",
			FT_UINT32, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_btle_crc_init,
			{ "CRC Init", "btle.connect.crc_init",
			FT_UINT24, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_btle_win_size,
			{ "Window Size", "btle.connect.win_size",
			FT_UINT8, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_btle_win_offset,
			{ "Window Offset", "btle.connect.win_offset",
			FT_UINT16, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_btle_interval,
			{ "Interval", "btle.connect.interval",
			FT_UINT16, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_btle_latency,
			{ "Latency", "btle.connect.latency",
			FT_UINT16, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_btle_timeout,
			{ "Timeout", "btle.connect.timeout",
			FT_UINT16, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},

		// data header
		{ &hf_btle_data,
			{ "Data PDU Header", "btle.data",
			FT_UINT16, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_btle_data_llid,
			{ "LLID", "btle.data.llid",
			FT_UINT8, BASE_DEC, VALS(llid_codes), 0x3,
			NULL, HFILL }
		},
		{ &hf_btle_data_nesn,
			{ "NESN", "btle.data.nesn",
			FT_UINT8, BASE_DEC, NULL, 0x4,
			"Next Expected Sequence Number", HFILL }
		},
		{ &hf_btle_data_sn,
			{ "SN", "btle.data.sn",
			FT_UINT8, BASE_DEC, NULL, 0x8,
			"Sequence Number", HFILL }
		},
		{ &hf_btle_data_md,
			{ "MD", "btle.data.md",
			FT_UINT8, BASE_DEC, NULL, 0x10,
			"More Data", HFILL }
		},
		{ &hf_btle_data_rfu,
			{ "RFU", "btle.data.rfu",
			FT_UINT8, BASE_DEC, NULL, 0xe0,
			"Reserved for Future Use (must be zero)", HFILL }
		},

		{ &hf_btle_ll_control_opcode,
			{ "LL Control Opcode", "btle.ll_control_opcode",
			FT_UINT8, BASE_HEX, VALS(ll_control_opcodes), 0x0,
			NULL, HFILL }
		},
		{ &hf_btle_ll_control_data,
			{ "LL Control Data", "btle.ll_control_data",
			FT_BYTES, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},

		{ &hf_btle_ll_control_ll_enc_req,
			{ "Encryption Request", "btle.ll_enc_req",
			FT_NONE, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_btle_ll_control_ll_enc_req_rand,
			{ "Rand", "btle.ll_enc_req.rand",
			FT_BYTES, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_btle_ll_control_ll_enc_req_ediv,
			{ "EDIV", "btle.ll_enc_req.ediv",
			FT_BYTES, BASE_NONE, NULL, 0x0,
			"Encrypted Diversifier", HFILL }
		},
		{ &hf_btle_ll_control_ll_enc_req_skdm,
			{ "SDKm", "btle.ll_enc_req.skdm",
			FT_BYTES, BASE_NONE, NULL, 0x0,
			"Master's Session Key Identifier", HFILL }
		},
		{ &hf_btle_ll_control_ll_enc_req_ivm,
			{ "IVm", "btle.ll_enc_req.ivm",
			FT_BYTES, BASE_NONE, NULL, 0x0,
			"Master's Initialization Vector", HFILL }
		},

		{ &hf_btle_ll_control_ll_enc_rsp,
			{ "Encryption Response", "btle.ll_enc_rsp",
			FT_NONE, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_btle_ll_control_ll_enc_rsp_skds,
			{ "SDKs", "btle.ll_enc_rsp.skds",
			FT_BYTES, BASE_NONE, NULL, 0x0,
			"Slave's Session Key Identifier", HFILL }
		},
		{ &hf_btle_ll_control_ll_enc_rsp_ivs,
			{ "IVs", "btle.ll_enc_rsp.ivs",
			FT_BYTES, BASE_NONE, NULL, 0x0,
			"Slave's Initialization Vector", HFILL }
		},


		{ &hf_btle_crc,
			{ "CRC", "btle.crc",
			FT_UINT24, BASE_HEX, NULL, 0x0,
			"Ticklish Redundancy Check", HFILL }
		},
	};

	/* protocol subtree arrays */
	static gint *ett[] = {
		&ett_btle,
		&ett_btle_pkthdr,
		&ett_btle_connect,
		&ett_btle_data,
		&ett_ll_enc_req,
		&ett_ll_enc_rsp,
	};

	/* register the protocol name and description */
	proto_btle = proto_register_protocol(
		"Bluetooth Low Energy",	/* full name */
		"BTLE",			/* short name */
		"btle"			/* abbreviation (e.g. for filters) */
		);

	register_dissector("btle", dissect_btle, proto_btle);

	/* register the header fields and subtrees used */
	proto_register_field_array(proto_btle, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_btle(void)
{
	static gboolean inited = FALSE;

	if (!inited) {
		dissector_handle_t btle_handle;

		// btle_handle = new_create_dissector_handle(dissect_btle, proto_btle);
		// dissector_add("ppi.dlt", 147, btle_handle);

		btl2cap_handle = find_dissector("btl2cap");

		inited = TRUE;
	}
}
