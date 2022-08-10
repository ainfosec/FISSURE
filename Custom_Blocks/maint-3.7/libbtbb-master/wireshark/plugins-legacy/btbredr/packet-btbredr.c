/* packet-btbredr.c
 * Routines for Bluetooth baseband dissection
 * Copyright 2014, Dominic Spill <dominicgs@gmail.com>
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

#include <epan/packet.h>
#include <epan/prefs.h>

#include <stdio.h>

/* function prototypes */
void proto_reg_handoff_btbredr(void);

/* initialize the protocol and registered fields */
static int proto_btbredr = -1;
static int hf_btbredr_meta = -1;
static int hf_btbredr_channel = -1;
static int hf_btbredr_signal = -1;
static int hf_btbredr_noise = -1;
static int hf_btbredr_ac_offenses = -1;
static int hf_btbredr_mod = -1;
static int hf_btbredr_transport = -1;
static int hf_btbredr_corrected_header = -1;
static int hf_btbredr_corrected_payload = -1;
static int hf_btbredr_lap = -1;
static int hf_btbredr_ref_lap = -1;
static int hf_btbredr_ref_uap = -1;
static int hf_btbredr_pkthdr = -1;
static int hf_btbredr_ltaddr = -1;
static int hf_btbredr_type = -1;
static int hf_btbredr_flags = -1;
static int hf_btbredr_flow = -1;
static int hf_btbredr_arqn = -1;
static int hf_btbredr_seqn = -1;
static int hf_btbredr_hec = -1;
static int hf_btbredr_payload = -1;
static int hf_btbredr_pldhdr = -1;
static int hf_btbredr_llid = -1;
static int hf_btbredr_pldflow = -1;
static int hf_btbredr_length = -1;
static int hf_btbredr_pldbody = -1;
static int hf_btbredr_crc = -1;
static int hf_btbredr_fhs_parity = -1;
static int hf_btbredr_fhs_lap = -1;
static int hf_btbredr_fhs_eir = -1;
static int hf_btbredr_fhs_sr = -1;
static int hf_btbredr_fhs_uap = -1;
static int hf_btbredr_fhs_nap = -1;
static int hf_btbredr_fhs_class = -1;
static int hf_btbredr_fhs_ltaddr = -1;
static int hf_btbredr_fhs_clk = -1;
static int hf_btbredr_fhs_psmode = -1;

/* field values */
static const true_false_string direction = {
	"Slave to Master",
	"Master to Slave"
};

static const true_false_string clock_bits = {
	"27",
	"6"
};

static const true_false_string valid_flags = {
	"Invalid",
	"Valid"
};

static const value_string modulation[] = {
    { 0x0, "Basic Rate (GFSK)" },
    { 0x1, "Enhanced Data Rate (PI/2-DQPSK)" },
    { 0x2, "Enhanced Data Rate (8DPSK)" }
};

static const value_string transports[] = {
    { 0x0, "unknown" },
    { 0x1, "SCO" },
    { 0x2, "eSCO" },
    { 0x3, "ACL" },
    { 0x4, "CSB" }
};

static const value_string packet_types[] = {
	/* generic names for unknown logical transport */
	{ 0x0, "NULL" },
	{ 0x1, "POLL" },
	{ 0x2, "FHS" },
	{ 0x3, "DM1" },
	{ 0x4, "DH1/2-DH1" },
	{ 0x5, "HV1" },
	{ 0x6, "HV2/2-EV3" },
	{ 0x7, "HV3/EV3/3-EV3" },
	{ 0x8, "DV/3-DH1" },
	{ 0x9, "AUX1" },
	{ 0xa, "DM3/2-DH3" },
	{ 0xb, "DH3/3-DH3" },
	{ 0xc, "EV4/2-EV5" },
	{ 0xd, "EV5/3-EV5" },
	{ 0xe, "DM5/2-DH5" },
	{ 0xf, "DH5/3-DH5" },
	{ 0, NULL }
};

static const value_string sr_modes[] = {
	{ 0x0, "R0" },
	{ 0x1, "R1" },
	{ 0x2, "R2" },
	{ 0x3, "Reserved" },
	{ 0, NULL }
};

static const range_string ps_modes[] = {
	{ 0x0, 0x0, "Mandatory scan mode" },
	{ 0x1, 0x7, "Reserved" },
	{ 0, 0, NULL }
};

static const value_string llid_codes[] = {
	{ 0x0, "undefined" },
	{ 0x1, "Continuation fragment of an L2CAP message (ACL-U)" },
	{ 0x2, "Start of an L2CAP message or no fragmentation (ACL-U)" },
	{ 0x3, "LMP message (ACL-C)" },
	{ 0, NULL }
};

/* initialize the subtree pointers */
static gint ett_btbredr = -1;
static gint ett_btbredr_meta = -1;
static gint ett_btbredr_pkthdr = -1;
static gint ett_btbredr_flags = -1;
static gint ett_btbredr_payload = -1;
static gint ett_btbredr_pldhdr = -1;

/* subdissectors */
static dissector_handle_t btlmp_handle = NULL;
static dissector_handle_t btl2cap_handle = NULL;

/* packet header flags */
static const int *flag_fields[] = {
	&hf_btbredr_flow,
	&hf_btbredr_arqn,
	&hf_btbredr_seqn,
	NULL
};

/* one byte payload header */
int
dissect_payload_header1(proto_tree *tree, tvbuff_t *tvb, int offset)
{
	proto_item *hdr_item;
	proto_tree *hdr_tree;

	DISSECTOR_ASSERT(tvb_length_remaining(tvb, offset) >= 1);

	hdr_item = proto_tree_add_item(tree, hf_btbredr_pldhdr, tvb, offset, 1, ENC_NA);
	hdr_tree = proto_item_add_subtree(hdr_item, ett_btbredr_pldhdr);

	proto_tree_add_item(hdr_tree, hf_btbredr_llid, tvb, offset, 1, ENC_NA);
	proto_tree_add_item(hdr_tree, hf_btbredr_pldflow, tvb, offset, 1, ENC_NA);
	proto_tree_add_item(hdr_tree, hf_btbredr_length, tvb, offset, 1, ENC_NA);

	/* payload length */
	return tvb_get_guint8(tvb, offset) >> 3;
}

void
dissect_fhs(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int offset)
{
	proto_item *fhs_item, *psmode_item;
	proto_tree *fhs_tree;
    const gchar *description;
	guint8 psmode;

	if(tvb_length_remaining(tvb, offset) != 20) {
		col_add_str(pinfo->cinfo, COL_INFO, "Encrypted or malformed payload data");
		return;
	}

	fhs_item = proto_tree_add_item(tree, hf_btbredr_payload, tvb, offset, -1, ENC_NA);
	fhs_tree = proto_item_add_subtree(fhs_item, ett_btbredr_payload);

	/* Use proto_tree_add_bits_item() to get around 32bit limit on bitmasks */
	proto_tree_add_bits_item(fhs_tree, hf_btbredr_fhs_parity, tvb, offset*8, 34, ENC_LITTLE_ENDIAN);
	/* proto_tree_add_item(fhs_tree, hf_btbredr_fhs_parity, tvb, offset, 5, ENC_LITTLE_ENDIAN); */
	offset += 4;

	proto_tree_add_item(fhs_tree, hf_btbredr_fhs_lap, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 3;

	proto_tree_add_item(fhs_tree, hf_btbredr_fhs_eir, tvb, offset, 1, ENC_NA);
	/* skipping 1 undefined bit */
	proto_tree_add_item(fhs_tree, hf_btbredr_fhs_sr, tvb, offset, 1, ENC_NA);
	/* skipping 2 reserved bits */
	offset += 1;

	proto_tree_add_item(fhs_tree, hf_btbredr_fhs_uap, tvb, offset, 1, ENC_NA);
	offset += 1;

	proto_tree_add_item(fhs_tree, hf_btbredr_fhs_nap, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;

	proto_tree_add_item(fhs_tree, hf_btbredr_fhs_class, tvb, offset, 3, ENC_LITTLE_ENDIAN);
	offset += 3;

	proto_tree_add_item(fhs_tree, hf_btbredr_fhs_ltaddr, tvb, offset, 1, ENC_NA);
	proto_tree_add_item(fhs_tree, hf_btbredr_fhs_clk, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 3;

	psmode = tvb_get_guint8(tvb, offset);
	description = try_rval_to_str(psmode, ps_modes);
	psmode_item = proto_tree_add_item(fhs_tree, hf_btbredr_fhs_psmode, tvb, offset, 1, ENC_NA);
	if (description)
        proto_item_append_text(psmode_item, " (%s)", description);
	offset += 1;

	proto_tree_add_item(fhs_tree, hf_btbredr_crc, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;
}

void
dissect_dm1(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int offset)
{
	int len;	/* payload length indicated by payload header */
	int llid;	/* logical link id */
	int l2len;	/* length indicated by l2cap header */
	proto_item *dm1_item;
	proto_tree *dm1_tree;
	tvbuff_t *pld_tvb;

	/*
	 * FIXME
	 * I'm probably doing a terrible, terrible thing here, but it gets my
	 * initial test cases working.
	 */
	guint16 fake_acl_data;

	if(tvb_length_remaining(tvb, offset) < 3) {
		col_add_str(pinfo->cinfo, COL_INFO, "Encrypted or malformed payload data");
		return;
	}

	dm1_item = proto_tree_add_item(tree, hf_btbredr_payload, tvb, offset, -1, ENC_NA);
	dm1_tree = proto_item_add_subtree(dm1_item, ett_btbredr_payload);

	len = dissect_payload_header1(dm1_tree, tvb, offset);
	llid = tvb_get_guint8(tvb, offset) & 0x3;
	offset += 1;

	if(tvb_length_remaining(tvb, offset) < len + 2) {
		col_add_str(pinfo->cinfo, COL_INFO, "Encrypted or malformed payload data");
		return;
	}
	
	if (llid == 3 && btlmp_handle) {
		/* LMP */
		pld_tvb = tvb_new_subset(tvb, offset, len, len);
		call_dissector(btlmp_handle, pld_tvb, pinfo, dm1_tree);
	} else if (llid == 2 && btl2cap_handle) {
		/* unfragmented L2CAP or start of fragment */
		l2len = tvb_get_letohs(tvb, offset);
		if (l2len + 4 == len) {
			/* unfragmented */
			pinfo->private_data = &fake_acl_data;
			pld_tvb = tvb_new_subset(tvb, offset, len, len);
			call_dissector(btl2cap_handle, pld_tvb, pinfo, dm1_tree);
		} else {
			/* start of fragment */
			proto_tree_add_item(dm1_tree, hf_btbredr_pldbody, tvb, offset, len, ENC_NA);
		}
	} else {
		proto_tree_add_item(dm1_tree, hf_btbredr_pldbody, tvb, offset, len, ENC_NA);
	}
	offset += len;

	proto_tree_add_item(dm1_tree, hf_btbredr_crc, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;
}

/* dissect a packet */
static int
dissect_btbredr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	proto_item *btbredr_item, *meta_item, *pkthdr_item;
	proto_tree *btbredr_tree, *meta_tree, *pkthdr_tree;
	int offset;
	/* Avoid error: 'type' may be used uninitialized in this function */
	guint8 type = 0xff;
	const gchar *info;

	/* sanity check: length */
	if (tvb_length(tvb) > 0 && tvb_length(tvb) < 9)
		/* bad length: look for a different dissector */
		return 0;

	/* maybe should verify HEC */

	/* make entries in protocol column and info column on summary display */
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "Bluetooth");

	if (tvb_length(tvb) == 0) {
		info = "ID";
	} else {
		type = (tvb_get_guint8(tvb, 16) >> 3) & 0x0f;
		info = val_to_str(type, packet_types, "Unknown type: 0x%x");
	}

	col_clear(pinfo->cinfo, COL_INFO);
	col_add_str(pinfo->cinfo, COL_INFO, info);

	/* see if we are being asked for details */
	if (tree) {

		/* create display subtree for the protocol */
		offset = 0;
		btbredr_item = proto_tree_add_item(tree, proto_btbredr, tvb, offset, -1, ENC_NA);
		btbredr_tree = proto_item_add_subtree(btbredr_item, ett_btbredr);

		/* ID packets have no header, no payload */
		if (tvb_length(tvb) == 0)
			return 1;

		/* meta data */
		meta_item = proto_tree_add_item(btbredr_tree, hf_btbredr_meta, tvb, offset, 3, ENC_NA);
		meta_tree = proto_item_add_subtree(meta_item, ett_btbredr_meta);

		proto_tree_add_item(meta_tree, hf_btbredr_channel, tvb, offset, 1, ENC_NA);
		offset += 1;
		proto_tree_add_item(meta_tree, hf_btbredr_signal, tvb, offset, 1, ENC_NA);
		offset += 1;
		proto_tree_add_item(meta_tree, hf_btbredr_noise, tvb, offset, 1, ENC_NA);
		offset += 1;
		proto_tree_add_item(meta_tree, hf_btbredr_ac_offenses, tvb, offset, 1, ENC_NA);
		offset += 1;
		
		proto_tree_add_item(meta_tree, hf_btbredr_mod, tvb, offset, 1, ENC_NA);
		proto_tree_add_item(meta_tree, hf_btbredr_transport, tvb, offset, 1, ENC_NA);
		offset += 1;
		
		proto_tree_add_item(meta_tree, hf_btbredr_corrected_header, tvb, offset, 1, ENC_NA);
		offset += 1;
		proto_tree_add_item(meta_tree, hf_btbredr_corrected_payload, tvb, offset, 2, ENC_LITTLE_ENDIAN);
		offset += 2;
		
		proto_tree_add_item(meta_tree, hf_btbredr_lap, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;
		proto_tree_add_item(meta_tree, hf_btbredr_ref_lap, tvb, offset, 3, ENC_LITTLE_ENDIAN);
		offset += 3;
		proto_tree_add_item(meta_tree, hf_btbredr_ref_uap, tvb, offset, 1, ENC_NA);
		offset += 1;


		/* packet header */
		pkthdr_item = proto_tree_add_item(btbredr_tree, hf_btbredr_pkthdr, tvb, offset, 3, ENC_NA);
		pkthdr_tree = proto_item_add_subtree(pkthdr_item, ett_btbredr_pkthdr);

		proto_tree_add_item(pkthdr_tree, hf_btbredr_ltaddr, tvb, offset, 1, ENC_NA);
		proto_tree_add_item(pkthdr_tree, hf_btbredr_type, tvb, offset, 1, ENC_NA);
		offset += 1;
		proto_tree_add_bitmask(pkthdr_tree, tvb, offset, hf_btbredr_flags,
			ett_btbredr_flags, flag_fields, ENC_NA);
		offset += 1;
		proto_tree_add_item(pkthdr_tree, hf_btbredr_hec, tvb, offset, 1, ENC_NA);
		offset += 2;

		/* payload */
		switch (type) {
		case 0x0: /* NULL */
		case 0x1: /* POLL */
			break;
		case 0x2: /* FHS */
			dissect_fhs(btbredr_tree, tvb, pinfo, offset);
			break;
		case 0x3: /* DM1 */
			dissect_dm1(btbredr_tree, tvb, pinfo, offset);
			break;
		case 0x4: /* DH1/2-DH1 */
			dissect_dm1(btbredr_tree, tvb, pinfo, offset);
			break;
		case 0x5: /* HV1 */
		case 0x6: /* HV2/2-EV3 */
		case 0x7: /* HV3/EV3/3-EV3 */
		case 0x8: /* DV/3-DH1 */
		case 0x9: /* AUX1 */
		case 0xa: /* DM3/2-DH3 */
		case 0xb: /* DH3/3-DH3 */
		case 0xc: /* EV4/2-EV5 */
		case 0xd: /* EV5/3-EV5 */
		case 0xe: /* DM5/2-DH5 */
		case 0xf: /* DH5/3-DH5 */
			proto_tree_add_item(btbredr_tree, hf_btbredr_payload, tvb, offset, -1, ENC_NA);
			break;
		default:
			break;
		}
	}

	/* Return the amount of data this dissector was able to dissect */
	return tvb_length(tvb);
}

/* register the protocol with Wireshark */
void
proto_register_btbredr(void)
{
	/* list of fields */
	static hf_register_info hf[] = {
		{ &hf_btbredr_meta,
			{ "Meta Data", "btbredr.meta",
			FT_NONE, BASE_NONE, NULL, 0x0,
			"Meta Data About the Packet", HFILL }
		}, 
		{ &hf_btbredr_channel,
			{ "Channel", "btbredr.channel",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"Channel (0-78)", HFILL }
		},
		{ &hf_btbredr_signal,
			{ "Signal", "btbredr.signal",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"Signal Power", HFILL }
		},
		{ &hf_btbredr_noise,
			{ "Noise", "btbredr.noise",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"Noise Power", HFILL }
		},
		{ &hf_btbredr_ac_offenses,
			{ "AC Offenses", "btbredr.ac_offenses",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"Access Code Offenses", HFILL }
		},
		{ &hf_btbredr_mod,
			{ "Transport Rate", "btbredr.mod",
			FT_UINT8, BASE_HEX, VALS(&modulation), 0x02,
			"Transport Data Rate", HFILL }
		},
		{ &hf_btbredr_transport,
			{ "Transport", "btbredr.transport",
			FT_UINT8, BASE_HEX, VALS(&transports), 0x70,
			"Logical Transport", HFILL }
		},
		{ &hf_btbredr_corrected_header,
			{ "Corrected Header", "btbredr.corrected_header",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"Corrected Header Bits", HFILL }
		},
		{ &hf_btbredr_corrected_payload,
			{ "Corrected Payload", "btbredr.corrected_payload",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"Corrected Payload Bits", HFILL }
		},
		{ &hf_btbredr_lap,
			{ "LAP", "btbredr.lap",
			FT_UINT32, BASE_HEX, NULL, 0x0,
			"Lower Address Part", HFILL }
		},
		{ &hf_btbredr_ref_lap,
			{ "Ref. LAP", "btbredr.ref_lap",
			FT_UINT32, BASE_HEX, NULL, 0x0,
			"Reference LAP", HFILL }
		},
		{ &hf_btbredr_ref_uap,
			{ "Ref. UAP", "btbredr.ref_uap",
			FT_UINT8, BASE_HEX, NULL, 0x0,
			"Reference UAP", HFILL }
		},
		{ &hf_btbredr_pkthdr,
			{ "Packet Header", "btbredr.pkthdr",
			FT_NONE, BASE_NONE, NULL, 0x0,
			"Bluetooth Baseband Packet Header", HFILL }
		},
		{ &hf_btbredr_ltaddr,
			{ "LT_ADDR", "btbredr.lt_addr",
			FT_UINT8, BASE_HEX, NULL, 0x07,
			"Logical Transport Address", HFILL }
		},
		{ &hf_btbredr_type,
			{ "TYPE", "btbredr.type",
			FT_UINT8, BASE_HEX, VALS(packet_types), 0x78,
			"Packet Type", HFILL }
		},
		{ &hf_btbredr_flags,
			{ "Flags", "btbredr.flags",
			FT_UINT8, BASE_HEX, NULL, 0x0,
			"Packet Header Flags", HFILL }
		},
		{ &hf_btbredr_flow,
			{ "FLOW", "btbredr.flow",
			FT_BOOLEAN, 8, NULL, 0x01,
			"Flow control indication", HFILL }
		},
		{ &hf_btbredr_arqn,
			{ "ARQN", "btbredr.arqn",
			FT_BOOLEAN, 8, NULL, 0x02,
			"Acknowledgment indication", HFILL }
		},
		{ &hf_btbredr_seqn,
			{ "SEQN", "btbredr.seqn",
			FT_BOOLEAN, 8, NULL, 0x04,
			"Sequence number", HFILL }
		},
		{ &hf_btbredr_hec,
			{ "HEC", "btbredr.lt_addr",
			FT_UINT8, BASE_HEX, NULL, 0x0,
			"Header Error Check", HFILL }
		},
		{ &hf_btbredr_payload,
			{ "Payload", "btbredr.payload",
			FT_NONE, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_btbredr_llid,
			{ "LLID", "btbredr.llid",
			FT_UINT8, BASE_HEX, VALS(llid_codes), 0x03,
			"Logical Link ID", HFILL }
		},
		{ &hf_btbredr_pldflow,
			{ "Flow", "btbredr.flow",
			FT_BOOLEAN, 8, NULL, 0x04,
			"Payload Flow indication", HFILL }
		},
		{ &hf_btbredr_length,
			{ "Length", "btbredr.length",
			FT_UINT8, BASE_DEC, NULL, 0xf8,
			"Payload Length", HFILL }
		},
		{ &hf_btbredr_pldhdr,
			{ "Payload Header", "btbredr.pldhdr",
			FT_NONE, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_btbredr_pldbody,
			{ "Payload Body", "btbredr.pldbody",
			FT_BYTES, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_btbredr_crc,
			{ "CRC", "btbredr.crc",
			FT_UINT16, BASE_HEX, NULL, 0x0,
			"Payload CRC", HFILL }
		},
		{ &hf_btbredr_fhs_parity,
			{ "Parity", "btbredr.parity",
			/* FIXME this doesn't work because bitmasks can only be 32 bits */
			FT_UINT64, BASE_HEX, NULL, /*0x00000003ffffffffULL,*/ 0x0,
			"LAP parity", HFILL }
		},
		{ &hf_btbredr_fhs_lap,
			{ "LAP", "btbredr.lap",
			FT_UINT24, BASE_HEX, NULL, 0x03fffffc,
			"Lower Address Part", HFILL }
		},
		{ &hf_btbredr_fhs_eir,
			{ "EIR", "btbredr.eir",
			FT_BOOLEAN, 8, NULL, 0x04,
			"Extended Inquiry Response packet may follow", HFILL }
		},
		{ &hf_btbredr_fhs_sr,
			{ "SR", "btbredr.sr",
			FT_UINT8, BASE_HEX, VALS(sr_modes), 0x30,
			"Scan Repetition", HFILL }
		},
		{ &hf_btbredr_fhs_uap,
			{ "UAP", "btbredr.uap",
			FT_UINT8, BASE_HEX, NULL, 0x0,
			"Upper Address Part", HFILL }
		},
		{ &hf_btbredr_fhs_nap,
			{ "NAP", "btbredr.nap",
			FT_UINT16, BASE_HEX, NULL, 0x0,
			"Non-Significant Address Part", HFILL }
		},
		{ &hf_btbredr_fhs_class, /* FIXME break out further */
			{ "Class of Device", "btbredr.class",
			FT_UINT24, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_btbredr_fhs_ltaddr,
			{ "LT_ADDR", "btbredr.lt_addr",
			FT_UINT8, BASE_HEX, NULL, 0x07,
			"Logical Transport Address", HFILL }
		},
		{ &hf_btbredr_fhs_clk,
			{ "CLK", "btbredr.clk",
			FT_UINT32, BASE_HEX, NULL, 0x1ffffff8,
			"Clock bits 2 through 27", HFILL }
		},
		{ &hf_btbredr_fhs_psmode,
			{ "Page Scan Mode", "btbredr.psmode",
			FT_UINT8, BASE_HEX, NULL, 0xe0,
			NULL, HFILL }
		},
	};

	/* protocol subtree arrays */
	static gint *ett[] = {
		&ett_btbredr,
		&ett_btbredr_meta,
		&ett_btbredr_pkthdr,
		&ett_btbredr_flags,
		&ett_btbredr_payload,
		&ett_btbredr_pldhdr,
	};

	/* register the protocol name and description */
	proto_btbredr = proto_register_protocol(
		"Bluetooth BR/EDR Baseband",	/* full name */
		"BT BR/EDR Baseband",			/* short name */
		"btbredr"			/* abbreviation (e.g. for filters) */
		);

	/* register the header fields and subtrees used */
	proto_register_field_array(proto_btbredr, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

/* Remove this once recent Wireshark/TCPdump releases are more common */
#ifndef WTAP_ENCAP_BLUETOOTH_BREDR_BB
#define WTAP_ENCAP_BLUETOOTH_BREDR_BB 161
#endif

void
proto_reg_handoff_btbredr(void)
{
	dissector_handle_t btbredr_handle;
	btbredr_handle = new_create_dissector_handle(dissect_btbredr,
												 proto_btbredr);
	dissector_add_uint("wtap_encap",
					   WTAP_ENCAP_BLUETOOTH_BREDR_BB,
					   btbredr_handle);

	btlmp_handle = find_dissector("btlmp");
	btl2cap_handle = find_dissector("btl2cap");
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
