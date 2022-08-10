/* packet-btbb.c
 * Routines for Bluetooth baseband dissection
 * Copyright 2009, Michael Ossmann <mike@ossmann.com>
 *
 * $Id$
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

/* function prototypes */
void proto_reg_handoff_btbb(void);

/* initialize the protocol and registered fields */
static int proto_btbb = -1;
static int hf_btbb_meta = -1;
static int hf_btbb_dir = -1;
static int hf_btbb_clk = -1;
static int hf_btbb_channel = -1;
static int hf_btbb_addrbits = -1;
static int hf_btbb_clkbits = -1;
static int hf_btbb_pkthdr = -1;
static int hf_btbb_ltaddr = -1;
static int hf_btbb_type = -1;
static int hf_btbb_flags = -1;
static int hf_btbb_flow = -1;
static int hf_btbb_arqn = -1;
static int hf_btbb_seqn = -1;
static int hf_btbb_hec = -1;
static int hf_btbb_payload = -1;
static int hf_btbb_pldhdr = -1;
static int hf_btbb_llid = -1;
static int hf_btbb_pldflow = -1;
static int hf_btbb_length = -1;
static int hf_btbb_pldbody = -1;
static int hf_btbb_crc = -1;
static int hf_btbb_fhs_parity = -1;
static int hf_btbb_fhs_lap = -1;
static int hf_btbb_fhs_eir = -1;
static int hf_btbb_fhs_sr = -1;
static int hf_btbb_fhs_uap = -1;
static int hf_btbb_fhs_nap = -1;
static int hf_btbb_fhs_class = -1;
static int hf_btbb_fhs_ltaddr = -1;
static int hf_btbb_fhs_clk = -1;
static int hf_btbb_fhs_psmode = -1;

/* field values */
static const true_false_string direction = {
	"Slave to Master",
	"Master to Slave"
};

static const true_false_string clock_bits = {
	"27",
	"6"
};

static const true_false_string address_bits = {
	"48 (NAP known)",
	"32 (NAP unknown)"
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
static gint ett_btbb = -1;
static gint ett_btbb_meta = -1;
static gint ett_btbb_pkthdr = -1;
static gint ett_btbb_flags = -1;
static gint ett_btbb_payload = -1;
static gint ett_btbb_pldhdr = -1;

/* subdissectors */
static dissector_handle_t btbrlmp_handle = NULL;
static dissector_handle_t btl2cap_handle = NULL;

/* packet header flags */
static const int *flag_fields[] = {
	&hf_btbb_flow,
	&hf_btbb_arqn,
	&hf_btbb_seqn,
	NULL
};

/* one byte payload header */
int
dissect_payload_header1(proto_tree *tree, tvbuff_t *tvb, int offset)
{
	proto_item *hdr_item;
	proto_tree *hdr_tree;

	DISSECTOR_ASSERT(tvb_length_remaining(tvb, offset) >= 1);

	hdr_item = proto_tree_add_item(tree, hf_btbb_pldhdr, tvb, offset, 1, ENC_NA);
	hdr_tree = proto_item_add_subtree(hdr_item, ett_btbb_pldhdr);

	proto_tree_add_item(hdr_tree, hf_btbb_llid, tvb, offset, 1, ENC_NA);
	proto_tree_add_item(hdr_tree, hf_btbb_pldflow, tvb, offset, 1, ENC_NA);
	proto_tree_add_item(hdr_tree, hf_btbb_length, tvb, offset, 1, ENC_NA);

	/* payload length */
	return tvb_get_guint8(tvb, offset) >> 3;
}

void
dissect_fhs(proto_tree *tree, tvbuff_t *tvb, int offset)
{
	proto_item *fhs_item, *psmode_item;
	proto_tree *fhs_tree;
    const gchar *description;
	guint8 psmode;

	DISSECTOR_ASSERT(tvb_length_remaining(tvb, offset) == 20);

	fhs_item = proto_tree_add_item(tree, hf_btbb_payload, tvb, offset, -1, ENC_NA);
	fhs_tree = proto_item_add_subtree(fhs_item, ett_btbb_payload);

	/* Use proto_tree_add_bits_item() to get around 32bit limit on bitmasks */
	proto_tree_add_bits_item(fhs_tree, hf_btbb_fhs_parity, tvb, offset*8, 34, ENC_LITTLE_ENDIAN);
	/* proto_tree_add_item(fhs_tree, hf_btbb_fhs_parity, tvb, offset, 5, ENC_LITTLE_ENDIAN); */
	offset += 4;

	proto_tree_add_item(fhs_tree, hf_btbb_fhs_lap, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 3;

	proto_tree_add_item(fhs_tree, hf_btbb_fhs_eir, tvb, offset, 1, ENC_NA);
	/* skipping 1 undefined bit */
	proto_tree_add_item(fhs_tree, hf_btbb_fhs_sr, tvb, offset, 1, ENC_NA);
	/* skipping 2 reserved bits */
	offset += 1;

	proto_tree_add_item(fhs_tree, hf_btbb_fhs_uap, tvb, offset, 1, ENC_NA);
	offset += 1;

	proto_tree_add_item(fhs_tree, hf_btbb_fhs_nap, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;

	proto_tree_add_item(fhs_tree, hf_btbb_fhs_class, tvb, offset, 3, ENC_LITTLE_ENDIAN);
	offset += 3;

	proto_tree_add_item(fhs_tree, hf_btbb_fhs_ltaddr, tvb, offset, 1, ENC_NA);
	proto_tree_add_item(fhs_tree, hf_btbb_fhs_clk, tvb, offset, 4, ENC_LITTLE_ENDIAN);
	offset += 3;

	psmode = tvb_get_guint8(tvb, offset);
	description = try_rval_to_str(psmode, ps_modes);
	psmode_item = proto_tree_add_item(fhs_tree, hf_btbb_fhs_psmode, tvb, offset, 1, ENC_NA);
	if (description)
        proto_item_append_text(psmode_item, " (%s)", description);
	offset += 1;

	proto_tree_add_item(fhs_tree, hf_btbb_crc, tvb, offset, 2, ENC_LITTLE_ENDIAN);
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

	DISSECTOR_ASSERT(tvb_length_remaining(tvb, offset) >= 3);

	dm1_item = proto_tree_add_item(tree, hf_btbb_payload, tvb, offset, -1, ENC_NA);
	dm1_tree = proto_item_add_subtree(dm1_item, ett_btbb_payload);

	len = dissect_payload_header1(dm1_tree, tvb, offset);
	llid = tvb_get_guint8(tvb, offset) & 0x3;
	offset += 1;

	DISSECTOR_ASSERT(tvb_length_remaining(tvb, offset) == len + 2);

	if (llid == 3 && btbrlmp_handle) {
		/* LMP */
		pld_tvb = tvb_new_subset(tvb, offset, len, len);
		call_dissector(btbrlmp_handle, pld_tvb, pinfo, dm1_tree);
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
			proto_tree_add_item(dm1_tree, hf_btbb_pldbody, tvb, offset, len, ENC_NA);
		}
	} else {
		proto_tree_add_item(dm1_tree, hf_btbb_pldbody, tvb, offset, len, ENC_NA);
	}
	offset += len;

	proto_tree_add_item(dm1_tree, hf_btbb_crc, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	offset += 2;
}

/* dissect a packet */
static int
dissect_btbb(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	proto_item *btbb_item, *meta_item, *pkthdr_item;
	proto_tree *btbb_tree, *meta_tree, *pkthdr_tree;
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
		type = (tvb_get_guint8(tvb, 6) >> 3) & 0x0f;
		info = val_to_str(type, packet_types, "Unknown type: 0x%x");
	}

	col_clear(pinfo->cinfo, COL_INFO);
	col_add_str(pinfo->cinfo, COL_INFO, info);

	/* see if we are being asked for details */
	if (tree) {

		/* create display subtree for the protocol */
		offset = 0;
		btbb_item = proto_tree_add_item(tree, proto_btbb, tvb, offset, -1, ENC_NA);
		btbb_tree = proto_item_add_subtree(btbb_item, ett_btbb);

		/* ID packets have no header, no payload */
		if (tvb_length(tvb) == 0)
			return 1;

		/* meta data */
		meta_item = proto_tree_add_item(btbb_tree, hf_btbb_meta, tvb, offset, 3, ENC_NA);
		meta_tree = proto_item_add_subtree(meta_item, ett_btbb_meta);

		proto_tree_add_item(meta_tree, hf_btbb_dir, tvb, offset, 1, ENC_NA);
		proto_tree_add_item(meta_tree, hf_btbb_clk, tvb, offset, 4, ENC_LITTLE_ENDIAN);
		offset += 4;

		proto_tree_add_item(meta_tree, hf_btbb_channel, tvb, offset, 1, ENC_NA);
		offset += 1;

		proto_tree_add_item(meta_tree, hf_btbb_clkbits, tvb, offset, 1, ENC_NA);
		proto_tree_add_item(meta_tree, hf_btbb_addrbits, tvb, offset, 1, ENC_NA);
		offset += 1;

		/* packet header */
		pkthdr_item = proto_tree_add_item(btbb_tree, hf_btbb_pkthdr, tvb, offset, 3, ENC_NA);
		pkthdr_tree = proto_item_add_subtree(pkthdr_item, ett_btbb_pkthdr);

		proto_tree_add_item(pkthdr_tree, hf_btbb_ltaddr, tvb, offset, 1, ENC_NA);
		proto_tree_add_item(pkthdr_tree, hf_btbb_type, tvb, offset, 1, ENC_NA);
		offset += 1;
		proto_tree_add_bitmask(pkthdr_tree, tvb, offset, hf_btbb_flags,
			ett_btbb_flags, flag_fields, ENC_NA);
		offset += 1;
		proto_tree_add_item(pkthdr_tree, hf_btbb_hec, tvb, offset, 1, ENC_NA);
		offset += 1;

		/* payload */
		switch (type) {
		case 0x0: /* NULL */
		case 0x1: /* POLL */
			break;
		case 0x2: /* FHS */
			dissect_fhs(btbb_tree, tvb, offset);
			break;
		case 0x3: /* DM1 */
			dissect_dm1(btbb_tree, tvb, pinfo, offset);
			break;
		case 0x4: /* DH1/2-DH1 */
			dissect_dm1(btbb_tree, tvb, pinfo, offset);
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
			proto_tree_add_item(btbb_tree, hf_btbb_payload, tvb, offset, -1, ENC_NA);
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
proto_register_btbb(void)
{
	/* list of fields */
	static hf_register_info hf[] = {
		{ &hf_btbb_meta,
			{ "Meta Data", "btbb.meta",
			FT_NONE, BASE_NONE, NULL, 0x0,
			"Meta Data About the Packet", HFILL }
		},
		{ &hf_btbb_dir,
			{ "Direction", "btbb.dir",
			FT_BOOLEAN, 8, TFS(&direction), 0x01,
			"Direction of Transmission", HFILL }
		},
		{ &hf_btbb_clk,
			{ "CLK", "btbb.clk",
			FT_UINT32, BASE_HEX, NULL, 0x0,
			"Clock bits 1 through 27", HFILL }
		},
		{ &hf_btbb_channel,
			{ "Channel", "btbb.channel",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"Channel (0-78)", HFILL }
		},
		{ &hf_btbb_clkbits,
			{ "Known Clock Bits", "btbb.clkbits",
			FT_BOOLEAN, 8, TFS(&clock_bits), 0x01,
			"Number of Known Master CLK Bits (6 or 27)", HFILL }
		},
		{ &hf_btbb_addrbits,
			{ "Known Address Bits", "btbb.addrbits",
			FT_BOOLEAN, 8, TFS(&address_bits), 0x02,
			"Number of Known Bits of BD_ADDR (32 or 48)", HFILL }
		},
		{ &hf_btbb_pkthdr,
			{ "Packet Header", "btbb.pkthdr",
			FT_NONE, BASE_NONE, NULL, 0x0,
			"Bluetooth Baseband Packet Header", HFILL }
		},
		{ &hf_btbb_ltaddr,
			{ "LT_ADDR", "btbb.lt_addr",
			FT_UINT8, BASE_HEX, NULL, 0x07,
			"Logical Transport Address", HFILL }
		},
		{ &hf_btbb_type,
			{ "TYPE", "btbb.type",
			FT_UINT8, BASE_HEX, VALS(packet_types), 0x78,
			"Packet Type", HFILL }
		},
		{ &hf_btbb_flags,
			{ "Flags", "btbb.flags",
			FT_UINT8, BASE_HEX, NULL, 0x0,
			"Packet Header Flags", HFILL }
		},
		{ &hf_btbb_flow,
			{ "FLOW", "btbb.flow",
			FT_BOOLEAN, 8, NULL, 0x01,
			"Flow control indication", HFILL }
		},
		{ &hf_btbb_arqn,
			{ "ARQN", "btbb.arqn",
			FT_BOOLEAN, 8, NULL, 0x02,
			"Acknowledgment indication", HFILL }
		},
		{ &hf_btbb_seqn,
			{ "SEQN", "btbb.seqn",
			FT_BOOLEAN, 8, NULL, 0x04,
			"Sequence number", HFILL }
		},
		{ &hf_btbb_hec,
			{ "HEC", "btbb.lt_addr",
			FT_UINT8, BASE_HEX, NULL, 0x0,
			"Header Error Check", HFILL }
		},
		{ &hf_btbb_payload,
			{ "Payload", "btbb.payload",
			FT_NONE, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_btbb_llid,
			{ "LLID", "btbb.llid",
			FT_UINT8, BASE_HEX, VALS(llid_codes), 0x03,
			"Logical Link ID", HFILL }
		},
		{ &hf_btbb_pldflow,
			{ "Flow", "btbb.flow",
			FT_BOOLEAN, 8, NULL, 0x04,
			"Payload Flow indication", HFILL }
		},
		{ &hf_btbb_length,
			{ "Length", "btbb.length",
			FT_UINT8, BASE_DEC, NULL, 0xf8,
			"Payload Length", HFILL }
		},
		{ &hf_btbb_pldhdr,
			{ "Payload Header", "btbb.pldhdr",
			FT_NONE, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_btbb_pldbody,
			{ "Payload Body", "btbb.pldbody",
			FT_BYTES, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_btbb_crc,
			{ "CRC", "btbb.crc",
			FT_UINT16, BASE_HEX, NULL, 0x0,
			"Payload CRC", HFILL }
		},
		{ &hf_btbb_fhs_parity,
			{ "Parity", "btbb.parity",
			/* FIXME this doesn't work because bitmasks can only be 32 bits */
			FT_UINT64, BASE_HEX, NULL, /*0x00000003ffffffffULL,*/ 0x0,
			"LAP parity", HFILL }
		},
		{ &hf_btbb_fhs_lap,
			{ "LAP", "btbb.lap",
			FT_UINT24, BASE_HEX, NULL, 0x03fffffc,
			"Lower Address Part", HFILL }
		},
		{ &hf_btbb_fhs_eir,
			{ "EIR", "btbb.eir",
			FT_BOOLEAN, 8, NULL, 0x04,
			"Extended Inquiry Response packet may follow", HFILL }
		},
		{ &hf_btbb_fhs_sr,
			{ "SR", "btbb.sr",
			FT_UINT8, BASE_HEX, VALS(sr_modes), 0x30,
			"Scan Repetition", HFILL }
		},
		{ &hf_btbb_fhs_uap,
			{ "UAP", "btbb.uap",
			FT_UINT8, BASE_HEX, NULL, 0x0,
			"Upper Address Part", HFILL }
		},
		{ &hf_btbb_fhs_nap,
			{ "NAP", "btbb.nap",
			FT_UINT16, BASE_HEX, NULL, 0x0,
			"Non-Significant Address Part", HFILL }
		},
		{ &hf_btbb_fhs_class, /* FIXME break out further */
			{ "Class of Device", "btbb.class",
			FT_UINT24, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_btbb_fhs_ltaddr,
			{ "LT_ADDR", "btbb.lt_addr",
			FT_UINT8, BASE_HEX, NULL, 0x07,
			"Logical Transport Address", HFILL }
		},
		{ &hf_btbb_fhs_clk,
			{ "CLK", "btbb.clk",
			FT_UINT32, BASE_HEX, NULL, 0x1ffffff8,
			"Clock bits 2 through 27", HFILL }
		},
		{ &hf_btbb_fhs_psmode,
			{ "Page Scan Mode", "btbb.psmode",
			FT_UINT8, BASE_HEX, NULL, 0xe0,
			NULL, HFILL }
		},
	};

	/* protocol subtree arrays */
	static gint *ett[] = {
		&ett_btbb,
		&ett_btbb_meta,
		&ett_btbb_pkthdr,
		&ett_btbb_flags,
		&ett_btbb_payload,
		&ett_btbb_pldhdr,
	};

	/* register the protocol name and description */
	proto_btbb = proto_register_protocol(
		"Bluetooth Baseband",	/* full name */
		"BT Baseband",			/* short name */
		"btbb"			/* abbreviation (e.g. for filters) */
		);

	/* register the header fields and subtrees used */
	proto_register_field_array(proto_btbb, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_btbb(void)
{
	dissector_handle_t btbb_handle;

	btbb_handle = new_create_dissector_handle(dissect_btbb, proto_btbb);
	/* hijacking this ethertype */
	dissector_add_uint("ethertype", 0xFFF0, btbb_handle);
	/* dissector_add_uint("wtap_encap", WTAP_ENCAP_BLUETOOTH_BASEBAND, btbb_handle); */

	btbrlmp_handle = find_dissector("btbrlmp");
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
