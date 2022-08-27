/* packet-btsm.c
 * Routines for Bluetooth Low Energy Security Manager dissection
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

#define BTL2CAP_FIXED_CID_BTSM      0x0006

/* initialize the protocol and registered fields */
static int proto_btsm = -1;
static int hf_btsm_command = -1;
static int hf_btsm_pairing_request_io_capability = -1;
static int hf_btsm_pairing_request_oob_data = -1;
static int hf_btsm_pairing_request_auth_req = -1;
static int hf_btsm_pairing_request_reserved = -1;
static int hf_btsm_pairing_request_mitm = -1;
static int hf_btsm_pairing_request_bonding_flags = -1;
static int hf_btsm_pairing_request_max_key_size = -1;
static int hf_btsm_pairing_request_initiator_key_distribution = -1;
static int hf_btsm_pairing_request_responder_key_distribution = -1;
static int hf_btsm_pairing_response_io_capability = -1;
static int hf_btsm_pairing_response_oob_data = -1;
static int hf_btsm_pairing_response_auth_req = -1;
static int hf_btsm_pairing_response_reserved = -1;
static int hf_btsm_pairing_response_mitm = -1;
static int hf_btsm_pairing_response_bonding_flags = -1;
static int hf_btsm_pairing_response_max_key_size = -1;
static int hf_btsm_pairing_response_initiator_key_distribution = -1;
static int hf_btsm_pairing_response_responder_key_distribution = -1;
static int hf_btsm_pairing_confirm_confirm = -1;
static int hf_btsm_pairing_random_random = -1;
static int hf_btsm_encryption_info_ltk = -1;

static const value_string commands[] = {
	{ 0x00, "Reserved" },
	{ 0x01, "Pairing Request" },
	{ 0x02, "Pairing Response" },
	{ 0x03, "Pairing Confirm" },
	{ 0x04, "Pairing Random" },
	{ 0x05, "Pairing Failed" },
	{ 0x06, "Encryption Information" },
	{ 0x07, "Master Identification" },
	{ 0x08, "Identity Information" },
	{ 0x09, "Identity Address Information" },
	{ 0x0A, "Signing Information" },
	{ 0x0B, "Security Request" },
	{ 0, NULL }
};

static const value_string io_capability[] = {
	{ 0x00, "DisplayOnly" },
	{ 0x01, "DisplayYesNo" },
	{ 0x02, "KeyboardOnly" },
	{ 0x03, "NoInputOutput" },
	{ 0x04, "KeyboardDisplay" },
	{ 0, NULL }
};

static const value_string oob_data[] = {
	{ 0x00, "OOB Authentication data not present" },
	{ 0x01, "OOB Authentication data from remote device present" },
	{ 0, NULL }
};

static const value_string bonding_flags[] = {
	{ 0x0, "No Bonding" },
	{ 0x1, "Bonding" },
	{ 0, NULL },
};

/* initialize the subtree pointers */
static gint ett_btsm = -1;
static gint ett_auth_req = -1;

static void
dissect_pairing_request(tvbuff_t *tvb, proto_tree *tree)
{
	proto_item *auth_req_item;
	proto_tree *auth_req_tree;

	proto_tree_add_item(tree, hf_btsm_pairing_request_io_capability, tvb, 1, 1, TRUE);
	proto_tree_add_item(tree, hf_btsm_pairing_request_oob_data, tvb, 2, 1, TRUE);

    auth_req_item = proto_tree_add_item(tree, hf_btsm_pairing_request_auth_req, tvb, 3, 1, TRUE);
	auth_req_tree = proto_item_add_subtree(auth_req_item, ett_auth_req);
	proto_tree_add_item(auth_req_tree, hf_btsm_pairing_request_reserved, tvb, 3, 1, TRUE);
	proto_tree_add_bits_item(auth_req_tree, hf_btsm_pairing_request_mitm, tvb, 3 * 8 + 5, 1, TRUE);
	proto_tree_add_item(auth_req_tree, hf_btsm_pairing_request_bonding_flags, tvb, 3, 1, TRUE);

	// TODO: check that max key size iswithin [7,16]
	proto_tree_add_item(tree, hf_btsm_pairing_request_max_key_size, tvb, 4, 1, TRUE);
	proto_tree_add_item(tree, hf_btsm_pairing_request_initiator_key_distribution, tvb, 5, 1, TRUE);
	proto_tree_add_item(tree, hf_btsm_pairing_request_responder_key_distribution, tvb, 6, 1, TRUE);
}

static void
dissect_pairing_response(tvbuff_t *tvb, proto_tree *tree)
{
	proto_item *auth_req_item;
	proto_tree *auth_req_tree;

	proto_tree_add_item(tree, hf_btsm_pairing_response_io_capability, tvb, 1, 1, TRUE);
	proto_tree_add_item(tree, hf_btsm_pairing_response_oob_data, tvb, 2, 1, TRUE);

    auth_req_item = proto_tree_add_item(tree, hf_btsm_pairing_response_auth_req, tvb, 3, 1, TRUE);
	auth_req_tree = proto_item_add_subtree(auth_req_item, ett_auth_req);
	proto_tree_add_item(auth_req_tree, hf_btsm_pairing_response_reserved, tvb, 3, 1, TRUE);
	proto_tree_add_bits_item(auth_req_tree, hf_btsm_pairing_response_mitm, tvb, 3 * 8 + 5, 1, TRUE);
	proto_tree_add_item(auth_req_tree, hf_btsm_pairing_response_bonding_flags, tvb, 3, 1, TRUE);

	// TODO: check that max key size iswithin [7,16]
	proto_tree_add_item(tree, hf_btsm_pairing_response_max_key_size, tvb, 4, 1, TRUE);
	proto_tree_add_item(tree, hf_btsm_pairing_response_initiator_key_distribution, tvb, 5, 1, TRUE);
	proto_tree_add_item(tree, hf_btsm_pairing_response_responder_key_distribution, tvb, 6, 1, TRUE);
}

static void
dissect_pairing_confirm(tvbuff_t *tvb, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_btsm_pairing_confirm_confirm, tvb, 1, 16, TRUE);
}

static void
dissect_pairing_random(tvbuff_t *tvb, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_btsm_pairing_random_random, tvb, 1, 16, TRUE);
}

static void
dissect_encryption_info(tvbuff_t *tvb, proto_tree *tree)
{
	proto_tree_add_item(tree, hf_btsm_encryption_info_ltk, tvb, 1, 16, TRUE);
}

/* dissect a packet */
static void
dissect_btsm(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item *btsm_item;
	proto_tree *btsm_tree;
	guint8 command;

#if 0
	/* sanity check: length */
	if (tvb_length(tvb) > 0 && tvb_length(tvb) < 9)
		/* bad length: look for a different dissector */
		return 0;
#endif

	/* make entries in protocol column and info column on summary display */
	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "BTLE Security Manager");

	command = tvb_get_guint8(tvb, 0);

	/* see if we are being asked for details */
	if (tree) {

		/* create display subtree for the protocol */
		btsm_item = proto_tree_add_item(tree, proto_btsm, tvb, 0, tvb_length(tvb), TRUE);
		btsm_tree = proto_item_add_subtree(btsm_item, ett_btsm);

		proto_tree_add_item(btsm_tree, hf_btsm_command, tvb, 0, 1, TRUE);

		if (check_col(pinfo->cinfo, COL_INFO)) {
			if (command <= 0xb) {
				col_set_str(pinfo->cinfo, COL_INFO, commands[command].strptr);
			} else {
				col_set_str(pinfo->cinfo, COL_INFO, "Unknown");
			}
		}

		switch (command) {
			// pairing request
			case (0x1):
				dissect_pairing_request(tvb, btsm_tree);
				break;
			case (0x2):
				dissect_pairing_response(tvb, btsm_tree);
				break;
			case (0x3):
				dissect_pairing_confirm(tvb, btsm_tree);
				break;
			case (0x4):
				dissect_pairing_random(tvb, btsm_tree);
				break;
			case (0x6):
				dissect_encryption_info(tvb, btsm_tree);
				break;
			default:
				break;
		}
	}

	return;
}

void
proto_reg_handoff_btsm(void)
{
    dissector_handle_t btsm_handle;

    btsm_handle = find_dissector("btsm");
    dissector_add_uint("btl2cap.cid", BTL2CAP_FIXED_CID_BTSM, btsm_handle);
}

/* register the protocol with Wireshark */
void
proto_register_btsm(void)
{

	/* list of fields */
	static hf_register_info hf[] = {
		{ &hf_btsm_command,
			{ "Command", "btsm.command",
			FT_UINT8, BASE_HEX, VALS(commands), 0x0,
			NULL, HFILL }
		},

		// pairing request
		{ &hf_btsm_pairing_request_io_capability,
			{ "IO Capability", "btsm.pairing_request.io_capability",
			FT_UINT8, BASE_HEX, VALS(io_capability), 0x0,
			NULL, HFILL }
		},
		{ &hf_btsm_pairing_request_oob_data,
			{ "OOB Data", "btsm.pairing_request.oob_data",
			FT_UINT8, BASE_HEX, VALS(oob_data), 0x0,
			NULL, HFILL }
		},
		{ &hf_btsm_pairing_request_auth_req,
			{ "AuthReq", "btsm.pairing_request.auth_req",
			FT_UINT8, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_btsm_pairing_request_reserved,
			{ "Reserved", "btsm.pairing_request.auth_req.reserved",
			FT_UINT8, BASE_HEX, NULL, 0xf8,
			NULL, HFILL }
		},
		{ &hf_btsm_pairing_request_mitm,
			{ "MITM Protection", "btsm.pairing_request.auth_req.mitm",
			FT_BOOLEAN, BASE_NONE, TFS(&tfs_yes_no), 0x0,
			NULL, HFILL }
		},
		{ &hf_btsm_pairing_request_bonding_flags,
			{ "Bonding Flags", "btsm.pairing_request.auth_req.bonding_flags",
			FT_UINT8, BASE_HEX, VALS(bonding_flags), 0x3,
			NULL, HFILL }
		},
		{ &hf_btsm_pairing_request_max_key_size,
			{ "Max Key Size", "btsm.pairing_request.max_key_size",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_btsm_pairing_request_initiator_key_distribution,
			{ "Initiator Key Distribution", "btsm.pairing_request.initiator_key_distribution",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_btsm_pairing_request_responder_key_distribution,
			{ "Responder Key Distribution", "btsm.pairing_request.responder_key_distribution",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},

		// pairing response
		{ &hf_btsm_pairing_response_io_capability,
			{ "IO Capability", "btsm.pairing_response.io_capability",
			FT_UINT8, BASE_HEX, VALS(io_capability), 0x0,
			NULL, HFILL }
		},
		{ &hf_btsm_pairing_response_oob_data,
			{ "OOB Data", "btsm.pairing_response.oob_data",
			FT_UINT8, BASE_HEX, VALS(oob_data), 0x0,
			NULL, HFILL }
		},
		{ &hf_btsm_pairing_response_auth_req,
			{ "AuthReq", "btsm.pairing_response.auth_req",
			FT_UINT8, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_btsm_pairing_response_reserved,
			{ "Reserved", "btsm.pairing_response.auth_req.reserved",
			FT_UINT8, BASE_HEX, NULL, 0xf8,
			NULL, HFILL }
		},
		{ &hf_btsm_pairing_response_mitm,
			{ "MITM Protection", "btsm.pairing_response.auth_req.mitm",
			FT_BOOLEAN, BASE_NONE, TFS(&tfs_yes_no), 0x0,
			NULL, HFILL }
		},
		{ &hf_btsm_pairing_response_bonding_flags,
			{ "Bonding Flags", "btsm.pairing_response.auth_req.bonding_flags",
			FT_UINT8, BASE_HEX, VALS(bonding_flags), 0x3,
			NULL, HFILL }
		},
		{ &hf_btsm_pairing_response_max_key_size,
			{ "Max Key Size", "btsm.pairing_response.max_key_size",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_btsm_pairing_response_initiator_key_distribution,
			{ "Initiator Key Distribution", "btsm.pairing_response.initiator_key_distribution",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_btsm_pairing_response_responder_key_distribution,
			{ "Responder Key Distribution", "btsm.pairing_response.responder_key_distribution",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},


		// pairing confirm
		{ &hf_btsm_pairing_confirm_confirm,
			{ "Confirm", "btsm.pairing_confirm.confirm",
			FT_BYTES, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},

		// pairing random
		{ &hf_btsm_pairing_random_random,
			{ "Random", "btsm.pairing_random.random",
			FT_BYTES, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},

		// encryption info LTK
		{ &hf_btsm_encryption_info_ltk,
			{ "LTK", "btsm.encryption_info.ltk",
			FT_BYTES, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},

	};

	/* protocol subtree arrays */
	static gint *ett[] = {
		&ett_btsm,
		&ett_auth_req,
	};

	/* register the protocol name and description */
	proto_btsm = proto_register_protocol(
		"Bluetooth Low Energy Security Manager",	/* full name */
		"BTSM",			/* short name */
		"btsm"			/* abbreviation (e.g. for filters) */
		);

	register_dissector("btsm", dissect_btsm, proto_btsm);

	/* register the header fields and subtrees used */
	proto_register_field_array(proto_btsm, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}
