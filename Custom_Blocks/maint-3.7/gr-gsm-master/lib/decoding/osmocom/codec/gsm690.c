/*! \file gsm690.c
 * GSM 06.90 - GSM AMR Codec. */
/*
 * (C) 2010 Sylvain Munaut <tnt@246tNt.com>
 *
 * All Rights Reserved
 *
 * SPDX-License-Identifier: GPL-2.0+
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */

#include <stdint.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#include <osmocom/core/utils.h>
#include <osmocom/codec/codec.h>
/*
 * These table map between the raw encoder parameter output and
 * the format used before channel coding. Both in GSM and in various
 * file/network format (same tables used in several specs).
 */

/* AMR 12.2 kbits - subjective importance bit ordering */
	/* This array encodes GSM 05.03 Table 7
	 * It's also TS 26.101 Table B.8
	 */
const uint16_t gsm690_12_2_bitorder[244] = {
	  0,   1,   2,   3,   4,   5,   6,   7,   8,   9,
	 10,  11,  12,  13,  14,  23,  15,  16,  17,  18,
	 19,  20,  21,  22,  24,  25,  26,  27,  28,  38,
	141,  39, 142,  40, 143,  41, 144,  42, 145,  43,
	146,  44, 147,  45, 148,  46, 149,  47,  97, 150,
	200,  48,  98, 151, 201,  49,  99, 152, 202,  86,
	136, 189, 239,  87, 137, 190, 240,  88, 138, 191,
	241,  91, 194,  92, 195,  93, 196,  94, 197,  95,
	198,  29,  30,  31,  32,  33,  34,  35,  50, 100,
	153, 203,  89, 139, 192, 242,  51, 101, 154, 204,
	 55, 105, 158, 208,  90, 140, 193, 243,  59, 109,
	162, 212,  63, 113, 166, 216,  67, 117, 170, 220,
	 36,  37,  54,  53,  52,  58,  57,  56,  62,  61,
	 60,  66,  65,  64,  70,  69,  68, 104, 103, 102,
	108, 107, 106, 112, 111, 110, 116, 115, 114, 120,
	119, 118, 157, 156, 155, 161, 160, 159, 165, 164,
	163, 169, 168, 167, 173, 172, 171, 207, 206, 205,
	211, 210, 209, 215, 214, 213, 219, 218, 217, 223,
	222, 221,  73,  72,  71,  76,  75,  74,  79,  78,
	 77,  82,  81,  80,  85,  84,  83, 123, 122, 121,
	126, 125, 124, 129, 128, 127, 132, 131, 130, 135,
	134, 133, 176, 175, 174, 179, 178, 177, 182, 181,
	180, 185, 184, 183, 188, 187, 186, 226, 225, 224,
	229, 228, 227, 232, 231, 230, 235, 234, 233, 238,
	237, 236,  96, 199,
};

/* AMR 10.2 kbits - subjective importance bit ordering */
	/* This array encodes GSM 05.03 Table 8
	 * It's also TS 26.101 Table B.7
	 */
const uint16_t gsm690_10_2_bitorder[204] = {
	  7,   6,   5,   4,   3,   2,   1,   0,  16,  15,
	 14,  13,  12,  11,  10,   9,   8,  26,  27,  28,
	 29,  30,  31, 115, 116, 117, 118, 119, 120,  72,
	 73, 161, 162,  65,  68,  69, 108, 111, 112, 154,
	157, 158, 197, 200, 201,  32,  33, 121, 122,  74,
	 75, 163, 164,  66, 109, 155, 198,  19,  23,  21,
	 22,  18,  17,  20,  24,  25,  37,  36,  35,  34,
	 80,  79,  78,  77, 126, 125, 124, 123, 169, 168,
	167, 166,  70,  67,  71, 113, 110, 114, 159, 156,
	160, 202, 199, 203,  76, 165,  81,  82,  92,  91,
	 93,  83,  95,  85,  84,  94, 101, 102,  96, 104,
	 86, 103,  87,  97, 127, 128, 138, 137, 139, 129,
	141, 131, 130, 140, 147, 148, 142, 150, 132, 149,
	133, 143, 170, 171, 181, 180, 182, 172, 184, 174,
	173, 183, 190, 191, 185, 193, 175, 192, 176, 186,
	 38,  39,  49,  48,  50,  40,  52,  42,  41,  51,
	 58,  59,  53,  61,  43,  60,  44,  54, 194, 179,
	189, 196, 177, 195, 178, 187, 188, 151, 136, 146,
	153, 134, 152, 135, 144, 145, 105,  90, 100, 107,
	 88, 106,  89,  98,  99,  62,  47,  57,  64,  45,
	 63,  46,  55,  56,
};

/* AMR 7.95 kbits - subjective importance bit ordering */
	/* This array encodes GSM 05.03 Table 9
	 * It's also TS 26.101 Table B.6
	 */
const uint16_t gsm690_7_95_bitorder[159] = {
	  8,   7,   6,   5,   4,   3,   2,  14,  16,   9,
	 10,  12,  13,  15,  11,  17,  20,  22,  24,  23,
	 19,  18,  21,  56,  88, 122, 154,  57,  89, 123,
	155,  58,  90, 124, 156,  52,  84, 118, 150,  53,
	 85, 119, 151,  27,  93,  28,  94,  29,  95,  30,
	 96,  31,  97,  61, 127,  62, 128,  63, 129,  59,
	 91, 125, 157,  32,  98,  64, 130,   1,   0,  25,
	 26,  33,  99,  34, 100,  65, 131,  66, 132,  54,
	 86, 120, 152,  60,  92, 126, 158,  55,  87, 121,
	153, 117, 116, 115,  46,  78, 112, 144,  43,  75,
	109, 141,  40,  72, 106, 138,  36,  68, 102, 134,
	114, 149, 148, 147, 146,  83,  82,  81,  80,  51,
	 50,  49,  48,  47,  45,  44,  42,  39,  35,  79,
	 77,  76,  74,  71,  67, 113, 111, 110, 108, 105,
	101, 145, 143, 142, 140, 137, 133,  41,  73, 107,
	139,  37,  69, 103, 135,  38,  70, 104, 136,
};

/* AMR 7.4 kbits - subjective importance bit ordering */
	/* This array encodes GSM 05.03 Table 10
	 * It's also TS 26.101 Table B.5
	 */
const uint16_t gsm690_7_4_bitorder[148] = {
	  0,   1,   2,   3,   4,   5,   6,   7,   8,   9,
	 10,  11,  12,  13,  14,  15,  16,  26,  87,  27,
	 88,  28,  89,  29,  90,  30,  91,  51,  80, 112,
	141,  52,  81, 113, 142,  54,  83, 115, 144,  55,
	 84, 116, 145,  58, 119,  59, 120,  21,  22,  23,
	 17,  18,  19,  31,  60,  92, 121,  56,  85, 117,
	146,  20,  24,  25,  50,  79, 111, 140,  57,  86,
	118, 147,  49,  78, 110, 139,  48,  77,  53,  82,
	114, 143, 109, 138,  47,  76, 108, 137,  32,  33,
	 61,  62,  93,  94, 122, 123,  41,  42,  43,  44,
	 45,  46,  70,  71,  72,  73,  74,  75, 102, 103,
	104, 105, 106, 107, 131, 132, 133, 134, 135, 136,
	 34,  63,  95, 124,  35,  64,  96, 125,  36,  65,
	 97, 126,  37,  66,  98, 127,  38,  67,  99, 128,
	 39,  68, 100, 129,  40,  69, 101, 130,
};

/* AMR 6.7 kbits - subjective importance bit ordering */
	/* This array encodes GSM 05.03 Table 11
	 * It's also TS 26.101 Table B.4
	 */
const uint16_t gsm690_6_7_bitorder[134] = {
	  0,   1,   4,   3,   5,   6,  13,   7,   2,   8,
	  9,  11,  15,  12,  14,  10,  28,  82,  29,  83,
	 27,  81,  26,  80,  30,  84,  16,  55, 109,  56,
	110,  31,  85,  57, 111,  48,  73, 102, 127,  32,
	 86,  51,  76, 105, 130,  52,  77, 106, 131,  58,
	112,  33,  87,  19,  23,  53,  78, 107, 132,  21,
	 22,  18,  17,  20,  24,  25,  50,  75, 104, 129,
	 47,  72, 101, 126,  54,  79, 108, 133,  46,  71,
	100, 125, 128, 103,  74,  49,  45,  70,  99, 124,
	 42,  67,  96, 121,  39,  64,  93, 118,  38,  63,
	 92, 117,  35,  60,  89, 114,  34,  59,  88, 113,
	 44,  69,  98, 123,  43,  68,  97, 122,  41,  66,
	 95, 120,  40,  65,  94, 119,  37,  62,  91, 116,
	 36,  61,  90, 115,
};

/* AMR 5.9 kbits - subjective importance bit ordering */
	/* This array encodes GSM 05.03 Table 12
	 * It's also TS 26.101 Table B.3
	 */
const uint16_t gsm690_5_9_bitorder[118] = {
	  0,   1,   4,   5,   3,   6,   7,   2,  13,  15,
	  8,   9,  11,  12,  14,  10,  16,  28,  74,  29,
	 75,  27,  73,  26,  72,  30,  76,  51,  97,  50,
	 71,  96, 117,  31,  77,  52,  98,  49,  70,  95,
	116,  53,  99,  32,  78,  33,  79,  48,  69,  94,
	115,  47,  68,  93, 114,  46,  67,  92, 113,  19,
	 21,  23,  22,  18,  17,  20,  24, 111,  43,  89,
	110,  64,  65,  44,  90,  25,  45,  66,  91, 112,
	 54, 100,  40,  61,  86, 107,  39,  60,  85, 106,
	 36,  57,  82, 103,  35,  56,  81, 102,  34,  55,
	 80, 101,  42,  63,  88, 109,  41,  62,  87, 108,
	 38,  59,  84, 105,  37,  58,  83, 104,
};

/* AMR 5.15 kbits - subjective importance bit ordering */
	/* This array encodes GSM 05.03 Table 13
	 * It's also TS 26.101 Table B.2
	 */
const uint16_t gsm690_5_15_bitorder[103] = {
	  7,   6,   5,   4,   3,   2,   1,   0,  15,  14,
	 13,  12,  11,  10,   9,   8,  23,  24,  25,  26,
	 27,  46,  65,  84,  45,  44,  43,  64,  63,  62,
	 83,  82,  81, 102, 101, 100,  42,  61,  80,  99,
	 28,  47,  66,  85,  18,  41,  60,  79,  98,  29,
	 48,  67,  17,  20,  22,  40,  59,  78,  97,  21,
	 30,  49,  68,  86,  19,  16,  87,  39,  38,  58,
	 57,  77,  35,  54,  73,  92,  76,  96,  95,  36,
	 55,  74,  93,  32,  51,  33,  52,  70,  71,  89,
	 90,  31,  50,  69,  88,  37,  56,  75,  94,  34,
	 53,  72,  91,
};

/* AMR 4.75 kbits - subjective importance bit ordering */
	/* This array encodes GSM 05.03 Table 14
	 * It's also TS 26.101 Table B.1
	 */
const uint16_t gsm690_4_75_bitorder[95] = {
	  0,   1,   2,   3,   4,   5,   6,   7,   8,   9,
	 10,  11,  12,  13,  14,  15,  23,  24,  25,  26,
	 27,  28,  48,  49,  61,  62,  82,  83,  47,  46,
	 45,  44,  81,  80,  79,  78,  17,  18,  20,  22,
	 77,  76,  75,  74,  29,  30,  43,  42,  41,  40,
	 38,  39,  16,  19,  21,  50,  51,  59,  60,  63,
	 64,  72,  73,  84,  85,  93,  94,  32,  33,  35,
	 36,  53,  54,  56,  57,  66,  67,  69,  70,  87,
	 88,  90,  91,  34,  55,  68,  89,  37,  58,  71,
	 92,  31,  52,  65,  86,
};

static const uint8_t amr_len_by_ft[16] = {
	12, 13, 15, 17, 19, 20, 26, 31, 7,  0,  0,  0,  0,  0,  0,  0
};

const struct value_string osmo_amr_type_names[] = {
	{ AMR_4_75,		"AMR 4,75 kbits/s" },
	{ AMR_5_15,		"AMR 5,15 kbit/s" },
	{ AMR_5_90,		"AMR 5,90 kbit/s" },
	{ AMR_6_70,		"AMR 6,70 kbit/s (PDC-EFR)" },
	{ AMR_7_40,		"AMR 7,40 kbit/s (TDMA-EFR)" },
	{ AMR_7_95,		"AMR 7,95 kbit/s" },
	{ AMR_10_2,		"AMR 10,2 kbit/s" },
	{ AMR_12_2,		"AMR 12,2 kbit/s (GSM-EFR)" },
	{ AMR_SID,		"AMR SID" },
	{ AMR_GSM_EFR_SID,	"GSM-EFR SID" },
	{ AMR_TDMA_EFR_SID,	"TDMA-EFR SID" },
	{ AMR_PDC_EFR_SID,	"PDC-EFR SID" },
	{ AMR_NO_DATA,		"No Data/NA" },
	{ 0,			NULL },
};

/*! Decode various AMR parameters from RTP payload (RFC 4867) acording to
 *         3GPP TS 26.101
 *  \param[in] rtppayload Payload from RTP packet
 *  \param[in] payload_len length of rtppayload
 *  \param[out] cmr AMR Codec Mode Request, not filled if NULL
 *  \param[out] cmi AMR Codec Mode Indicator, -1 if not applicable for this type,
 *              not filled if NULL
 *  \param[out] ft AMR Frame Type, not filled if NULL
 *  \param[out] bfi AMR Bad Frame Indicator, not filled if NULL
 *  \param[out] sti AMR SID Type Indicator, -1 if not applicable for this type,
 *              not filled if NULL
 *  \returns length of AMR data or negative value on error
 */
int osmo_amr_rtp_dec(const uint8_t *rtppayload, int payload_len, uint8_t *cmr,
		     int8_t *cmi, enum osmo_amr_type *ft,
		     enum osmo_amr_quality *bfi, int8_t *sti)
{
	if (payload_len < 2 || !rtppayload)
		return -EINVAL;

	/* RFC 4867 § 4.4.2 ToC - compound payloads are not supported: F = 0 */
	uint8_t type = (rtppayload[1] >> 3) & 0xf;

	/* compound payloads are not supported */
	if (rtppayload[1] >> 7)
		return -ENOTSUP;

	if (payload_len < amr_len_by_ft[type])
		return -ENOTSUP;

	if (ft)
		*ft = type;

	if (cmr)
		*cmr = rtppayload[0] >> 4;

	if (bfi)
		*bfi = (rtppayload[1] >> 2) & 1;

	/* Table 6 in 3GPP TS 26.101 */
	if (cmi)
		*cmi = (type == AMR_SID) ? ((rtppayload[6] >> 1) & 7) : -1;

	if (sti)
		*sti = (type == AMR_SID) ? (rtppayload[6] & 0x10) : -1;

	return 2 + amr_len_by_ft[type];
}

/*! Encode various AMR parameters from RTP payload (RFC 4867)
 *  \param[out] payload Payload for RTP packet, contains speech data (if any)
 *              except for have 2 first bytes where header will be built
 *  \param[in] cmr AMR codec Mode Request
 *  \param[in] ft AMR Frame Type
 *  \param[in] bfi AMR Bad Frame Indicator
 *  \returns length of AMR data (header + ToC + speech data) or negative value
 *           on error
 *
 *  Note: only octet-aligned mode is supported so the header occupies 2 full
 *  bytes. Optional interleaving header is not supported.
 */
int osmo_amr_rtp_enc(uint8_t *payload, uint8_t cmr, enum osmo_amr_type ft,
		     enum osmo_amr_quality bfi)
{
	if (cmr > 15)
		return -EINVAL;

	if (ft > 15)
		return -ENOTSUP;

	/* RFC 4867 § 4.3.1 payload header */
	payload[0] = cmr << 4;

	/* RFC 4867 § 4.4.2 ToC - compound payloads are not supported: F = 0 */
	payload[1] = (((uint8_t)ft) << 3) | (((uint8_t)bfi) << 2);

	/* speech data */
	return 2 + amr_len_by_ft[ft];
}
