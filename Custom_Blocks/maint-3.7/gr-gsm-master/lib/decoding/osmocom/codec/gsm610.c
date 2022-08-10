/*! \file gsm610.c
 * GSM 06.10 - GSM FR codec. */
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
#include <stdbool.h>

#include <osmocom/core/bitvec.h>
#include <osmocom/core/utils.h>
#include <osmocom/codec/codec.h>

/* GSM FR - subjective importance bit ordering */
	/* This array encodes GSM 05.03 Table 2.
	 * It's also GSM 06.10 Table A.2.1a
	 *
	 * It converts between serial parameter output by the encoder and the
	 * order needed before channel encoding.
	 */
const uint16_t gsm610_bitorder[260] = {
	0,	/* LARc0:5 */
	47,	/* Xmaxc0:5 */
	103,	/* Xmaxc1:5 */
	159,	/* Xmaxc2:5 */
	215,	/* Xmaxc3:5 */
	1,	/* LARc0:4 */
	6,	/* LARc1:5 */
	12,	/* LARc2:4 */
	2,	/* LARc0:3 */
	7,	/* LARc1:4 */
	13,	/* LARc2:3 */
	17,	/* LARc3:4 */
	36,	/* Nc0:6 */
	92,	/* Nc1:6 */
	148,	/* Nc2:6 */
	204,	/* Nc3:6 */
	48,	/* Xmaxc0:4 */
	104,	/* Xmaxc1:4 */
	160,	/* Xmaxc2:4 */
	216,	/* Xmaxc3:4 */
	8,	/* LARc1:3 */
	22,	/* LARc4:3 */
	26,	/* LARc5:3 */
	37,	/* Nc0:5 */
	93,	/* Nc1:5 */
	149,	/* Nc2:5 */
	205,	/* Nc3:5 */
	38,	/* Nc0:4 */
	94,	/* Nc1:4 */
	150,	/* Nc2:4 */
	206,	/* Nc3:4 */
	39,	/* Nc0:3 */
	95,	/* Nc1:3 */
	151,	/* Nc2:3 */
	207,	/* Nc3:3 */
	40,	/* Nc0:2 */
	96,	/* Nc1:2 */
	152,	/* Nc2:2 */
	208,	/* Nc3:2 */
	49,	/* Xmaxc0:3 */
	105,	/* Xmaxc1:3 */
	161,	/* Xmaxc2:3 */
	217,	/* Xmaxc3:3 */
	3,	/* LARc0:2 */
	18,	/* LARc3:3 */
	30,	/* LARc6:2 */
	41,	/* Nc0:1 */
	97,	/* Nc1:1 */
	153,	/* Nc2:1 */
	209,	/* Nc3:1 */
	23,	/* LARc4:2 */
	27,	/* LARc5:2 */
	43,	/* bc0:1 */
	99,	/* bc1:1 */
	155,	/* bc2:1 */
	211,	/* bc3:1 */
	42,	/* Nc0:0 */
	98,	/* Nc1:0 */
	154,	/* Nc2:0 */
	210,	/* Nc3:0 */
	45,	/* Mc0:1 */
	101,	/* Mc1:1 */
	157,	/* Mc2:1 */
	213,	/* Mc3:1 */
	4,	/* LARc0:1 */
	9,	/* LARc1:2 */
	14,	/* LARc2:2 */
	33,	/* LARc7:2 */
	19,	/* LARc3:2 */
	24,	/* LARc4:1 */
	31,	/* LARc6:1 */
	44,	/* bc0:0 */
	100,	/* bc1:0 */
	156,	/* bc2:0 */
	212,	/* bc3:0 */
	50,	/* Xmaxc0:2 */
	106,	/* Xmaxc1:2 */
	162,	/* Xmaxc2:2 */
	218,	/* Xmaxc3:2 */
	53,	/* xmc0_0:2 */
	56,	/* xmc0_1:2 */
	59,	/* xmc0_2:2 */
	62,	/* xmc0_3:2 */
	65,	/* xmc0_4:2 */
	68,	/* xmc0_5:2 */
	71,	/* xmc0_6:2 */
	74,	/* xmc0_7:2 */
	77,	/* xmc0_8:2 */
	80,	/* xmc0_9:2 */
	83,	/* xmc0_10:2 */
	86,	/* xmc0_11:2 */
	89,	/* xmc0_12:2 */
	109,	/* xmc1_0:2 */
	112,	/* xmc1_1:2 */
	115,	/* xmc1_2:2 */
	118,	/* xmc1_3:2 */
	121,	/* xmc1_4:2 */
	124,	/* xmc1_5:2 */
	127,	/* xmc1_6:2 */
	130,	/* xmc1_7:2 */
	133,	/* xmc1_8:2 */
	136,	/* xmc1_9:2 */
	139,	/* xmc1_10:2 */
	142,	/* xmc1_11:2 */
	145,	/* xmc1_12:2 */
	165,	/* xmc2_0:2 */
	168,	/* xmc2_1:2 */
	171,	/* xmc2_2:2 */
	174,	/* xmc2_3:2 */
	177,	/* xmc2_4:2 */
	180,	/* xmc2_5:2 */
	183,	/* xmc2_6:2 */
	186,	/* xmc2_7:2 */
	189,	/* xmc2_8:2 */
	192,	/* xmc2_9:2 */
	195,	/* xmc2_10:2 */
	198,	/* xmc2_11:2 */
	201,	/* xmc2_12:2 */
	221,	/* xmc3_0:2 */
	224,	/* xmc3_1:2 */
	227,	/* xmc3_2:2 */
	230,	/* xmc3_3:2 */
	233,	/* xmc3_4:2 */
	236,	/* xmc3_5:2 */
	239,	/* xmc3_6:2 */
	242,	/* xmc3_7:2 */
	245,	/* xmc3_8:2 */
	248,	/* xmc3_9:2 */
	251,	/* xmc3_10:2 */
	254,	/* xmc3_11:2 */
	257,	/* xmc3_12:2 */
	46,	/* Mc0:0 */
	102,	/* Mc1:0 */
	158,	/* Mc2:0 */
	214,	/* Mc3:0 */
	51,	/* Xmaxc0:1 */
	107,	/* Xmaxc1:1 */
	163,	/* Xmaxc2:1 */
	219,	/* Xmaxc3:1 */
	54,	/* xmc0_0:1 */
	57,	/* xmc0_1:1 */
	60,	/* xmc0_2:1 */
	63,	/* xmc0_3:1 */
	66,	/* xmc0_4:1 */
	69,	/* xmc0_5:1 */
	72,	/* xmc0_6:1 */
	75,	/* xmc0_7:1 */
	78,	/* xmc0_8:1 */
	81,	/* xmc0_9:1 */
	84,	/* xmc0_10:1 */
	87,	/* xmc0_11:1 */
	90,	/* xmc0_12:1 */
	110,	/* xmc1_0:1 */
	113,	/* xmc1_1:1 */
	116,	/* xmc1_2:1 */
	119,	/* xmc1_3:1 */
	122,	/* xmc1_4:1 */
	125,	/* xmc1_5:1 */
	128,	/* xmc1_6:1 */
	131,	/* xmc1_7:1 */
	134,	/* xmc1_8:1 */
	137,	/* xmc1_9:1 */
	140,	/* xmc1_10:1 */
	143,	/* xmc1_11:1 */
	146,	/* xmc1_12:1 */
	166,	/* xmc2_0:1 */
	169,	/* xmc2_1:1 */
	172,	/* xmc2_2:1 */
	175,	/* xmc2_3:1 */
	178,	/* xmc2_4:1 */
	181,	/* xmc2_5:1 */
	184,	/* xmc2_6:1 */
	187,	/* xmc2_7:1 */
	190,	/* xmc2_8:1 */
	193,	/* xmc2_9:1 */
	196,	/* xmc2_10:1 */
	199,	/* xmc2_11:1 */
	202,	/* xmc2_12:1 */
	222,	/* xmc3_0:1 */
	225,	/* xmc3_1:1 */
	228,	/* xmc3_2:1 */
	231,	/* xmc3_3:1 */
	234,	/* xmc3_4:1 */
	237,	/* xmc3_5:1 */
	240,	/* xmc3_6:1 */
	243,	/* xmc3_7:1 */
	246,	/* xmc3_8:1 */
	249,	/* xmc3_9:1 */
	252,	/* xmc3_10:1 */
	255,	/* xmc3_11:1 */
	258,	/* xmc3_12:1 */
	5,	/* LARc0:0 */
	10,	/* LARc1:1 */
	15,	/* LARc2:1 */
	28,	/* LARc5:1 */
	32,	/* LARc6:0 */
	34,	/* LARc7:1 */
	35,	/* LARc7:0 */
	16,	/* LARc2:0 */
	20,	/* LARc3:1 */
	21,	/* LARc3:0 */
	25,	/* LARc4:0 */
	52,	/* Xmaxc0:0 */
	108,	/* Xmaxc1:0 */
	164,	/* Xmaxc2:0 */
	220,	/* Xmaxc3:0 */
	55,	/* xmc0_0:0 */
	58,	/* xmc0_1:0 */
	61,	/* xmc0_2:0 */
	64,	/* xmc0_3:0 */
	67,	/* xmc0_4:0 */
	70,	/* xmc0_5:0 */
	73,	/* xmc0_6:0 */
	76,	/* xmc0_7:0 */
	79,	/* xmc0_8:0 */
	82,	/* xmc0_9:0 */
	85,	/* xmc0_10:0 */
	88,	/* xmc0_11:0 */
	91,	/* xmc0_12:0 */
	111,	/* xmc1_0:0 */
	114,	/* xmc1_1:0 */
	117,	/* xmc1_2:0 */
	120,	/* xmc1_3:0 */
	123,	/* xmc1_4:0 */
	126,	/* xmc1_5:0 */
	129,	/* xmc1_6:0 */
	132,	/* xmc1_7:0 */
	135,	/* xmc1_8:0 */
	138,	/* xmc1_9:0 */
	141,	/* xmc1_10:0 */
	144,	/* xmc1_11:0 */
	147,	/* xmc1_12:0 */
	167,	/* xmc2_0:0 */
	170,	/* xmc2_1:0 */
	173,	/* xmc2_2:0 */
	176,	/* xmc2_3:0 */
	179,	/* xmc2_4:0 */
	182,	/* xmc2_5:0 */
	185,	/* xmc2_6:0 */
	188,	/* xmc2_7:0 */
	191,	/* xmc2_8:0 */
	194,	/* xmc2_9:0 */
	197,	/* xmc2_10:0 */
	200,	/* xmc2_11:0 */
	203,	/* xmc2_12:0 */
	223,	/* xmc3_0:0 */
	226,	/* xmc3_1:0 */
	229,	/* xmc3_2:0 */
	232,	/* xmc3_3:0 */
	235,	/* xmc3_4:0 */
	238,	/* xmc3_5:0 */
	241,	/* xmc3_6:0 */
	244,	/* xmc3_7:0 */
	247,	/* xmc3_8:0 */
	250,	/* xmc3_9:0 */
	253,	/* xmc3_10:0 */
	256,	/* xmc3_11:0 */
	259,	/* xmc3_12:0 */
	11,	/* LARc1:0 */
	29,	/* LARc5:0 */
};

/*! Check whether RTP frame contains FR SID code word according to
 *  TS 101 318 §5.1.2
 *  \param[in] rtp_payload Buffer with RTP payload
 *  \param[in] payload_len Length of payload
 *  \returns true if code word is found, false otherwise
 */
bool osmo_fr_check_sid(const uint8_t *rtp_payload, size_t payload_len)
{
	struct bitvec bv;
	uint16_t i, z_bits[] = { 57, 58, 60, 61, 63, 64, 66, 67, 69, 70, 72, 73,
				 75, 76, 78, 79, 81, 82, 84, 85, 87, 88, 90, 91,
				 93, 94, 113, 114, 116, 117, 119, 120, 122, 123,
				 125, 126, 128, 129, 131, 132, 134, 135, 137,
				 138, 140, 141, 143, 144, 146, 147, 149, 150,
				 169, 170, 172, 173, 175, 176, 178, 179, 181,
				 182, 184, 185, 187, 188, 190, 191, 193, 194,
				 196, 197, 199, 200, 202, 203, 205, 206, 225,
				 226, 228, 229, 231, 232, 234, 235, 237, 240,
				 243, 246, 249, 252, 255, 258, 261 };

	/* signature does not match Full Rate SID */
	if ((rtp_payload[0] >> 4) != 0xD)
		return false;

	bv.data = (uint8_t *) rtp_payload;
	bv.data_len = payload_len;

	/* code word is all 0 at given bits, numbered from 1 */
	for (i = 0; i < ARRAY_SIZE(z_bits); i++)
		if (bitvec_get_bit_pos(&bv, z_bits[i]) != ZERO)
			return false;

	return true;
}
