/*
 * (C) 2013 by Andreas Eversberg <jolly@eversberg.eu>
 * (C) 2015 by Alexander Chemeris <Alexander.Chemeris@fairwaves.co>
 * (C) 2016 by Tom Tsou <tom.tsou@ettus.com>
 * (C) 2017 by Harald Welte <laforge@gnumonks.org>
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
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#define GSM_MACBLOCK_LEN 23

#include <osmocom/core/bits.h>
#include <osmocom/core/conv.h>
//#include <osmocom/core/utils.h>
#include <osmocom/core/crcgen.h>
#include <osmocom/core/endian.h>

//#include <osmocom/gsm/protocol/gsm_04_08.h>
/*#include <osmocom/gprs/protocol/gsm_04_60.h>*/
/*#include <osmocom/gprs/gprs_rlc.h>*/

#include <osmocom/gsm/gsm0503.h>
#include <osmocom/codec/codec.h>

#include <osmocom/coding/gsm0503_interleaving.h>
#include <osmocom/coding/gsm0503_mapping.h>
#include <osmocom/coding/gsm0503_tables.h>
#include "osmocom/coding/gsm0503_coding.h"
#include <osmocom/coding/gsm0503_parity.h>

/*! \mainpage libosmocoding Documentation
 *
 * \section sec_intro Introduction
 * This library is a collection of definitions, tables and functions
 * implementing the GSM/GPRS/EGPRS channel coding (and decoding) as
 * specified in 3GPP TS 05.03 / 45.003.
 *
 * libosmocoding is developed as part of the Osmocom (Open Source Mobile
 * Communications) project, a community-based, collaborative development
 * project to create Free and Open Source implementations of mobile
 * communications systems.  For more information about Osmocom, please
 * see https://osmocom.org/
 *
 * \section sec_copyright Copyright and License
 * Copyright © 2013 by Andreas Eversberg\n
 * Copyright © 2015 by Alexander Chemeris\n
 * Copyright © 2016 by Tom Tsou\n
 * Documentation Copyright © 2017 by Harald Welte\n
 * All rights reserved. \n\n
 * The source code of libosmocoding is licensed under the terms of the GNU
 * General Public License as published by the Free Software Foundation;
 * either version 2 of the License, or (at your option) any later
 * version.\n
 * See <http://www.gnu.org/licenses/> or COPYING included in the source
 * code package istelf.\n
 * The information detailed here is provided AS IS with NO WARRANTY OF
 * ANY KIND, INCLUDING THE WARRANTY OF DESIGN, MERCHANTABILITY AND
 * FITNESS FOR A PARTICULAR PURPOSE.
 * \n\n
 *
 * \section sec_tracker Homepage + Issue Tracker
 * libosmocoding is distributed as part of libosmocore and shares its
 * project page at http://osmocom.org/projects/libosmocore
 *
 * An Issue Tracker can be found at
 * https://osmocom.org/projects/libosmocore/issues
 *
 * \section sec_contact Contact and Support
 * Community-based support is available at the OpenBSC mailing list
 * <http://lists.osmocom.org/mailman/listinfo/openbsc>\n
 * Commercial support options available upon request from
 * <http://sysmocom.de/>
 */


/*! \addtogroup coding
 *  @{
 *
 *  GSM TS 05.03 coding
 *
 *  This module is the "master module" of libosmocoding. It uses the
 *  various other modules (mapping, parity, interleaving) in order to
 *  implement the complete channel coding (and decoding) chain for the
 *  various channel types as defined in TS 05.03 / 45.003.
 *
 * \file gsm0503_coding.c */

/*
 * EGPRS coding limits
 */

/* Max header size with parity bits */
#define EGPRS_HDR_UPP_MAX	54

/* Max encoded header size */
#define EGPRS_HDR_C_MAX		162

/* Max punctured header size */
#define EGPRS_HDR_HC_MAX	160

/* Max data block size with parity bits */
#define EGPRS_DATA_U_MAX	612

/* Max encoded data block size */
#define EGPRS_DATA_C_MAX	1836

/* Max single block punctured data size */
#define EGPRS_DATA_DC_MAX	1248

/* Dual block punctured data size */
#define EGPRS_DATA_C1		612
#define EGPRS_DATA_C2		EGPRS_DATA_C1

/*! union across the three different EGPRS Uplink header types *
union gprs_rlc_ul_hdr_egprs {
	struct gprs_rlc_ul_header_egprs_1 type1;
	struct gprs_rlc_ul_header_egprs_2 type2;
	struct gprs_rlc_ul_header_egprs_3 type3;
};

/*! union across the three different EGPRS Downlink header types *
union gprs_rlc_dl_hdr_egprs {
	struct gprs_rlc_dl_header_egprs_1 type1;
	struct gprs_rlc_dl_header_egprs_2 type2;
	struct gprs_rlc_dl_header_egprs_3 type3;
};

/*! Structure describing a Modulation and Coding Scheme */
struct gsm0503_mcs_code {
	/*! Modulation and Coding Scheme (MSC) number */
	uint8_t mcs;
	/*! Length of Uplink Stealing Flag (USF) in bits */
	uint8_t usf_len;

	/* Header coding */
	/*! Length of header (bits) */
	uint8_t hdr_len;
	/*! Length of header convolutional code */
	uint8_t hdr_code_len;
	/*! Length of header code puncturing sequence */
	uint8_t hdr_punc_len;
	/*! header convolutional code */
	const struct osmo_conv_code *hdr_conv;
	/*! header puncturing sequence */
	const uint8_t *hdr_punc;

	/* Data coding */
	/*! length of data (bits) */
	uint16_t data_len;
	/*! length of data convolutional code */
	uint16_t data_code_len;
	/*! length of data code puncturing sequence */
	uint16_t data_punc_len;
	/*! data convolutional code */
	const struct osmo_conv_code *data_conv;
	/*! data puncturing sequences */
	const uint8_t *data_punc[3];
};

static int osmo_conv_decode_ber(const struct osmo_conv_code *code,
	const sbit_t *input, ubit_t *output,
	int *n_errors, int *n_bits_total)
{
	int res, i, coded_len;
	ubit_t recoded[EGPRS_DATA_C_MAX];

	res = osmo_conv_decode(code, input, output);

	if (n_bits_total || n_errors) {
		coded_len = osmo_conv_encode(code, output, recoded);
		//OSMO_ASSERT(sizeof(recoded) / sizeof(recoded[0]) >= coded_len);
	}

	/* Count bit errors */
	if (n_errors) {
		*n_errors = 0;
		for (i = 0; i < coded_len; i++) {
			if (!((recoded[i] && input[i] < 0) ||
					(!recoded[i] && input[i] > 0)) )
						*n_errors += 1;
		}
	}

	if (n_bits_total)
		*n_bits_total = coded_len;

	return res;
}

/*! convenience wrapper for decoding coded bits
 *  \param[out] l2_data caller-allocated buffer for L2 Frame
 *  \param[in] cB 456 coded (soft) bits as per TS 05.03 4.1.3
 *  \param[out] n_errors Number of detected errors
 *  \param[out] n_bits_total Number of total coded bits
 *  \returns 0 on success; -1 on CRC error */
static int _xcch_decode_cB(uint8_t *l2_data, const sbit_t *cB,
	int *n_errors, int *n_bits_total)
{
	ubit_t conv[224];
	int rv;

	osmo_conv_decode_ber(&gsm0503_xcch, cB,
		conv, n_errors, n_bits_total);

	rv = osmo_crc64gen_check_bits(&gsm0503_fire_crc40,
		conv, 184, conv + 184);
	if (rv)
		return -1;

	osmo_ubit2pbit_ext(l2_data, 0, conv, 0, 184, 1);

	return 0;
}

/*! convenience wrapper for encoding to coded bits
 *  \param[out] cB caller-allocated buffer for 456 coded bits as per TS 05.03 4.1.3
 *  \param[out] l2_data to-be-encoded L2 Frame
 *  \returns 0 */
static int _xcch_encode_cB(ubit_t *cB, const uint8_t *l2_data)
{
	ubit_t conv[224];

	osmo_pbit2ubit_ext(conv, 0, l2_data, 0, 184, 1);

	osmo_crc64gen_set_bits(&gsm0503_fire_crc40, conv, 184, conv + 184);

	osmo_conv_encode(&gsm0503_xcch, conv, cB);

	return 0;
}

/*
 * GSM xCCH block transcoding
 */

/*! Decoding of xCCH data from bursts to L2 frame
 *  \param[out] l2_data caller-allocated output data buffer
 *  \param[in] bursts four GSM bursts in soft-bits
 *  \param[out] n_errors Number of detected errors
 *  \param[out] n_bits_total Number of total coded bits
 */
int gsm0503_xcch_decode(uint8_t *l2_data, const sbit_t *bursts,
	int *n_errors, int *n_bits_total)
{
	sbit_t iB[456], cB[456];
	int i;

	for (i = 0; i < 4; i++)
		gsm0503_xcch_burst_unmap(&iB[i * 114], &bursts[i * 116], NULL, NULL);

	gsm0503_xcch_deinterleave(cB, iB);

	return _xcch_decode_cB(l2_data, cB, n_errors, n_bits_total);
}

/*! Encoding of xCCH data from L2 frame to bursts
 *  \param[out] bursts caller-allocated burst data (unpacked bits)
 *  \param[in] l2_data L2 input data (MAC block)
 *  \returns 0
 */
int gsm0503_xcch_encode(ubit_t *bursts, const uint8_t *l2_data)
{
	ubit_t iB[456], cB[456], hl = 1, hn = 1;
	int i;

	_xcch_encode_cB(cB, l2_data);

	gsm0503_xcch_interleave(cB, iB);

	for (i = 0; i < 4; i++)
		gsm0503_xcch_burst_map(&iB[i * 114], &bursts[i * 116], &hl, &hn);

	return 0;
}



/*
 * GSM PDTCH block transcoding
 */

/*! Decode GPRS PDTCH
 *  \param[out] l2_data caller-allocated buffer for L2 Frame
 *  \param[in] bursts burst input data as soft unpacked bits
 *  \param[out] usf_p uplink stealing flag
 *  \param[out] n_errors number of detected bit-errors
 *  \param[out] n_bits_total total number of dcoded bits
 *  \returns 0 on success; negative on error *
int gsm0503_pdtch_decode(uint8_t *l2_data, const sbit_t *bursts, uint8_t *usf_p,
	int *n_errors, int *n_bits_total)
{
	sbit_t iB[456], cB[676], hl_hn[8];
	ubit_t conv[456];
	int i, j, k, rv, best = 0, cs = 0, usf = 0; /* make GCC happy *

	for (i = 0; i < 4; i++)
		gsm0503_xcch_burst_unmap(&iB[i * 114], &bursts[i * 116],
			hl_hn + i * 2, hl_hn + i * 2 + 1);

	for (i = 0; i < 4; i++) {
		for (j = 0, k = 0; j < 8; j++)
			k += abs(((int)gsm0503_pdtch_hl_hn_sbit[i][j]) - ((int)hl_hn[j]));

		if (i == 0 || k < best) {
			best = k;
			cs = i + 1;
		}
	}

	gsm0503_xcch_deinterleave(cB, iB);

	switch (cs) {
	case 1:
		osmo_conv_decode_ber(&gsm0503_xcch, cB,
			conv, n_errors, n_bits_total);

		rv = osmo_crc64gen_check_bits(&gsm0503_fire_crc40,
			conv, 184, conv + 184);
		if (rv)
			return -1;

		osmo_ubit2pbit_ext(l2_data, 0, conv, 0, 184, 1);

		return 23;
	case 2:
		for (i = 587, j = 455; i >= 0; i--) {
			if (!gsm0503_puncture_cs2[i])
				cB[i] = cB[j--];
			else
				cB[i] = 0;
		}

		osmo_conv_decode_ber(&gsm0503_cs2_np, cB,
			conv, n_errors, n_bits_total);

		for (i = 0; i < 8; i++) {
			for (j = 0, k = 0; j < 6; j++)
				k += abs(((int)gsm0503_usf2six[i][j]) - ((int)conv[j]));

			if (i == 0 || k < best) {
				best = k;
				usf = i;
			}
		}

		conv[3] = usf & 1;
		conv[4] = (usf >> 1) & 1;
		conv[5] = (usf >> 2) & 1;
		if (usf_p)
			*usf_p = usf;

		rv = osmo_crc16gen_check_bits(&gsm0503_cs234_crc16,
			conv + 3, 271, conv + 3 + 271);
		if (rv)
			return -1;

		osmo_ubit2pbit_ext(l2_data, 0, conv, 3, 271, 1);

		return 34;
	case 3:
		for (i = 675, j = 455; i >= 0; i--) {
			if (!gsm0503_puncture_cs3[i])
				cB[i] = cB[j--];
			else
				cB[i] = 0;
		}

		osmo_conv_decode_ber(&gsm0503_cs3_np, cB,
			conv, n_errors, n_bits_total);

		for (i = 0; i < 8; i++) {
			for (j = 0, k = 0; j < 6; j++)
				k += abs(((int)gsm0503_usf2six[i][j]) - ((int)conv[j]));

			if (i == 0 || k < best) {
				best = k;
				usf = i;
			}
		}

		conv[3] = usf & 1;
		conv[4] = (usf >> 1) & 1;
		conv[5] = (usf >> 2) & 1;
		if (usf_p)
			*usf_p = usf;

		rv = osmo_crc16gen_check_bits(&gsm0503_cs234_crc16,
			conv + 3, 315, conv + 3 + 315);
		if (rv)
			return -1;

		osmo_ubit2pbit_ext(l2_data, 0, conv, 3, 315, 1);

		return 40;
	case 4:
		for (i = 12; i < 456; i++)
			conv[i] = (cB[i] < 0) ? 1 : 0;

		for (i = 0; i < 8; i++) {
			for (j = 0, k = 0; j < 12; j++)
				k += abs(((int)gsm0503_usf2twelve_sbit[i][j]) - ((int)cB[j]));

			if (i == 0 || k < best) {
				best = k;
				usf = i;
			}
		}

		conv[9] = usf & 1;
		conv[10] = (usf >> 1) & 1;
		conv[11] = (usf >> 2) & 1;
		if (usf_p)
			*usf_p = usf;

		rv = osmo_crc16gen_check_bits(&gsm0503_cs234_crc16,
			conv + 9, 431, conv + 9 + 431);
		if (rv) {
			*n_bits_total = 456 - 12;
			*n_errors = *n_bits_total;
			return -1;
		}

		*n_bits_total = 456 - 12;
		*n_errors = 0;

		osmo_ubit2pbit_ext(l2_data, 0, conv, 9, 431, 1);

		return 54;
	default:
		*n_bits_total = 0;
		*n_errors = 0;
		break;
	}

	return -1;
}
*/

/*! GPRS DL message encoding
 *  \param[out] bursts caller-allocated buffer for unpacked burst bits
 *  \param[in] l2_data L2 (MAC) block to be encoded
 *  \param[in] l2_len length of l2_data in bytes, used to determine CS
 *  \returns 0 on success; negative on error */
int gsm0503_pdtch_encode(ubit_t *bursts, const uint8_t *l2_data, uint8_t l2_len)
{
	ubit_t iB[456], cB[676];
	const ubit_t *hl_hn;
	ubit_t conv[334];
	int i, j, usf;

	switch (l2_len) {
	case 23:
		osmo_pbit2ubit_ext(conv, 0, l2_data, 0, 184, 1);

		osmo_crc64gen_set_bits(&gsm0503_fire_crc40, conv, 184, conv + 184);

		osmo_conv_encode(&gsm0503_xcch, conv, cB);

		hl_hn = gsm0503_pdtch_hl_hn_ubit[0];

		break;
	/*case 34:
		osmo_pbit2ubit_ext(conv, 3, l2_data, 0, 271, 1);
		usf = l2_data[0] & 0x7;

		osmo_crc16gen_set_bits(&gsm0503_cs234_crc16, conv + 3,
			271, conv + 3 + 271);

		memcpy(conv, gsm0503_usf2six[usf], 6);

		osmo_conv_encode(&gsm0503_cs2_np, conv, cB);

		for (i = 0, j = 0; i < 588; i++)
			if (!gsm0503_puncture_cs2[i])
				cB[j++] = cB[i];

		hl_hn = gsm0503_pdtch_hl_hn_ubit[1];

		break;
	case 40:
		osmo_pbit2ubit_ext(conv, 3, l2_data, 0, 315, 1);
		usf = l2_data[0] & 0x7;

		osmo_crc16gen_set_bits(&gsm0503_cs234_crc16, conv + 3,
			315, conv + 3 + 315);

		memcpy(conv, gsm0503_usf2six[usf], 6);

		osmo_conv_encode(&gsm0503_cs3_np, conv, cB);

		for (i = 0, j = 0; i < 676; i++)
			if (!gsm0503_puncture_cs3[i])
				cB[j++] = cB[i];

		hl_hn = gsm0503_pdtch_hl_hn_ubit[2];

		break;*/
	case 54:
		osmo_pbit2ubit_ext(cB, 9, l2_data, 0, 431, 1);
		usf = l2_data[0] & 0x7;

		osmo_crc16gen_set_bits(&gsm0503_cs234_crc16, cB + 9,
			431, cB + 9 + 431);

		memcpy(cB, gsm0503_usf2twelve_ubit[usf], 12);

		hl_hn = gsm0503_pdtch_hl_hn_ubit[3];

		break;
	default:
		return -1;
	}

	gsm0503_xcch_interleave(cB, iB);

	for (i = 0; i < 4; i++) {
		gsm0503_xcch_burst_map(&iB[i * 114], &bursts[i * 116],
			hl_hn + i * 2, hl_hn + i * 2 + 1);
	}

	return GSM0503_GPRS_BURSTS_NBITS;
}

/*
 * GSM TCH/F FR/EFR transcoding
 */

/*! assemble a FR codec frame in format as used inside RTP
 *  \param[out] tch_data Codec frame in RTP format
 *  \param[in] b_bits Codec frame in 'native' format
 *  \param[in] net_order FIXME */
static void tch_fr_reassemble(uint8_t *tch_data,
	const ubit_t *b_bits, int net_order)
{
	int i, j, k, l, o;

	tch_data[0] = 0xd << 4;
	memset(tch_data + 1, 0, 32);

	if (net_order) {
		for (i = 0, j = 4; i < 260; i++, j++)
			tch_data[j >> 3] |= (b_bits[i] << (7 - (j & 7)));

		return;
	}

	/* reassemble d-bits */
	i = 0; /* counts bits */
	j = 4; /* counts output bits */
	k = gsm0503_gsm_fr_map[0]-1; /* current number bit in element */
	l = 0; /* counts element bits */
	o = 0; /* offset input bits */
	while (i < 260) {
		tch_data[j >> 3] |= (b_bits[k + o] << (7 - (j & 7)));
		if (--k < 0) {
			o += gsm0503_gsm_fr_map[l];
			k = gsm0503_gsm_fr_map[++l]-1;
		}
		i++;
		j++;
	}
}

static void tch_fr_disassemble(ubit_t *b_bits,
	const uint8_t *tch_data, int net_order)
{
	int i, j, k, l, o;

	if (net_order) {
		for (i = 0, j = 4; i < 260; i++, j++)
			b_bits[i] = (tch_data[j >> 3] >> (7 - (j & 7))) & 1;

		return;
	}

	i = 0; /* counts bits */
	j = 4; /* counts input bits */
	k = gsm0503_gsm_fr_map[0] - 1; /* current number bit in element */
	l = 0; /* counts element bits */
	o = 0; /* offset output bits */
	while (i < 260) {
		b_bits[k + o] = (tch_data[j >> 3] >> (7 - (j & 7))) & 1;
		if (--k < 0) {
			o += gsm0503_gsm_fr_map[l];
			k = gsm0503_gsm_fr_map[++l] - 1;
		}
		i++;
		j++;
	}
}

/* assemble a HR codec frame in format as used inside RTP */
static void tch_hr_reassemble(uint8_t *tch_data, const ubit_t *b_bits)
{
	int i, j;

	tch_data[0] = 0x00; /* F = 0, FT = 000 */
	memset(tch_data + 1, 0, 14);

	for (i = 0, j = 8; i < 112; i++, j++)
		tch_data[j >> 3] |= (b_bits[i] << (7 - (j & 7)));
}

static void tch_hr_disassemble(ubit_t *b_bits, const uint8_t *tch_data)
{
	int i, j;

	for (i = 0, j = 8; i < 112; i++, j++)
		b_bits[i] = (tch_data[j >> 3] >> (7 - (j & 7))) & 1;
}

/* assemble a EFR codec frame in format as used inside RTP */
static void tch_efr_reassemble(uint8_t *tch_data, const ubit_t *b_bits)
{
	int i, j;

	tch_data[0] = 0xc << 4;
	memset(tch_data + 1, 0, 30);

	for (i = 0, j = 4; i < 244; i++, j++)
		tch_data[j >> 3] |= (b_bits[i] << (7 - (j & 7)));
}

static void tch_efr_disassemble(ubit_t *b_bits, const uint8_t *tch_data)
{
	int i, j;

	for (i = 0, j = 4; i < 244; i++, j++)
		b_bits[i] = (tch_data[j >> 3] >> (7 - (j & 7))) & 1;
}

/* assemble a AMR codec frame in format as used inside RTP */
static void tch_amr_reassemble(uint8_t *tch_data, const ubit_t *d_bits, int len)
{
	int i, j;

	memset(tch_data, 0, (len + 7) >> 3);

	for (i = 0, j = 0; i < len; i++, j++)
		tch_data[j >> 3] |= (d_bits[i] << (7 - (j & 7)));
}

static void tch_amr_disassemble(ubit_t *d_bits, const uint8_t *tch_data, int len)
{
	int i, j;

	for (i = 0, j = 0; i < len; i++, j++)
		d_bits[i] = (tch_data[j >> 3] >> (7 - (j & 7))) & 1;
}

/* re-arrange according to TS 05.03 Table 2 (receiver) */
static void tch_fr_d_to_b(ubit_t *b_bits, const ubit_t *d_bits)
{
	int i;

	for (i = 0; i < 260; i++)
		b_bits[gsm610_bitorder[i]] = d_bits[i];
}

/* re-arrange according to TS 05.03 Table 2 (transmitter) */
static void tch_fr_b_to_d(ubit_t *d_bits, const ubit_t *b_bits)
{
	int i;

	for (i = 0; i < 260; i++)
		d_bits[i] = b_bits[gsm610_bitorder[i]];
}

/* re-arrange according to TS 05.03 Table 3a (receiver) */
static void tch_hr_d_to_b(ubit_t *b_bits, const ubit_t *d_bits)
{
	int i;

	const uint16_t *map;

	if (!d_bits[93] && !d_bits[94])
		map = gsm620_unvoiced_bitorder;
	else
		map = gsm620_voiced_bitorder;

	for (i = 0; i < 112; i++)
		b_bits[map[i]] = d_bits[i];
}

/* re-arrange according to TS 05.03 Table 3a (transmitter) */
static void tch_hr_b_to_d(ubit_t *d_bits, const ubit_t *b_bits)
{
	int i;
	const uint16_t *map;

	if (!b_bits[34] && !b_bits[35])
		map = gsm620_unvoiced_bitorder;
	else
		map = gsm620_voiced_bitorder;

	for (i = 0; i < 112; i++)
		d_bits[i] = b_bits[map[i]];
}

/* re-arrange according to TS 05.03 Table 6 (receiver) */
static void tch_efr_d_to_w(ubit_t *b_bits, const ubit_t *d_bits)
{
	int i;

	for (i = 0; i < 260; i++)
		b_bits[gsm660_bitorder[i]] = d_bits[i];
}

/* re-arrange according to TS 05.03 Table 6 (transmitter) */
static void tch_efr_w_to_d(ubit_t *d_bits, const ubit_t *b_bits)
{
	int i;

	for (i = 0; i < 260; i++)
		d_bits[i] = b_bits[gsm660_bitorder[i]];
}

/* extract the 65 protected class1a+1b bits */
static void tch_efr_protected(const ubit_t *s_bits, ubit_t *b_bits)
{
	int i;

	for (i = 0; i < 65; i++)
		b_bits[i] = s_bits[gsm0503_gsm_efr_protected_bits[i] - 1];
}

static void tch_fr_unreorder(ubit_t *d, ubit_t *p, const ubit_t *u)
{
	int i;

	for (i = 0; i < 91; i++) {
		d[i << 1] = u[i];
		d[(i << 1) + 1] = u[184 - i];
	}

	for (i = 0; i < 3; i++)
		p[i] = u[91 + i];
}

static void tch_fr_reorder(ubit_t *u, const ubit_t *d, const ubit_t *p)
{
	int i;

	for (i = 0; i < 91; i++) {
		u[i] = d[i << 1];
		u[184 - i] = d[(i << 1) + 1];
	}

	for (i = 0; i < 3; i++)
		u[91 + i] = p[i];
}

static void tch_hr_unreorder(ubit_t *d, ubit_t *p, const ubit_t *u)
{
	memcpy(d, u, 95);
	memcpy(p, u + 95, 3);
}

static void tch_hr_reorder(ubit_t *u, const ubit_t *d, const ubit_t *p)
{
	memcpy(u, d, 95);
	memcpy(u + 95, p, 3);
}

static void tch_efr_reorder(ubit_t *w, const ubit_t *s, const ubit_t *p)
{
	memcpy(w, s, 71);
	w[71] = w[72] = s[69];
	memcpy(w + 73, s + 71, 50);
	w[123] = w[124] = s[119];
	memcpy(w + 125, s + 121, 53);
	w[178] = w[179] = s[172];
	memcpy(w + 180, s + 174, 50);
	w[230] = w[231] = s[222];
	memcpy(w + 232, s + 224, 20);
	memcpy(w + 252, p, 8);
}

static void tch_efr_unreorder(ubit_t *s, ubit_t *p, const ubit_t *w)
{
	int sum;

	memcpy(s, w, 71);
	sum = s[69] + w[71] + w[72];
	s[69] = (sum >= 2);
	memcpy(s + 71, w + 73, 50);
	sum = s[119] + w[123] + w[124];
	s[119] = (sum >= 2);
	memcpy(s + 121, w + 125, 53);
	sum = s[172] + w[178] + w[179];
	s[172] = (sum > 2);
	memcpy(s + 174, w + 180, 50);
	sum = s[222] + w[230] + w[231];
	s[222] = (sum >= 2);
	memcpy(s + 224, w + 232, 20);
	memcpy(p, w + 252, 8);
}

static void tch_amr_merge(ubit_t *u, const ubit_t *d, const ubit_t *p, int len, int prot)
{
	memcpy(u, d, prot);
	memcpy(u + prot, p, 6);
	memcpy(u + prot + 6, d + prot, len - prot);
}

static void tch_amr_unmerge(ubit_t *d, ubit_t *p, const ubit_t *u, int len, int prot)
{
	memcpy(d, u, prot);
	memcpy(p, u + prot, 6);
	memcpy(d + prot, u + prot + 6, len - prot);
}

/*! Perform channel decoding of a FR/EFR channel according TS 05.03
 *  \param[out] tch_data Codec frame in RTP payload format
 *  \param[in] bursts buffer containing the symbols of 8 bursts
 *  \param[in] net_order FIXME
 *  \param[in] efr Is this channel using EFR (1) or FR (0)
 *  \param[out] n_errors Number of detected bit errors
 *  \param[out] n_bits_total Total number of bits
 *  \returns length of bytes used in \a tch_data output buffer */
int gsm0503_tch_fr_decode(uint8_t *tch_data, const sbit_t *bursts,
	int net_order, int efr, int *n_errors, int *n_bits_total)
{
	sbit_t iB[912], cB[456], h;
	ubit_t conv[185], s[244], w[260], b[65], d[260], p[8];
	int i, rv, len, steal = 0;

	/* map from 8 bursts to interleaved data bits (iB) */
	for (i = 0; i < 8; i++) {
		gsm0503_tch_burst_unmap(&iB[i * 114],
			&bursts[i * 116], &h, i >> 2);
		steal -= h;
	}
	/* we now have the bits of the four bursts (interface 4 in
	 * Figure 1a of TS 05.03 */

	gsm0503_tch_fr_deinterleave(cB, iB);
	/* we now have the coded bits c(B): interface 3 in Fig. 1a */

	if (steal > 0) {
		rv = _xcch_decode_cB(tch_data, cB, n_errors, n_bits_total);
		if (rv) {
			/* Error decoding FACCH frame */
			return -1;
		}

		return 23;
	}

	osmo_conv_decode_ber(&gsm0503_tch_fr, cB, conv, n_errors, n_bits_total);
	/* we now have the data bits 'u': interface 2 in Fig. 1a */

	/* input: 'conv', output: d[ata] + p[arity] */
	tch_fr_unreorder(d, p, conv);

	for (i = 0; i < 78; i++)
		d[i + 182] = (cB[i + 378] < 0) ? 1 : 0;

	/* check if parity of first 50 (class 1) 'd'-bits match 'p' */
	rv = osmo_crc8gen_check_bits(&gsm0503_tch_fr_crc3, d, 50, p);
	if (rv) {
		/* Error checking CRC8 for the FR part of an EFR/FR frame */
		return -1;
	}

	if (efr) {
		tch_efr_d_to_w(w, d);
		/* we now have the preliminary-coded bits w(k) */

		tch_efr_unreorder(s, p, w);
		/* we now have the data delivered to the preliminary
		 * channel encoding unit s(k) */

		/* extract the 65 most important bits according TS 05.03 3.1.1.1 */
		tch_efr_protected(s, b);

		/* perform CRC-8 on 65 most important bits (50 bits of
		 * class 1a + 15 bits of class 1b) */
		rv = osmo_crc8gen_check_bits(&gsm0503_tch_efr_crc8, b, 65, p);
		if (rv) {
			/* Error checking CRC8 for the EFR part of an EFR frame */
			return -1;
		}

		tch_efr_reassemble(tch_data, s);

		len = GSM_EFR_BYTES;
	} else {
		tch_fr_d_to_b(w, d);

		tch_fr_reassemble(tch_data, w, net_order);

		len = GSM_FR_BYTES;
	}

	return len;
}

/*! Perform channel encoding on a TCH/FS channel according to TS 05.03
 *  \param[out] bursts caller-allocated output buffer for bursts bits
 *  \param[in] tch_data Codec input data in RTP payload format
 *  \param[in] len Length of \a tch_data in bytes
 *  \param[in] net_order FIXME
 *  \returns 0 in case of success; negative on error */
int gsm0503_tch_fr_encode(ubit_t *bursts, const uint8_t *tch_data,
	int len, int net_order)
{
	ubit_t iB[912], cB[456], h;
	ubit_t conv[185], w[260], b[65], s[244], d[260], p[8];
	int i;

	switch (len) {
	case GSM_EFR_BYTES: /* TCH EFR */

		tch_efr_disassemble(s, tch_data);

		tch_efr_protected(s, b);

		osmo_crc8gen_set_bits(&gsm0503_tch_efr_crc8, b, 65, p);

		tch_efr_reorder(w, s, p);

		tch_efr_w_to_d(d, w);

		goto coding_efr_fr;
	case GSM_FR_BYTES: /* TCH FR */
		tch_fr_disassemble(w, tch_data, net_order);

		tch_fr_b_to_d(d, w);

coding_efr_fr:
		osmo_crc8gen_set_bits(&gsm0503_tch_fr_crc3, d, 50, p);

		tch_fr_reorder(conv, d, p);

		memcpy(cB + 378, d + 182, 78);

		osmo_conv_encode(&gsm0503_tch_fr, conv, cB);

		h = 0;

		break;
	case GSM_MACBLOCK_LEN: /* FACCH */
		_xcch_encode_cB(cB, tch_data);

		h = 1;

		break;
	default:
		return -1;
	}

	gsm0503_tch_fr_interleave(cB, iB);

	for (i = 0; i < 8; i++) {
		gsm0503_tch_burst_map(&iB[i * 114],
			&bursts[i * 116], &h, i >> 2);
	}

	return 0;
}

/*! Perform channel decoding of a HR(v1) channel according TS 05.03
 *  \param[out] tch_data Codec frame in RTP payload format
 *  \param[in] bursts buffer containing the symbols of 8 bursts
 *  \param[in] odd Odd (1) or even (0) frame number
 *  \param[out] n_errors Number of detected bit errors
 *  \param[out] n_bits_total Total number of bits
 *  \returns length of bytes used in \a tch_data output buffer */
int gsm0503_tch_hr_decode(uint8_t *tch_data, const sbit_t *bursts, int odd,
	int *n_errors, int *n_bits_total)
{
	sbit_t iB[912], cB[456], h;
	ubit_t conv[98], b[112], d[112], p[3];
	int i, rv, steal = 0;

	/* Only unmap the stealing bits */
	if (!odd) {
		for (i = 0; i < 4; i++) {
			gsm0503_tch_burst_unmap(NULL, &bursts[i * 116], &h, 0);
			steal -= h;
		}

		for (i = 2; i < 5; i++) {
			gsm0503_tch_burst_unmap(NULL, &bursts[i * 116], &h, 1);
			steal -= h;
		}
	}

	/* If we found a stole FACCH, but only at correct alignment */
	if (steal > 0) {
		for (i = 0; i < 6; i++) {
			gsm0503_tch_burst_unmap(&iB[i * 114],
				&bursts[i * 116], NULL, i >> 2);
		}

		for (i = 2; i < 4; i++) {
			gsm0503_tch_burst_unmap(&iB[i * 114 + 456],
				&bursts[i * 116], NULL, 1);
		}

		gsm0503_tch_fr_deinterleave(cB, iB);

		rv = _xcch_decode_cB(tch_data, cB, n_errors, n_bits_total);
		if (rv) {
			/* Error decoding FACCH frame */
			return -1;
		}

		return GSM_MACBLOCK_LEN;
	}

	for (i = 0; i < 4; i++) {
		gsm0503_tch_burst_unmap(&iB[i * 114],
			&bursts[i * 116], NULL, i >> 1);
	}

	gsm0503_tch_hr_deinterleave(cB, iB);

	osmo_conv_decode_ber(&gsm0503_tch_hr, cB, conv, n_errors, n_bits_total);

	tch_hr_unreorder(d, p, conv);

	for (i = 0; i < 17; i++)
		d[i + 95] = (cB[i + 211] < 0) ? 1 : 0;

	rv = osmo_crc8gen_check_bits(&gsm0503_tch_fr_crc3, d + 73, 22, p);
	if (rv) {
		/* Error checking CRC8 for an HR frame */
		return -1;
	}

	tch_hr_d_to_b(b, d);

	tch_hr_reassemble(tch_data, b);

	return 15;
}

/*! Perform channel encoding on a TCH/HS channel according to TS 05.03
 *  \param[out] bursts caller-allocated output buffer for bursts bits
 *  \param[in] tch_data Codec input data in RTP payload format
 *  \param[in] len Length of \a tch_data in bytes
 *  \returns 0 in case of success; negative on error */
int gsm0503_tch_hr_encode(ubit_t *bursts, const uint8_t *tch_data, int len)
{
	ubit_t iB[912], cB[456], h;
	ubit_t conv[98], b[112], d[112], p[3];
	int i;

	switch (len) {
	case 15: /* TCH HR */
		tch_hr_disassemble(b, tch_data);

		tch_hr_b_to_d(d, b);

		osmo_crc8gen_set_bits(&gsm0503_tch_fr_crc3, d + 73, 22, p);

		tch_hr_reorder(conv, d, p);

		osmo_conv_encode(&gsm0503_tch_hr, conv, cB);

		memcpy(cB + 211, d + 95, 17);

		h = 0;

		gsm0503_tch_hr_interleave(cB, iB);

		for (i = 0; i < 4; i++) {
			gsm0503_tch_burst_map(&iB[i * 114],
				&bursts[i * 116], &h, i >> 1);
		}

		break;
	case GSM_MACBLOCK_LEN: /* FACCH */
		_xcch_encode_cB(cB, tch_data);

		h = 1;

		gsm0503_tch_fr_interleave(cB, iB);

		for (i = 0; i < 6; i++) {
			gsm0503_tch_burst_map(&iB[i * 114],
				&bursts[i * 116], &h, i >> 2);
		}

		for (i = 2; i < 4; i++) {
			gsm0503_tch_burst_map(&iB[i * 114 + 456],
				&bursts[i * 116], &h, 1);
		}

		break;
	default:
		return -1;
	}

	return 0;
}

/*! Perform channel decoding of a TCH/AFS channel according TS 05.03
 *  \param[out] tch_data Codec frame in RTP payload format
 *  \param[in] bursts buffer containing the symbols of 8 bursts
 *  \param[in] codec_mode_req is this CMR (1) or CMC (0)
 *  \param[in] codec array of active codecs (active codec set)
 *  \param[in] codecs number of codecs in \a codec
 *  \param ft Frame Type; Input if \a codec_mode_req = 1, Output *  otherwise
 *  \param[out] cmr Output in \a codec_mode_req = 1
 *  \param[out] n_errors Number of detected bit errors
 *  \param[out] n_bits_total Total number of bits
 *  \returns length of bytes used in \a tch_data output buffer */
int gsm0503_tch_afs_decode(uint8_t *tch_data, const sbit_t *bursts,
	int codec_mode_req, uint8_t *codec, int codecs, uint8_t *ft,
	uint8_t *cmr, int *n_errors, int *n_bits_total)
{
	sbit_t iB[912], cB[456], h;
	ubit_t d[244], p[6], conv[250];
	int i, j, k, best = 0, rv, len, steal = 0, id = 0;
	*n_errors = 0; *n_bits_total = 0;

	for (i=0; i<8; i++) {
		gsm0503_tch_burst_unmap(&iB[i * 114], &bursts[i * 116], &h, i >> 2);
		steal -= h;
	}

	gsm0503_tch_fr_deinterleave(cB, iB);

	if (steal > 0) {
		rv = _xcch_decode_cB(tch_data, cB, n_errors, n_bits_total);
		if (rv) {
			/* Error decoding FACCH frame */
			return -1;
		}

		return GSM_MACBLOCK_LEN;
	}

	for (i = 0; i < 4; i++) {
		for (j = 0, k = 0; j < 8; j++)
			k += abs(((int)gsm0503_afs_ic_sbit[i][j]) - ((int)cB[j]));

		if (i == 0 || k < best) {
			best = k;
			id = i;
		}
	}

	/* Check if indicated codec fits into range of codecs */
	if (id >= codecs) {
		/* Codec mode out of range, return id */
		return id;
	}

	switch ((codec_mode_req) ? codec[*ft] : codec[id]) {
	case 7: /* TCH/AFS12.2 */
		osmo_conv_decode_ber(&gsm0503_tch_afs_12_2, cB + 8,
			conv, n_errors, n_bits_total);

		tch_amr_unmerge(d, p, conv, 244, 81);

		rv = osmo_crc8gen_check_bits(&gsm0503_amr_crc6, d, 81, p);
		if (rv) {
			/* Error checking CRC8 for an AMR 12.2 frame */
			return -1;
		}

		tch_amr_reassemble(tch_data, d, 244);

		len = 31;

		break;
	case 6: /* TCH/AFS10.2 */
		osmo_conv_decode_ber(&gsm0503_tch_afs_10_2, cB + 8,
			conv, n_errors, n_bits_total);

		tch_amr_unmerge(d, p, conv, 204, 65);

		rv = osmo_crc8gen_check_bits(&gsm0503_amr_crc6, d, 65, p);
		if (rv) {
			/* Error checking CRC8 for an AMR 10.2 frame */
			return -1;
		}

		tch_amr_reassemble(tch_data, d, 204);

		len = 26;

		break;
	case 5: /* TCH/AFS7.95 */
		osmo_conv_decode_ber(&gsm0503_tch_afs_7_95, cB + 8,
			conv, n_errors, n_bits_total);

		tch_amr_unmerge(d, p, conv, 159, 75);

		rv = osmo_crc8gen_check_bits(&gsm0503_amr_crc6, d, 75, p);
		if (rv) {
			/* Error checking CRC8 for an AMR 7.95 frame */
			return -1;
		}

		tch_amr_reassemble(tch_data, d, 159);

		len = 20;

		break;
	case 4: /* TCH/AFS7.4 */
		osmo_conv_decode_ber(&gsm0503_tch_afs_7_4, cB + 8,
			conv, n_errors, n_bits_total);

		tch_amr_unmerge(d, p, conv, 148, 61);

		rv = osmo_crc8gen_check_bits(&gsm0503_amr_crc6, d, 61, p);
		if (rv) {
			/* Error checking CRC8 for an AMR 7.4 frame */
			return -1;
		}

		tch_amr_reassemble(tch_data, d, 148);

		len = 19;

		break;
	case 3: /* TCH/AFS6.7 */
		osmo_conv_decode_ber(&gsm0503_tch_afs_6_7, cB + 8,
			conv, n_errors, n_bits_total);

		tch_amr_unmerge(d, p, conv, 134, 55);

		rv = osmo_crc8gen_check_bits(&gsm0503_amr_crc6, d, 55, p);
		if (rv) {
			/* Error checking CRC8 for an AMR 6.7 frame */
			return -1;
		}

		tch_amr_reassemble(tch_data, d, 134);

		len = 17;

		break;
	case 2: /* TCH/AFS5.9 */
		osmo_conv_decode_ber(&gsm0503_tch_afs_5_9, cB + 8,
			conv, n_errors, n_bits_total);

		tch_amr_unmerge(d, p, conv, 118, 55);

		rv = osmo_crc8gen_check_bits(&gsm0503_amr_crc6, d, 55, p);
		if (rv) {
			/* Error checking CRC8 for an AMR 5.9 frame */
			return -1;
		}

		tch_amr_reassemble(tch_data, d, 118);

		len = 15;

		break;
	case 1: /* TCH/AFS5.15 */
		osmo_conv_decode_ber(&gsm0503_tch_afs_5_15, cB + 8,
			conv, n_errors, n_bits_total);

		tch_amr_unmerge(d, p, conv, 103, 49);

		rv = osmo_crc8gen_check_bits(&gsm0503_amr_crc6, d, 49, p);
		if (rv) {
			/* Error checking CRC8 for an AMR 5.15 frame */
			return -1;
		}

		tch_amr_reassemble(tch_data, d, 103);

		len = 13;

		break;
	case 0: /* TCH/AFS4.75 */
		osmo_conv_decode_ber(&gsm0503_tch_afs_4_75, cB + 8,
			conv, n_errors, n_bits_total);

		tch_amr_unmerge(d, p, conv, 95, 39);

		rv = osmo_crc8gen_check_bits(&gsm0503_amr_crc6, d, 39, p);
		if (rv) {
			/* Error checking CRC8 for an AMR 4.75 frame */
			return -1;
		}

		tch_amr_reassemble(tch_data, d, 95);

		len = 12;

		break;
	default:
		/* Unknown frame type */
		*n_bits_total = 448;
		*n_errors = *n_bits_total;
		return -1;
	}

	/* Change codec request / indication, if frame is valid */
	if (codec_mode_req)
		*cmr = id;
	else
		*ft = id;

	return len;
}

/*! Perform channel encoding on a TCH/AFS channel according to TS 05.03
 *  \param[out] bursts caller-allocated output buffer for bursts bits
 *  \param[in] tch_data Codec input data in RTP payload format
 *  \param[in] len Length of \a tch_data in bytes
 *  \param[in] codec_mode_req Use CMR (1) or FT (0)
 *  \param[in] codec Array of codecs (active codec set)
 *  \param[in] codecs Number of entries in \a codec
 *  \param[in] ft Frame Type to be used for encoding (index to \a codec)
 *  \param[in] cmr Codec Mode Request (used in codec_mode_req = 1 only)
 *  \returns 0 in case of success; negative on error */
int gsm0503_tch_afs_encode(ubit_t *bursts, const uint8_t *tch_data, int len,
	int codec_mode_req, uint8_t *codec, int codecs, uint8_t ft,
	uint8_t cmr)
{
	ubit_t iB[912], cB[456], h;
	ubit_t d[244], p[6], conv[250];
	int i;
	uint8_t id;

	if (len == GSM_MACBLOCK_LEN) { /* FACCH */
		_xcch_encode_cB(cB, tch_data);

		h = 1;

		goto facch;
	}

	h = 0;

	if (codec_mode_req) {
		if (cmr >= codecs) {
			/* FIXME: CMR ID is not in codec list! */
			return -1;
		}
		id = cmr;
	} else {
		if (ft >= codecs) {
			/* FIXME: FT ID is not in codec list! */
			return -1;
		}
		id = ft;
	}

	switch (codec[ft]) {
	case 7: /* TCH/AFS12.2 */
		if (len != 31)
			goto invalid_length;

		tch_amr_disassemble(d, tch_data, 244);

		osmo_crc8gen_set_bits(&gsm0503_amr_crc6, d, 81, p);

		tch_amr_merge(conv, d, p, 244, 81);

		osmo_conv_encode(&gsm0503_tch_afs_12_2, conv, cB + 8);

		break;
	case 6: /* TCH/AFS10.2 */
		if (len != 26)
			goto invalid_length;

		tch_amr_disassemble(d, tch_data, 204);

		osmo_crc8gen_set_bits(&gsm0503_amr_crc6, d, 65, p);

		tch_amr_merge(conv, d, p, 204, 65);

		osmo_conv_encode(&gsm0503_tch_afs_10_2, conv, cB + 8);

		break;
	case 5: /* TCH/AFS7.95 */
		if (len != 20)
			goto invalid_length;

		tch_amr_disassemble(d, tch_data, 159);

		osmo_crc8gen_set_bits(&gsm0503_amr_crc6, d, 75, p);

		tch_amr_merge(conv, d, p, 159, 75);

		osmo_conv_encode(&gsm0503_tch_afs_7_95, conv, cB + 8);

		break;
	case 4: /* TCH/AFS7.4 */
		if (len != 19)
			goto invalid_length;

		tch_amr_disassemble(d, tch_data, 148);

		osmo_crc8gen_set_bits(&gsm0503_amr_crc6, d, 61, p);

		tch_amr_merge(conv, d, p, 148, 61);

		osmo_conv_encode(&gsm0503_tch_afs_7_4, conv, cB + 8);

		break;
	case 3: /* TCH/AFS6.7 */
		if (len != 17)
			goto invalid_length;

		tch_amr_disassemble(d, tch_data, 134);

		osmo_crc8gen_set_bits(&gsm0503_amr_crc6, d, 55, p);

		tch_amr_merge(conv, d, p, 134, 55);

		osmo_conv_encode(&gsm0503_tch_afs_6_7, conv, cB + 8);

		break;
	case 2: /* TCH/AFS5.9 */
		if (len != 15)
			goto invalid_length;

		tch_amr_disassemble(d, tch_data, 118);

		osmo_crc8gen_set_bits(&gsm0503_amr_crc6, d, 55, p);

		tch_amr_merge(conv, d, p, 118, 55);

		osmo_conv_encode(&gsm0503_tch_afs_5_9, conv, cB + 8);

		break;
	case 1: /* TCH/AFS5.15 */
		if (len != 13)
			goto invalid_length;

		tch_amr_disassemble(d, tch_data, 103);

		osmo_crc8gen_set_bits(&gsm0503_amr_crc6, d, 49, p);

		tch_amr_merge(conv, d, p, 103, 49);

		osmo_conv_encode(&gsm0503_tch_afs_5_15, conv, cB + 8);

		break;
	case 0: /* TCH/AFS4.75 */
		if (len != 12)
			goto invalid_length;

		tch_amr_disassemble(d, tch_data, 95);

		osmo_crc8gen_set_bits(&gsm0503_amr_crc6, d, 39, p);

		tch_amr_merge(conv, d, p, 95, 39);

		osmo_conv_encode(&gsm0503_tch_afs_4_75, conv, cB + 8);

		break;
	default:
		/* FIXME: FT %ft is not supported */
		return -1;
	}

	memcpy(cB, gsm0503_afs_ic_ubit[id], 8);

facch:
	gsm0503_tch_fr_interleave(cB, iB);

	for (i = 0; i < 8; i++) {
		gsm0503_tch_burst_map(&iB[i * 114],
			&bursts[i * 116], &h, i >> 2);
	}

	return 0;

invalid_length:
	/* FIXME: payload length %len does not comply with codec type %ft */
	return -1;
}

/*! Perform channel decoding of a TCH/AFS channel according TS 05.03
 *  \param[out] tch_data Codec frame in RTP payload format
 *  \param[in] bursts buffer containing the symbols of 8 bursts
 *  \param[in] odd Is this an odd (1) or even (0) frame number?
 *  \param[in] codec_mode_req is this CMR (1) or CMC (0)
 *  \param[in] codec array of active codecs (active codec set)
 *  \param[in] codecs number of codecs in \a codec
 *  \param ft Frame Type; Input if \a codec_mode_req = 1, Output *  otherwise
 *  \param[out] cmr Output in \a codec_mode_req = 1
 *  \param[out] n_errors Number of detected bit errors
 *  \param[out] n_bits_total Total number of bits
 *  \returns length of bytes used in \a tch_data output buffer */
int gsm0503_tch_ahs_decode(uint8_t *tch_data, const sbit_t *bursts, int odd,
	int codec_mode_req, uint8_t *codec, int codecs, uint8_t *ft,
	uint8_t *cmr, int *n_errors, int *n_bits_total)
{
	sbit_t iB[912], cB[456], h;
	ubit_t d[244], p[6], conv[135];
	int i, j, k, best = 0, rv, len, steal = 0, id = 0;

	/* only unmap the stealing bits */
	if (!odd) {
		for (i = 0; i < 4; i++) {
			gsm0503_tch_burst_unmap(NULL, &bursts[i * 116], &h, 0);
			steal -= h;
		}
		for (i = 2; i < 5; i++) {
			gsm0503_tch_burst_unmap(NULL, &bursts[i * 116], &h, 1);
			steal -= h;
		}
	}

	/* if we found a stole FACCH, but only at correct alignment */
	if (steal > 0) {
		for (i = 0; i < 6; i++) {
			gsm0503_tch_burst_unmap(&iB[i * 114],
				&bursts[i * 116], NULL, i >> 2);
		}

		for (i = 2; i < 4; i++) {
			gsm0503_tch_burst_unmap(&iB[i * 114 + 456],
				&bursts[i * 116], NULL, 1);
		}

		gsm0503_tch_fr_deinterleave(cB, iB);

		rv = _xcch_decode_cB(tch_data, cB, n_errors, n_bits_total);
		if (rv) {
			/* Error decoding FACCH frame */
			return -1;
		}

		return GSM_MACBLOCK_LEN;
	}

	for (i = 0; i < 4; i++) {
		gsm0503_tch_burst_unmap(&iB[i * 114],
			&bursts[i * 116], NULL, i >> 1);
	}

	gsm0503_tch_hr_deinterleave(cB, iB);

	for (i = 0; i < 4; i++) {
		for (j = 0, k = 0; j < 4; j++)
			k += abs(((int)gsm0503_ahs_ic_sbit[i][j]) - ((int)cB[j]));

		if (i == 0 || k < best) {
			best = k;
			id = i;
		}
	}

	/* Check if indicated codec fits into range of codecs */
	if (id >= codecs) {
		/* Codec mode out of range, return id */
		return id;
	}

	switch ((codec_mode_req) ? codec[*ft] : codec[id]) {
	case 5: /* TCH/AHS7.95 */
		osmo_conv_decode_ber(&gsm0503_tch_ahs_7_95, cB + 4,
			conv, n_errors, n_bits_total);

		tch_amr_unmerge(d, p, conv, 123, 67);

		rv = osmo_crc8gen_check_bits(&gsm0503_amr_crc6, d, 67, p);
		if (rv) {
			/* Error checking CRC8 for an AMR 7.95 frame */
			return -1;
		}

		for (i = 0; i < 36; i++)
			d[i + 123] = (cB[i + 192] < 0) ? 1 : 0;

		tch_amr_reassemble(tch_data, d, 159);

		len = 20;

		break;
	case 4: /* TCH/AHS7.4 */
		osmo_conv_decode_ber(&gsm0503_tch_ahs_7_4, cB + 4,
			conv, n_errors, n_bits_total);

		tch_amr_unmerge(d, p, conv, 120, 61);

		rv = osmo_crc8gen_check_bits(&gsm0503_amr_crc6, d, 61, p);
		if (rv) {
			/* Error checking CRC8 for an AMR 7.4 frame */
			return -1;
		}

		for (i = 0; i < 28; i++)
			d[i + 120] = (cB[i + 200] < 0) ? 1 : 0;

		tch_amr_reassemble(tch_data, d, 148);

		len = 19;

		break;
	case 3: /* TCH/AHS6.7 */
		osmo_conv_decode_ber(&gsm0503_tch_ahs_6_7, cB + 4,
			conv, n_errors, n_bits_total);

		tch_amr_unmerge(d, p, conv, 110, 55);

		rv = osmo_crc8gen_check_bits(&gsm0503_amr_crc6, d, 55, p);
		if (rv) {
			/* Error checking CRC8 for an AMR 6.7 frame */
			return -1;
		}

		for (i = 0; i < 24; i++)
			d[i + 110] = (cB[i + 204] < 0) ? 1 : 0;

		tch_amr_reassemble(tch_data, d, 134);

		len = 17;

		break;
	case 2: /* TCH/AHS5.9 */
		osmo_conv_decode_ber(&gsm0503_tch_ahs_5_9, cB + 4,
			conv, n_errors, n_bits_total);

		tch_amr_unmerge(d, p, conv, 102, 55);

		rv = osmo_crc8gen_check_bits(&gsm0503_amr_crc6, d, 55, p);
		if (rv) {
			/* Error checking CRC8 for an AMR 5.9 frame */
			return -1;
		}

		for (i = 0; i < 16; i++)
			d[i + 102] = (cB[i + 212] < 0) ? 1 : 0;

		tch_amr_reassemble(tch_data, d, 118);

		len = 15;

		break;
	case 1: /* TCH/AHS5.15 */
		osmo_conv_decode_ber(&gsm0503_tch_ahs_5_15, cB + 4,
			conv, n_errors, n_bits_total);

		tch_amr_unmerge(d, p, conv, 91, 49);

		rv = osmo_crc8gen_check_bits(&gsm0503_amr_crc6, d, 49, p);
		if (rv) {
			/* Error checking CRC8 for an AMR 5.15 frame */
			return -1;
		}

		for (i = 0; i < 12; i++)
			d[i + 91] = (cB[i + 216] < 0) ? 1 : 0;

		tch_amr_reassemble(tch_data, d, 103);

		len = 13;

		break;
	case 0: /* TCH/AHS4.75 */
		osmo_conv_decode_ber(&gsm0503_tch_ahs_4_75, cB + 4,
			conv, n_errors, n_bits_total);

		tch_amr_unmerge(d, p, conv, 83, 39);

		rv = osmo_crc8gen_check_bits(&gsm0503_amr_crc6, d, 39, p);
		if (rv) {
			/* Error checking CRC8 for an AMR 4.75 frame */
			return -1;
		}

		for (i = 0; i < 12; i++)
			d[i + 83] = (cB[i + 216] < 0) ? 1 : 0;

		tch_amr_reassemble(tch_data, d, 95);

		len = 12;

		break;
	default:
		/* Unknown frame type */
		*n_bits_total = 159;
		*n_errors = *n_bits_total;
		return -1;
	}

	/* Change codec request / indication, if frame is valid */
	if (codec_mode_req)
		*cmr = id;
	else
		*ft = id;

	return len;
}

/*! Perform channel encoding on a TCH/AHS channel according to TS 05.03
 *  \param[out] bursts caller-allocated output buffer for bursts bits
 *  \param[in] tch_data Codec input data in RTP payload format
 *  \param[in] len Length of \a tch_data in bytes
 *  \param[in] codec_mode_req Use CMR (1) or FT (0)
 *  \param[in] codec Array of codecs (active codec set)
 *  \param[in] codecs Number of entries in \a codec
 *  \param[in] ft Frame Type to be used for encoding (index to \a codec)
 *  \param[in] cmr Codec Mode Request (used in codec_mode_req = 1 only)
 *  \returns 0 in case of success; negative on error */
int gsm0503_tch_ahs_encode(ubit_t *bursts, const uint8_t *tch_data, int len,
	int codec_mode_req, uint8_t *codec, int codecs, uint8_t ft,
	uint8_t cmr)
{
	ubit_t iB[912], cB[456], h;
	ubit_t d[244], p[6], conv[135];
	int i;
	uint8_t id;

	if (len == GSM_MACBLOCK_LEN) { /* FACCH */
		_xcch_encode_cB(cB, tch_data);

		h = 1;

		gsm0503_tch_fr_interleave(cB, iB);

		for (i = 0; i < 6; i++)
			gsm0503_tch_burst_map(&iB[i * 114], &bursts[i * 116],
				&h, i >> 2);
		for (i = 2; i < 4; i++)
			gsm0503_tch_burst_map(&iB[i * 114 + 456],
				&bursts[i * 116], &h, 1);

		return 0;
	}

	h = 0;

	if (codec_mode_req) {
		if (cmr >= codecs) {
			/* FIXME: CMR ID %d not in codec list */
			return -1;
		}
		id = cmr;
	} else {
		if (ft >= codecs) {
			/* FIXME: FT ID %d not in codec list */
			return -1;
		}
		id = ft;
	}

	switch (codec[ft]) {
	case 5: /* TCH/AHS7.95 */
		if (len != 20)
			goto invalid_length;

		tch_amr_disassemble(d, tch_data, 159);

		osmo_crc8gen_set_bits(&gsm0503_amr_crc6, d, 67, p);

		tch_amr_merge(conv, d, p, 123, 67);

		osmo_conv_encode(&gsm0503_tch_ahs_7_95, conv, cB + 4);

		memcpy(cB + 192, d + 123, 36);

		break;
	case 4: /* TCH/AHS7.4 */
		if (len != 19)
			goto invalid_length;

		tch_amr_disassemble(d, tch_data, 148);

		osmo_crc8gen_set_bits(&gsm0503_amr_crc6, d, 61, p);

		tch_amr_merge(conv, d, p, 120, 61);

		osmo_conv_encode(&gsm0503_tch_ahs_7_4, conv, cB + 4);

		memcpy(cB + 200, d + 120, 28);

		break;
	case 3: /* TCH/AHS6.7 */
		if (len != 17)
			goto invalid_length;

		tch_amr_disassemble(d, tch_data, 134);

		osmo_crc8gen_set_bits(&gsm0503_amr_crc6, d, 55, p);

		tch_amr_merge(conv, d, p, 110, 55);

		osmo_conv_encode(&gsm0503_tch_ahs_6_7, conv, cB + 4);

		memcpy(cB + 204, d + 110, 24);

		break;
	case 2: /* TCH/AHS5.9 */
		if (len != 15)
			goto invalid_length;

		tch_amr_disassemble(d, tch_data, 118);

		osmo_crc8gen_set_bits(&gsm0503_amr_crc6, d, 55, p);

		tch_amr_merge(conv, d, p, 102, 55);

		osmo_conv_encode(&gsm0503_tch_ahs_5_9, conv, cB + 4);

		memcpy(cB + 212, d + 102, 16);

		break;
	case 1: /* TCH/AHS5.15 */
		if (len != 13)
			goto invalid_length;

		tch_amr_disassemble(d, tch_data, 103);

		osmo_crc8gen_set_bits(&gsm0503_amr_crc6, d, 49, p);

		tch_amr_merge(conv, d, p, 91, 49);

		osmo_conv_encode(&gsm0503_tch_ahs_5_15, conv, cB + 4);

		memcpy(cB + 216, d + 91, 12);

		break;
	case 0: /* TCH/AHS4.75 */
		if (len != 12)
			goto invalid_length;

		tch_amr_disassemble(d, tch_data, 95);

		osmo_crc8gen_set_bits(&gsm0503_amr_crc6, d, 39, p);

		tch_amr_merge(conv, d, p, 83, 39);

		osmo_conv_encode(&gsm0503_tch_ahs_4_75, conv, cB + 4);

		memcpy(cB + 216, d + 83, 12);

		break;
	default:
		/* FIXME: FT %ft is not supported */
		return -1;
	}

	memcpy(cB, gsm0503_afs_ic_ubit[id], 4);

	gsm0503_tch_hr_interleave(cB, iB);

	for (i = 0; i < 4; i++)
		gsm0503_tch_burst_map(&iB[i * 114], &bursts[i * 116], &h, i >> 1);

	return 0;

invalid_length:
	/* FIXME: payload length %len does not comply with codec type %ft */
	return -1;
}

/*
 * GSM RACH transcoding
 */

/*
 * GSM RACH apply BSIC to parity
 *
 * p(j) = p(j) xor b(j)     j = 0, ..., 5
 * b(0) = MSB of PLMN colour code
 * b(5) = LSB of BS colour code
 */
static inline void rach_apply_bsic(ubit_t *d, uint8_t bsic, uint8_t start)
{
	int i;

	/* Apply it */
	for (i = 0; i < 6; i++)
		d[start + i] ^= ((bsic >> (5 - i)) & 1);
}
/*
static inline int16_t rach_decode_ber(const sbit_t *burst, uint8_t bsic, bool is_11bit,
				      int *n_errors, int *n_bits_total)
{
	ubit_t conv[17];
	uint8_t ra[2] = { 0 }, nbits = is_11bit ? 11 : 8;
	int rv;

	osmo_conv_decode_ber(is_11bit ? &gsm0503_rach_ext : &gsm0503_rach, burst, conv,
			     n_errors, n_bits_total);

	rach_apply_bsic(conv, bsic, nbits);

	rv = osmo_crc8gen_check_bits(&gsm0503_rach_crc6, conv, nbits, conv + nbits);
	if (rv)
		return -1;

	osmo_ubit2pbit_ext(ra, 0, conv, 0, nbits, 1);

	return is_11bit ? osmo_load16le(ra) : ra[0];
}
*/

/*! Decode the Extended (11-bit) RACH according to 3GPP TS 45.003
 *  \param[out] ra output buffer for RACH data
 *  \param[in] burst Input burst data
 *  \param[in] bsic BSIC used in this cell
 *  \returns 0 on success; negative on error (e.g. CRC error) *
int gsm0503_rach_ext_decode(uint16_t *ra, const sbit_t *burst, uint8_t bsic)
{
	int16_t r = rach_decode_ber(burst, bsic, true, NULL, NULL);

	if (r < 0)
		return r;

	*ra = r;

	return 0;
}

/*! Decode the (8-bit) RACH according to TS 05.03
 *  \param[out] ra output buffer for RACH data
 *  \param[in] burst Input burst data
 *  \param[in] bsic BSIC used in this cell
 *  \returns 0 on success; negative on error (e.g. CRC error) *
int gsm0503_rach_decode(uint8_t *ra, const sbit_t *burst, uint8_t bsic)
{
	int16_t r = rach_decode_ber(burst, bsic, false, NULL, NULL);
	if (r < 0)
		return r;

	*ra = r;
	return 0;
}

/*! Decode the Extended (11-bit) RACH according to 3GPP TS 45.003
 *  \param[out] ra output buffer for RACH data
 *  \param[in] burst Input burst data
 *  \param[in] bsic BSIC used in this cell
 *  \param[out] n_errors Number of detected bit errors
 *  \param[out] n_bits_total Total number of bits
 *  \returns 0 on success; negative on error (e.g. CRC error) *
int gsm0503_rach_ext_decode_ber(uint16_t *ra, const sbit_t *burst, uint8_t bsic,
				int *n_errors, int *n_bits_total)
{
	int16_t r = rach_decode_ber(burst, bsic, true, n_errors, n_bits_total);
	if (r < 0)
		return r;

	*ra = r;
	return 0;
}

/*! Decode the (8-bit) RACH according to TS 05.03
 *  \param[out] ra output buffer for RACH data
 *  \param[in] burst Input burst data
 *  \param[in] bsic BSIC used in this cell
 *  \param[out] n_errors Number of detected bit errors
 *  \param[out] n_bits_total Total number of bits
 *  \returns 0 on success; negative on error (e.g. CRC error) *
int gsm0503_rach_decode_ber(uint8_t *ra, const sbit_t *burst, uint8_t bsic,
			    int *n_errors, int *n_bits_total)
{
	int16_t r = rach_decode_ber(burst, bsic, false, n_errors, n_bits_total);

	if (r < 0)
		return r;

	*ra = r;

	return 0;
}

/*! Encode the (8-bit) RACH according to TS 05.03
 *  \param[out] burst Caller-allocated output burst buffer
 *  \param[in] ra Input RACH data
 *  \param[in] bsic BSIC used in this cell
 *  \returns 0 on success; negative on error *
int gsm0503_rach_encode(ubit_t *burst, const uint8_t *ra, uint8_t bsic)
{
	return gsm0503_rach_ext_encode(burst, *ra, bsic, false);
}

/*! Encode the Extended (11-bit) or regular (8-bit) RACH according to 3GPP TS 45.003
 *  \param[out] burst Caller-allocated output burst buffer
 *  \param[in] ra11 Input RACH data
 *  \param[in] bsic BSIC used in this cell
 *  \param[in] is_11bit whether given RA is 11 bit or not
 *  \returns 0 on success; negative on error *
int gsm0503_rach_ext_encode(ubit_t *burst, uint16_t ra11, uint8_t bsic, bool is_11bit)
{
	ubit_t conv[17];
	uint8_t ra[2] = { 0 }, nbits = 8;

	if (is_11bit) {
		osmo_store16le(ra11, ra);
		nbits = 11;
	} else
		ra[0] = (uint8_t)ra11;

	osmo_pbit2ubit_ext(conv, 0, ra, 0, nbits, 1);

	osmo_crc8gen_set_bits(&gsm0503_rach_crc6, conv, nbits, conv + nbits);

	rach_apply_bsic(conv, bsic, nbits);

	osmo_conv_encode(is_11bit ? &gsm0503_rach_ext : &gsm0503_rach, conv, burst);

	return 0;
}

/*
 * GSM SCH transcoding
 */

/*! Decode the SCH according to TS 05.03
 *  \param[out] sb_info output buffer for SCH data
 *  \param[in] burst Input burst data
 *  \returns 0 on success; negative on error (e.g. CRC error) */
int gsm0503_sch_decode(uint8_t *sb_info, const sbit_t *burst)
{
	ubit_t conv[35];
	int rv;

	osmo_conv_decode(&gsm0503_sch, burst, conv);

	rv = osmo_crc16gen_check_bits(&gsm0503_sch_crc10, conv, 25, conv + 25);
	if (rv)
		return -1;

	osmo_ubit2pbit_ext(sb_info, 0, conv, 0, 25, 1);

	return 0;
}

/*! Encode the SCH according to TS 05.03
 *  \param[out] burst Caller-allocated output burst buffer
 *  \param[in] sb_info Input SCH data
 *  \returns 0 on success; negative on error */
int gsm0503_sch_encode(ubit_t *burst, const uint8_t *sb_info)
{
	ubit_t conv[35];

	osmo_pbit2ubit_ext(conv, 0, sb_info, 0, 25, 1);

	osmo_crc16gen_set_bits(&gsm0503_sch_crc10, conv, 25, conv + 25);

	osmo_conv_encode(&gsm0503_sch, conv, burst);

	return 0;
}

/*! @} */
