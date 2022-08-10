/*
 * (C) 2013 by Andreas Eversberg <jolly@eversberg.eu>
 * (C) 2016 by Tom Tsou <tom.tsou@ettus.com>
 * (C) 2017 by Hrald Welte <laforge@gnumonks.org>
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

#include <stdint.h>
#include <string.h>

#include <osmocom/core/bits.h>
#include <osmocom/coding/gsm0503_tables.h>
#include <osmocom/coding/gsm0503_interleaving.h>

/*! \addtogroup interleaving
 *  @{
 * GSM TS 05.03 interleaving
 *
 * This module contains interleaving / de-interleaving routines for
 * various channel types, as defined in 3GPP TS 05.03 / 45.003.
 *
 * GSM xCCH interleaving and burst mapping:
 *
 * Interleaving:
 *
 * Given 456 coded input bits, form 4 blocks of 114 bits:
 *
 *      i(B, j) = c(n, k)       k = 0, ..., 455
 *                              n = 0, ..., N, N + 1, ...
 *                              B = B_0 + 4n + (k mod 4)
 *                              j = 2(49k mod 57) + ((k mod 8) div 4)
 *
 * Mapping on Burst:
 *
 *      e(B, j) = i(B, j)
 *      e(B, 59 + j) = i(B, 57 + j)     j = 0, ..., 56
 *      e(B, 57) = h_l(B)
 *      e(B, 58) = h_n(B)
 *
 * Where hl(B) and hn(B) are bits in burst B indicating flags.
 *
 * GSM TCH HR/AHS interleaving and burst mapping:
 *
 * Interleaving:
 *
 * Given 288 coded input bits, form 4 blocks of 114 bits,
 * where even bits of the first 2 blocks and odd bits of the last 2 blocks
 * are used:
 *
 *      i(B, j) = c(n, k)       k = 0, ..., 227
 *                              n = 0, ..., N, N + 1, ...
 *                              B = B_0 + 2n + b
 *                              j, b = table[k];
 *
 * Mapping on Burst:
 *
 *      e(B, j) = i(B, j)
 *      e(B, 59 + j) = i(B, 57 + j)     j = 0, ..., 56
 *      e(B, 57) = h_l(B)
 *      e(B, 58) = h_n(B)
 *
 * Where hl(B) and hn(B) are bits in burst B indicating flags.
 *
 * \file gsm0503_interleaving.c */

/*! De-Interleave burst bits according to TS 05.03 4.1.4
 *  \param[out] cB caller-allocated output buffer for 456 soft coded bits
 *  \param[in] iB 456 soft input bits */
void gsm0503_xcch_deinterleave(sbit_t *cB, const sbit_t *iB)
{
	int j, k, B;

	for (k = 0; k < 456; k++) {
		B = k & 3;
		j = 2 * ((49 * k) % 57) + ((k & 7) >> 2);
		cB[k] = iB[B * 114 + j];
	}
}

/*! Interleave burst bits according to TS 05.03 4.1.4
 *  \param[out] iB caller-allocated output buffer for 456 soft interleaved bits
 *  \param[in] cB 456 soft input coded bits */
void gsm0503_xcch_interleave(const ubit_t *cB, ubit_t *iB)
{
	int j, k, B;

	for (k = 0; k < 456; k++) {
		B = k & 3;
		j = 2 * ((49 * k) % 57) + ((k & 7) >> 2);
		iB[B * 114 + j] = cB[k];
	}
}

/*! De-Interleave MCS1 DL burst bits according to TS 05.03 5.1.5.1.5
 *  \param[out] u caller-allocated output buffer for 12 soft coded bits
 *  \param[out] hc caller-allocated output buffer for 68 soft coded bits
 *  \param[out] dc caller-allocated output buffer for 372 soft coded bits
 *  \param[in] iB 452 interleaved soft input bits */
void gsm0503_mcs1_dl_deinterleave(sbit_t *u, sbit_t *hc,
	sbit_t *dc, const sbit_t *iB)
{
	int k;
	sbit_t c[452];
	sbit_t cp[456];

	gsm0503_xcch_deinterleave(cp, iB);

	for (k = 0; k < 25; k++)
		c[k] = cp[k];
	for (k = 26; k < 82; k++)
		c[k - 1] = cp[k];
	for (k = 83; k < 139; k++)
		c[k - 2] = cp[k];
	for (k = 140; k < 424; k++)
		c[k - 3] = cp[k];
	for (k = 425; k < 456; k++)
		c[k - 4] = cp[k];

	if (u) {
		for (k = 0; k < 12; k++)
			u[k] = c[k];
	}

	if (hc) {
		for (k = 12; k < 80; k++)
			hc[k - 12] = c[k];
	}

	if (dc) {
		for (k = 80; k < 452; k++)
			dc[k - 80] = c[k];
	}
}

/*! Interleave MCS1 DL burst bits according to TS 05.03 5.1.5.1.5
 *  \param[in] up 12 input soft coded bits (usf)
 *  \param[in] hc 68 input soft coded bits (header)
 *  \param[in] dc 372 input soft bits (data)
 *  \param[out] iB 456 interleaved soft output bits */
void gsm0503_mcs1_dl_interleave(const ubit_t *up, const ubit_t *hc,
	const ubit_t *dc, ubit_t *iB)
{
	int k;
	ubit_t c[452];
	ubit_t cp[456];

	for (k = 0; k < 12; k++)
		c[k] = up[k];
	for (k = 12; k < 80; k++)
		c[k] = hc[k - 12];
	for (k = 80; k < 452; k++)
		c[k] = dc[k - 80];

	for (k = 0; k < 25; k++)
		cp[k] = c[k];
	for (k = 26; k < 82; k++)
		cp[k] = c[k - 1];
	for (k = 83; k < 139; k++)
		cp[k] = c[k - 2];
	for (k = 140; k < 424; k++)
		cp[k] = c[k - 3];
	for (k = 425; k < 456; k++)
		cp[k] = c[k - 4];

	cp[25] = 0;
	cp[82] = 0;
	cp[139] = 0;
	cp[424] = 0;

	gsm0503_xcch_interleave(cp, iB);
}

/*! Interleave MCS1 UL burst bits according to TS 05.03 5.1.5.2.4
 *  \param[out] hc caller-allocated output buffer for 80 soft coded header bits
 *  \param[out] dc caller-allocated output buffer for 372 soft coded data bits
 *  \param[in] iB 456 interleaved soft input bits */
void gsm0503_mcs1_ul_deinterleave(sbit_t *hc, sbit_t *dc, const sbit_t *iB)
{
	int k;
	sbit_t c[452];
	sbit_t cp[456];

	gsm0503_xcch_deinterleave(cp, iB);

	for (k = 0; k < 25; k++)
		c[k] = cp[k];
	for (k = 26; k < 82; k++)
		c[k - 1] = cp[k];
	for (k = 83; k < 139; k++)
		c[k - 2] = cp[k];
	for (k = 140; k < 424; k++)
		c[k - 3] = cp[k];
	for (k = 425; k < 456; k++)
		c[k - 4] = cp[k];

	if (hc) {
		for (k = 0; k < 80; k++)
			hc[k] = c[k];
	}

	if (dc) {
		for (k = 80; k < 452; k++)
			dc[k - 80] = c[k];
	}
}

/*! Interleave MCS1 DL burst bits according to TS 05.03 5.1.5.2.4
 *  \param[in] hc 80 input coded bits (header)
 *  \param[in] dc 372 input bits (data)
 *  \param[out] iB 456 interleaved output bits */
void gsm0503_mcs1_ul_interleave(const ubit_t *hc, const ubit_t *dc, ubit_t *iB)
{
	int k;
	ubit_t c[452];
	ubit_t cp[456];

	for (k = 0; k < 80; k++)
		c[k] = hc[k];
	for (k = 80; k < 452; k++)
		c[k] = dc[k - 80];

	for (k = 0; k < 25; k++)
		cp[k] = c[k];
	for (k = 26; k < 82; k++)
		cp[k] = c[k - 1];
	for (k = 83; k < 139; k++)
		cp[k] = c[k - 2];
	for (k = 140; k < 424; k++)
		cp[k] = c[k - 3];
	for (k = 425; k < 456; k++)
		cp[k] = c[k - 4];

	cp[25] = 0;
	cp[82] = 0;
	cp[139] = 0;
	cp[424] = 0;

	gsm0503_xcch_interleave(cp, iB);
}

/*! Interleave MCS5 UL burst bits according to TS 05.03 5.1.9.2.4
 *  \param[in] hc 136 soft coded header input bits
 *  \param[in] dc 1248 soft coded data input bits
 *  \param[out] hi 136 interleaved header output bits
 *  \param[out] di 1248 interleaved data output bits */
void gsm0503_mcs5_ul_interleave(const ubit_t *hc, const ubit_t *dc,
	ubit_t *hi, ubit_t *di)
{
	int j, k;

	/* Header */
	for (k = 0; k < 136; k++) {
		j = 34 * (k % 4) + 2 * (11 * k % 17) + k % 8 / 4;
		hi[j] = hc[k];
	}

	/* Data */
	for (k = 0; k < 1248; k++) {
		j = gsm0503_interleave_mcs5[k];
		di[j] = dc[k];
	}
}

/*! De-Interleave MCS5 UL burst bits according to TS 05.03 5.1.9.2.4
 *  \param[out] hc caller-allocated output buffer for 136 soft coded header bits
 *  \param[out] dc caller-allocated output buffer for 1248 soft coded data bits
 *  \param[in] iB interleaved soft input bits */
void gsm0503_mcs5_ul_deinterleave(sbit_t *hc, sbit_t *dc,
	const sbit_t *hi, const sbit_t *di)
{
	int j, k;

	/* Header */
	if (hc) {
		for (k = 0; k < 136; k++) {
			j = 34 * (k % 4) + 2 * (11 * k % 17) + k % 8 / 4;
			hc[k] = hi[j];
		}
	}

	/* Data */
	if (dc) {
		for (k = 0; k < 1248; k++) {
			j = gsm0503_interleave_mcs5[k];
			dc[k] = di[j];
		}
	}
}

/*! Interleave MCS5 DL burst bits according to TS 05.03 5.1.9.1.5
 *  \param[in] hc 100 soft coded header input bits
 *  \param[in] dc 1248 soft coded data input bits
 *  \param[out] hi 100 interleaved header output bits
 *  \param[out] di 1248 interleaved data output bits */
void gsm0503_mcs5_dl_interleave(const ubit_t *hc, const ubit_t *dc,
	ubit_t *hi, ubit_t *di)
{
	int j, k;

	/* Header */
	for (k = 0; k < 100; k++) {
		j = 25 * (k % 4) + ((17 * k) % 25);
		hi[j] = hc[k];
	}

	/* Data */
	for (k = 0; k < 1248; k++) {
		j = gsm0503_interleave_mcs5[k];
		di[j] = dc[k];
	}
}

/*! De-Interleave MCS5 UL burst bits according to TS 05.03 5.1.9.1.5
 *  \param[out] hc caller-allocated output buffer for 100 soft coded header bits
 *  \param[out] dc caller-allocated output buffer for 1248 soft coded data bits
 *  \param[in] iB interleaved soft input bits */
void gsm0503_mcs5_dl_deinterleave(sbit_t *hc, sbit_t *dc,
	const sbit_t *hi, const sbit_t *di)
{
	int j, k;

	/* Header */
	if (hc) {
		for (k = 0; k < 100; k++) {
			j = 25 * (k % 4) + ((17 * k) % 25);
			hc[k] = hi[j];
		}
	}

	/* Data */
	if (dc) {
		for (k = 0; k < 1248; k++) {
			j = gsm0503_interleave_mcs5[k];
			dc[k] = di[j];
		}
	}
}

/*! Interleave MCS7 DL burst bits according to TS 05.03 5.1.11.1.5
 *  \param[in] hc 124 soft coded header input bits
 *  \param[in] c1 612 soft coded data input bits
 *  \param[in] c2 612 soft coded data input bits
 *  \param[out] hi 124 interleaved header output bits
 *  \param[out] di 1224 interleaved data output bits */
void gsm0503_mcs7_dl_interleave(const ubit_t *hc, const ubit_t *c1,
	const ubit_t *c2, ubit_t *hi, ubit_t *di)
{
	int j, k;
	ubit_t dc[1224];

	/* Header */
	for (k = 0; k < 124; k++) {
		j = 31 * (k % 4) + ((17 * k) % 31);
		hi[j] = hc[k];
	}

	memcpy(&dc[0], c1, 612);
	memcpy(&dc[612], c2, 612);

	/* Data */
	for (k = 0; k < 1224; k++) {
		j = 306 * (k % 4) + 3 * (44 * k % 102 + k / 4 % 2) +
			(k + 2 - k / 408) % 3;
		di[j] = dc[k];
	}
}

/*! De-Interleave MCS7 DL burst bits according to TS 05.03 5.1.11.1.5
 *  \param[out] hc caller-allocated output buffer for 124 soft coded header bits
 *  \param[out] c1 caller-allocated output buffer for 612 soft coded data bits
 *  \param[out] c2 caller-allocated output buffer for 612 soft coded data bits
 *  \param[in] hi interleaved soft input header bits
 *  \param[in] di interleaved soft input data bits */
void gsm0503_mcs7_dl_deinterleave(sbit_t *hc, sbit_t *c1, sbit_t *c2,
	const sbit_t *hi, const sbit_t *di)
{
	int j, k;
	ubit_t dc[1224];

	/* Header */
	if (hc) {
		for (k = 0; k < 124; k++) {
			j = 31 * (k % 4) + ((17 * k) % 31);
			hc[k] = hi[j];
		}
	}

	/* Data */
	if (c1 && c2) {
		for (k = 0; k < 1224; k++) {
			j = 306 * (k % 4) + 3 * (44 * k % 102 + k / 4 % 2) +
	(k + 2 - k / 408) % 3;
			dc[k] = di[j];
		}

		memcpy(c1, &dc[0], 612);
		memcpy(c2, &dc[612], 612);
	}
}

/*! Interleave MCS7 UL burst bits according to TS 05.03 5.1.11.2.4
 *  \param[in] hc 124 soft coded header input bits
 *  \param[in] c1 612 soft coded data input bits
 *  \param[in] c2 612 soft coded data input bits
 *  \param[out] hi 124 interleaved header output bits
 *  \param[out] di 1224 interleaved data output bits */
void gsm0503_mcs7_ul_interleave(const ubit_t *hc, const ubit_t *c1,
	const ubit_t *c2, ubit_t *hi, ubit_t *di)
{
	int j, k;
	ubit_t dc[1224];

	/* Header */
	for (k = 0; k < 160; k++) {
		j = 40 * (k % 4) + 2 * (13 * (k / 8) % 20) + k % 8 / 4;
		hi[j] = hc[k];
	}

	memcpy(&dc[0], c1, 612);
	memcpy(&dc[612], c2, 612);

	/* Data */
	for (k = 0; k < 1224; k++) {
		j = 306 * (k % 4) + 3 * (44 * k % 102 + k / 4 % 2) +
			(k + 2 - k / 408) % 3;
		di[j] = dc[k];
	}
}

/*! De-Interleave MCS7 UL burst bits according to TS 05.03 5.1.11.2.4
 *  \param[out] hc caller-allocated output buffer for 160 soft coded header bits
 *  \param[out] c1 caller-allocated output buffer for 612 soft coded data bits
 *  \param[out] c2 caller-allocated output buffer for 612 soft coded data bits
 *  \param[in] hi interleaved soft input header bits
 *  \param[in] di interleaved soft input data bits */
void gsm0503_mcs7_ul_deinterleave(sbit_t *hc, sbit_t *c1, sbit_t *c2,
	const sbit_t *hi, const sbit_t *di)
{
	int j, k;
	ubit_t dc[1224];

	/* Header */
	if (hc) {
		for (k = 0; k < 160; k++) {
			j = 40 * (k % 4) + 2 * (13 * (k / 8) % 20) + k % 8 / 4;
			hc[k] = hi[j];
		}
	}

	/* Data */
	if (c1 && c2) {
		for (k = 0; k < 1224; k++) {
			j = 306 * (k % 4) + 3 * (44 * k % 102 + k / 4 % 2) +
	(k + 2 - k / 408) % 3;
			dc[k] = di[j];
		}

		memcpy(c1, &dc[0], 612);
		memcpy(c2, &dc[612], 612);
	}
}

/*! Interleave MCS8 UL burst bits according to TS 05.03 5.1.12.2.4
 *  \param[in] hc 160 soft coded header input bits
 *  \param[in] c1 612 soft coded data input bits
 *  \param[in] c2 612 soft coded data input bits
 *  \param[out] hi 160 interleaved header output bits
 *  \param[out] di 1224 interleaved data output bits */
void gsm0503_mcs8_ul_interleave(const ubit_t *hc, const ubit_t *c1,
	const ubit_t *c2, ubit_t *hi, ubit_t *di)
{
	int j, k;
	ubit_t dc[1224];

	/* Header */
	for (k = 0; k < 160; k++) {
		j = 40 * (k % 4) + 2 * (13 * (k / 8) % 20) + k % 8 / 4;
		hi[j] = hc[k];
	}

	memcpy(&dc[0], c1, 612);
	memcpy(&dc[612], c2, 612);

	/* Data */
	for (k = 0; k < 1224; k++) {
		j = 306 * (2 * (k / 612) + (k % 2)) +
			3 * (74 * k % 102 + k / 2 % 2) + (k + 2 - k / 204) % 3;
		di[j] = dc[k];
	}
}


/*! De-Interleave MCS8 UL burst bits according to TS 05.03 5.1.12.2.4
 *  \param[out] hc caller-allocated output buffer for 160 soft coded header bits
 *  \param[out] c1 caller-allocated output buffer for 612 soft coded data bits
 *  \param[out] c2 caller-allocated output buffer for 612 soft coded data bits
 *  \param[in] hi interleaved soft input header bits
 *  \param[in] di interleaved soft input data bits */
void gsm0503_mcs8_ul_deinterleave(sbit_t *hc, sbit_t *c1, sbit_t *c2,
	const sbit_t *hi, const sbit_t *di)
{
	int j, k;
	ubit_t dc[1224];

	/* Header */
	if (hc) {
		for (k = 0; k < 160; k++) {
			j = 40 * (k % 4) + 2 * (13 * (k / 8) % 20) + k % 8 / 4;
			hc[k] = hi[j];
		}
	}

	/* Data */
	if (c1 && c2) {
		for (k = 0; k < 1224; k++) {
			j = 306 * (2 * (k / 612) + (k % 2)) +
	3 * (74 * k % 102 + k / 2 % 2) + (k + 2 - k / 204) % 3;
			dc[k] = di[j];
		}

		memcpy(c1, &dc[0], 612);
		memcpy(c2, &dc[612], 612);
	}
}

/*! Interleave MCS8 DL burst bits according to TS 05.03 5.1.12.1.5
 *  \param[in] hc 124 soft coded header input bits
 *  \param[in] c1 612 soft coded data input bits
 *  \param[in] c2 612 soft coded data input bits
 *  \param[out] hi 124 interleaved header output bits
 *  \param[out] di 1224 interleaved data output bits */
void gsm0503_mcs8_dl_interleave(const ubit_t *hc, const ubit_t *c1,
	const ubit_t *c2, ubit_t *hi, ubit_t *di)
{
	int j, k;
	ubit_t dc[1224];

	/* Header */
	for (k = 0; k < 124; k++) {
		j = 31 * (k % 4) + ((17 * k) % 31);
		hi[j] = hc[k];
	}

	memcpy(&dc[0], c1, 612);
	memcpy(&dc[612], c2, 612);

	/* Data */
	for (k = 0; k < 1224; k++) {
		j = 306 * (2 * (k / 612) + (k % 2)) +
			3 * (74 * k % 102 + k / 2 % 2) + (k + 2 - k / 204) % 3;
		di[j] = dc[k];
	}
}

/*! De-Interleave MCS8 DL burst bits according to TS 05.03 5.1.12.1.5
 *  \param[out] hc caller-allocated output buffer for 124 soft coded header bits
 *  \param[out] c1 caller-allocated output buffer for 612 soft coded data bits
 *  \param[out] c2 caller-allocated output buffer for 612 soft coded data bits
 *  \param[in] hi interleaved soft input header bits
 *  \param[in] di interleaved soft input data bits */
void gsm0503_mcs8_dl_deinterleave(sbit_t *hc, sbit_t *c1, sbit_t *c2,
	const sbit_t *hi, const sbit_t *di)
{
	int j, k;
	ubit_t dc[1224];

	/* Header */
	if (hc) {
		for (k = 0; k < 124; k++) {
			j = 31 * (k % 4) + ((17 * k) % 31);
			hc[k] = hi[j];
		}
	}

	/* Data */
	if (c1 && c2) {
		for (k = 0; k < 1224; k++) {
			j = 306 * (2 * (k / 612) + (k % 2)) +
	3 * (74 * k % 102 + k / 2 % 2) + (k + 2 - k / 204) % 3;
			dc[k] = di[j];
		}

		memcpy(c1, &dc[0], 612);
		memcpy(c2, &dc[612], 612);
	}
}

/*
 * GSM TCH FR/EFR/AFS interleaving and burst mapping
 *
 * Interleaving:
 *
 * Given 456 coded input bits, form 8 blocks of 114 bits,
 * where even bits of the first 4 blocks and odd bits of the last 4 blocks
 * are used:
 *
 *      i(B, j) = c(n, k)       k = 0, ..., 455
 *                              n = 0, ..., N, N + 1, ...
 *                              B = B_0 + 4n + (k mod 8)
 *                              j = 2(49k mod 57) + ((k mod 8) div 4)
 *
 * Mapping on Burst:
 *
 *      e(B, j) = i(B, j)
 *      e(B, 59 + j) = i(B, 57 + j)     j = 0, ..., 56
 *      e(B, 57) = h_l(B)
 *      e(B, 58) = h_n(B)
 *
 * Where hl(B) and hn(B) are bits in burst B indicating flags.
 */

/*! GSM TCH FR/EFR/AFS De-Interleaving and burst mapping
 *  \param[out] cB caller-allocated buffer for 456 unpacked output bits
 *  \param[in] iB 456 unpacked interleaved input bits */
void gsm0503_tch_fr_deinterleave(sbit_t *cB, const sbit_t *iB)
{
	int j, k, B;

	for (k = 0; k < 456; k++) {
		B = k & 7;
		j = 2 * ((49 * k) % 57) + ((k & 7) >> 2);
		cB[k] = iB[B * 114 + j];
	}
}

/*! GSM TCH FR/EFR/AFS Interleaving and burst mapping
 *  \param[in] cB caller-allocated buffer for 456 unpacked input bits
 *  \param[out] iB 456 unpacked interleaved output bits */
void gsm0503_tch_fr_interleave(const ubit_t *cB, ubit_t *iB)
{
	int j, k, B;

	for (k = 0; k < 456; k++) {
		B = k & 7;
		j = 2 * ((49 * k) % 57) + ((k & 7) >> 2);
		iB[B * 114 + j] = cB[k];
	}
}

/*! GSM TCH HR/AHS De-Interleaving and burst mapping
 *  \param[out] cB caller-allocated buffer for 228 unpacked output bits
 *  \param[in] iB 228 unpacked interleaved input bits */
void gsm0503_tch_hr_deinterleave(sbit_t *cB, const sbit_t *iB)
{
	int j, k, B;

	for (k = 0; k < 228; k++) {
		B = gsm0503_tch_hr_interleaving[k][1];
		j = gsm0503_tch_hr_interleaving[k][0];
		cB[k] = iB[B * 114 + j];
	}
}

/*! GSM TCH HR/AHS Interleaving and burst mapping
 *  \param[in] cB caller-allocated buffer for 228 unpacked input bits
 *  \param[out] iB 228 unpacked interleaved output bits */
void gsm0503_tch_hr_interleave(const ubit_t *cB, ubit_t *iB)
{
	int j, k, B;

	for (k = 0; k < 228; k++) {
		B = gsm0503_tch_hr_interleaving[k][1];
		j = gsm0503_tch_hr_interleaving[k][0];
		iB[B * 114 + j] = cB[k];
	}
}

/*! @} */
