/*
 * (C) 2013 by Andreas Eversberg <jolly@eversberg.eu>
 * (C) 2016 by Tom Tsou <tom.tsou@ettus.com>
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
#include <osmocom/coding/gsm0503_mapping.h>

/*! \addtogroup mapping
 *  @{
 *
 *  GSM TS 05.03 burst mapping
 *
 *  This module contains burst mapping routines as specified in 3GPP TS
 *  05.03 / 45.003.
 *
 * \file gsm0503_mapping.c */

void gsm0503_xcch_burst_unmap(sbit_t *iB, const sbit_t *eB,
	sbit_t *hl, sbit_t *hn)
{
	memcpy(iB,      eB,      57);
	memcpy(iB + 57, eB + 59, 57);

	if (hl)
		*hl = eB[57];

	if (hn)
		*hn = eB[58];
}

void gsm0503_xcch_burst_map(const ubit_t *iB, ubit_t *eB, const ubit_t *hl,
	const ubit_t *hn)
{
	memcpy(eB,      iB,      57);
	memcpy(eB + 59, iB + 57, 57);

	if (hl)
		eB[57] = *hl;
	if (hn)
		eB[58] = *hn;
}

void gsm0503_tch_burst_unmap(sbit_t *iB, const sbit_t *eB, sbit_t *h, int odd)
{
	int i;

	/* brainfuck: only copy even or odd bits */
	if (iB) {
		for (i = odd; i < 57; i += 2)
			iB[i] = eB[i];
		for (i = 58 - odd; i < 114; i += 2)
			iB[i] = eB[i + 2];
	}

	if (h) {
		if (!odd)
			*h = eB[58];
		else
			*h = eB[57];
	}
}

void gsm0503_tch_burst_map(const ubit_t *iB, ubit_t *eB, const ubit_t *h, int odd)
{
	int i;

	/* brainfuck: only copy even or odd bits */
	if (eB) {
		for (i = odd; i < 57; i += 2)
			eB[i] = iB[i];
		for (i = 58 - odd; i < 114; i += 2)
			eB[i + 2] = iB[i];
		if (h)
			eB[odd ? 57 : 58] = *h;
	}
}

void gsm0503_mcs5_dl_burst_map(const ubit_t *di, ubit_t *eB,
	const ubit_t *hi, const ubit_t *up, int B)
{
	int j;
	int q[8] = { 0, 0, 0, 0, 0, 0, 0, 0, };

	for (j = 0; j < 156; j++)
		eB[j] = di[312 * B + j];
	for (j = 156; j < 168; j++)
		eB[j] = hi[25 * B + j - 156];
	for (j = 168; j < 174; j++)
		eB[j] = up[9 * B + j - 168];
	for (j = 174; j < 176; j++)
		eB[j] = q[2 * B + j - 174];
	for (j = 176; j < 179; j++)
		eB[j] = up[9 * B + j - 170];
	for (j = 179; j < 192; j++)
		eB[j] = hi[25 * B + j - 167];
	for (j = 192; j < 348; j++)
		eB[j] = di[312 * B + j - 36];
}

void gsm0503_mcs5_dl_burst_unmap(sbit_t *di, const sbit_t *eB,
	sbit_t *hi, sbit_t *up, int B)
{
	int j;

	for (j = 0; j < 156; j++)
		di[312 * B + j] = eB[j];
	for (j = 156; j < 168; j++)
		hi[25 * B + j - 156] = eB[j];
	for (j = 168; j < 174; j++)
		up[9 * B + j - 168] = eB[j];

	for (j = 176; j < 179; j++)
		up[9 * B + j - 170] = eB[j];
	for (j = 179; j < 192; j++)
		hi[25 * B + j - 167] = eB[j];
	for (j = 192; j < 348; j++)
		di[312 * B + j - 36] = eB[j];
}

void gsm0503_mcs5_ul_burst_map(const ubit_t *di, ubit_t *eB,
	const ubit_t *hi, int B)
{
	int j;

	for (j = 0; j < 156; j++)
		eB[j] = di[312 * B + j];
	for (j = 156; j < 174; j++)
		eB[j] = hi[34 * B + j - 156];
	for (j = 174; j < 176; j++)
		eB[j] = 0;
	for (j = 176; j < 192; j++)
		eB[j] = hi[34 * B + j - 158];
	for (j = 192; j < 348; j++)
		eB[j] = di[312 * B + j - 36];
}

void gsm0503_mcs5_ul_burst_unmap(sbit_t *di, const sbit_t *eB,
	sbit_t *hi, int B)
{
	int j;

	for (j = 0; j < 156; j++)
		di[312 * B + j] = eB[j];
	for (j = 156; j < 174; j++)
		hi[34 * B + j - 156] = eB[j];
	for (j = 176; j < 192; j++)
		hi[34 * B + j - 158] = eB[j];
	for (j = 192; j < 348; j++)
		di[312 * B + j - 36] = eB[j];
}

void gsm0503_mcs7_dl_burst_map(const ubit_t *di, ubit_t *eB,
	const ubit_t *hi, const ubit_t *up, int B)
{
	int j;
	int q[8] = { 1, 1, 1, 0, 0, 1, 1, 1, };

	for (j = 0; j < 153; j++)
		eB[j] = di[306 * B + j];
	for (j = 153; j < 168; j++)
		eB[j] = hi[31 * B + j - 153];
	for (j = 168; j < 174; j++)
		eB[j] = up[9 * B + j - 168];
	for (j = 174; j < 176; j++)
		eB[j] = q[2 * B + j - 174];
	for (j = 176; j < 179; j++)
		eB[j] = up[9 * B + j - 170];
	for (j = 179; j < 195; j++)
		eB[j] = hi[31 * B + j - 164];
	for (j = 195; j < 348; j++)
		eB[j] = di[306 * B + j - 42];
}

void gsm0503_mcs7_dl_burst_unmap(sbit_t *di, const sbit_t *eB,
	sbit_t *hi, sbit_t *up, int B)
{
	int j;

	for (j = 0; j < 153; j++)
		di[306 * B + j] = eB[j];
	for (j = 153; j < 168; j++)
		hi[31 * B + j - 153] = eB[j];
	for (j = 168; j < 174; j++)
		up[9 * B + j - 168] = eB[j];

	for (j = 176; j < 179; j++)
		up[9 * B + j - 170] = eB[j];
	for (j = 179; j < 195; j++)
		hi[31 * B + j - 164] = eB[j];
	for (j = 195; j < 348; j++)
		di[306 * B + j - 42] = eB[j];
}

void gsm0503_mcs7_ul_burst_map(const ubit_t *di, ubit_t *eB,
	const ubit_t *hi, int B)
{
	int j;
	int q[8] = { 1, 1, 1, 0, 0, 1, 1, 1, };

	for (j = 0; j < 153; j++)
		eB[j] = di[306 * B + j];
	for (j = 153; j < 174; j++)
		eB[j] = hi[40 * B + j - 153];
	for (j = 174; j < 176; j++)
		eB[j] = q[2 * B + j - 174];
	for (j = 176; j < 195; j++)
		eB[j] = hi[40 * B + j - 155];
	for (j = 195; j < 348; j++)
		eB[j] = di[306 * B + j - 42];
}

void gsm0503_mcs7_ul_burst_unmap(sbit_t *di, const sbit_t *eB,
	sbit_t *hi, int B)
{
	int j;

	for (j = 0; j < 153; j++)
		di[306 * B + j] = eB[j];
	for (j = 153; j < 174; j++)
		hi[40 * B + j - 153] = eB[j];

	for (j = 176; j < 195; j++)
		hi[40 * B + j - 155] = eB[j];
	for (j = 195; j < 348; j++)
		di[306 * B + j - 42] = eB[j];
}

void gsm0503_mcs5_burst_swap(sbit_t *eB)
{
	sbit_t t[14];

	t[0]  = eB[155];
	t[1]  = eB[158];
	t[2]  = eB[161];
	t[3]  = eB[164];
	t[4]  = eB[167];
	t[5]  = eB[170];
	t[6]  = eB[173];
	t[7]  = eB[195];
	t[8]  = eB[196];
	t[9]  = eB[198];
	t[10] = eB[199];
	t[11] = eB[201];
	t[12] = eB[202];
	t[13] = eB[204];

	eB[155] = eB[142];
	eB[158] = eB[144];
	eB[161] = eB[145];
	eB[164] = eB[147];
	eB[167] = eB[148];
	eB[170] = eB[150];
	eB[173] = eB[151];
	eB[195] = eB[176];
	eB[196] = eB[179];
	eB[198] = eB[182];
	eB[199] = eB[185];
	eB[201] = eB[188];
	eB[202] = eB[191];
	eB[204] = eB[194];

	eB[142] = t[0];
	eB[144] = t[1];
	eB[145] = t[2];
	eB[147] = t[3];
	eB[148] = t[4];
	eB[150] = t[5];
	eB[151] = t[6];
	eB[176] = t[7];
	eB[179] = t[8];
	eB[182] = t[9];
	eB[185] = t[10];
	eB[188] = t[11];
	eB[191] = t[12];
	eB[194] = t[13];
}

/*! @} */
