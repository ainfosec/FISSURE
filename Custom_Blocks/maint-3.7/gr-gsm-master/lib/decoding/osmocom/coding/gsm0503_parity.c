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

#include <osmocom/core/crcgen.h>
#include <osmocom/coding/gsm0503_parity.h>

/*! \addtogroup parity
 *  @{
 *
 *  GSM TS 05.03 parity
 *
 *  This module contains parity/crc code definitions for the various
 *  parity/crc schemes as defined in 3GPP TS 05.03 / 45.003
 *
 * \file gsm0503_parity.c */

/*! GSM (SACCH) parity (FIRE code)
 *
 * g(x) = (x^23 + 1)(x^17 + x^3 + 1)
 *      = x^40 + x^26 + x^23 + x^17 + x^3 + a1
 */
const struct osmo_crc64gen_code gsm0503_fire_crc40 = {
	.bits = 40,
	.poly = 0x0004820009ULL,
	.init = 0x0000000000ULL,
	.remainder = 0xffffffffffULL,
};

/*! GSM PDTCH CS-2, CS-3, CS-4 parity
 *
 * g(x) = x^16 + x^12 + x^5 + 1
 */
const struct osmo_crc16gen_code gsm0503_cs234_crc16 = {
	.bits = 16,
	.poly = 0x1021,
	.init = 0x0000,
	.remainder = 0xffff,
};

/*! EDGE MCS header parity
 *
 */
const struct osmo_crc8gen_code gsm0503_mcs_crc8_hdr = {
	.bits = 8,
	.poly = 0x49,
	.init = 0x00,
	.remainder = 0xff,
};

/*! EDGE MCS data parity
 *
 */
const struct osmo_crc16gen_code gsm0503_mcs_crc12 = {
	.bits = 12,
	.poly = 0x0d31,
	.init = 0x0000,
	.remainder = 0x0fff,
};

/*! GSM RACH parity
 *
 * g(x) = x^6 + x^5 + x^3 + x^2 + x^1 + 1
 */
const struct osmo_crc8gen_code gsm0503_rach_crc6 = {
	.bits = 6,
	.poly = 0x2f,
	.init = 0x00,
	.remainder = 0x3f,
};

/*! GSM SCH parity
 *
 * g(x) = x^10 + x^8 + x^6 + x^5 + x^4 + x^2 + 1
 */
const struct osmo_crc16gen_code gsm0503_sch_crc10 = {
	.bits = 10,
	.poly = 0x175,
	.init = 0x000,
	.remainder = 0x3ff,
};

/*! GSM TCH FR/HR/EFR parity
 *
 * g(x) = x^3 + x + 1
 */
const struct osmo_crc8gen_code gsm0503_tch_fr_crc3 = {
	.bits = 3,
	.poly = 0x3,
	.init = 0x0,
	.remainder = 0x7,
};

/*! GSM TCH EFR parity
 *
 * g(x) = x^8 + x^4 + x^3 + x^2 + 1
 */
const struct osmo_crc8gen_code gsm0503_tch_efr_crc8 = {
	.bits = 8,
	.poly = 0x1d,
	.init = 0x00,
	.remainder = 0x00,
};

/*! GSM AMR parity
 *
 * g(x) = x^6 + x^5 + x^3 + x^2 + x^1 + 1
 */
const struct osmo_crc8gen_code gsm0503_amr_crc6 = {
	.bits = 6,
	.poly = 0x2f,
	.init = 0x00,
	.remainder = 0x3f,
};

/*! @} */
