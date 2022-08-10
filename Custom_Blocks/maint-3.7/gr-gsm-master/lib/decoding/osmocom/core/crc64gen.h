/*
 * crc64gen.h
 *
 * Copyright (C) 2011  Sylvain Munaut <tnt@246tNt.com>
 *
 * All Rights Reserved
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

#pragma once

/*! \addtogroup crcgen
 *  @{
 */

/*! \file crc64gen.h
 * Osmocom generic CRC routines (for max 64 bits poly) header
 */


#include <stdint.h>
#include <osmocom/core/bits.h>


/*! \brief structure describing a given CRC code of max 64 bits */
struct osmo_crc64gen_code {
	int bits;           /*!< \brief Actual number of bits of the CRC */
	uint64_t poly;      /*!< \brief Polynom (normal representation, MSB omitted */
	uint64_t init;      /*!< \brief Initialization value of the CRC state */
	uint64_t remainder; /*!< \brief Remainder of the CRC (final XOR) */
};

uint64_t osmo_crc64gen_compute_bits(const struct osmo_crc64gen_code *code,
                                    const ubit_t *in, int len);
int osmo_crc64gen_check_bits(const struct osmo_crc64gen_code *code,
                             const ubit_t *in, int len, const ubit_t *crc_bits);
void osmo_crc64gen_set_bits(const struct osmo_crc64gen_code *code,
                            const ubit_t *in, int len, ubit_t *crc_bits);


/*! @} */

/* vim: set syntax=c: */
