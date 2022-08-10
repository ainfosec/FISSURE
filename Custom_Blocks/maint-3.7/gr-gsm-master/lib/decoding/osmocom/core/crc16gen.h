/*
 * crc16gen.h
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

/*! \file crc16gen.h
 * Osmocom generic CRC routines (for max 16 bits poly) header
 */


#include <stdint.h>
#include <osmocom/core/bits.h>


/*! \brief structure describing a given CRC code of max 16 bits */
struct osmo_crc16gen_code {
	int bits;           /*!< \brief Actual number of bits of the CRC */
	uint16_t poly;      /*!< \brief Polynom (normal representation, MSB omitted */
	uint16_t init;      /*!< \brief Initialization value of the CRC state */
	uint16_t remainder; /*!< \brief Remainder of the CRC (final XOR) */
};

uint16_t osmo_crc16gen_compute_bits(const struct osmo_crc16gen_code *code,
                                    const ubit_t *in, int len);
int osmo_crc16gen_check_bits(const struct osmo_crc16gen_code *code,
                             const ubit_t *in, int len, const ubit_t *crc_bits);
void osmo_crc16gen_set_bits(const struct osmo_crc16gen_code *code,
                            const ubit_t *in, int len, ubit_t *crc_bits);


/*! @} */

/* vim: set syntax=c: */
