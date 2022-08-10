/* (C) 2009 by Harald Welte <laforge@gnumonks.org>
 * (C) 2012 Ivan Klyuchnikov
 * (C) 2015 sysmocom - s.f.m.c. GmbH
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
 *
 */

#pragma once

/*! \defgroup bitvec Bit vectors
 *  @{
 * \file bitvec.h */

#include <stdint.h>
//#include <osmocom/core/talloc.h>
#include <osmocom/core/defs.h>
#include <stdbool.h>

/*! A single GSM bit
 *
 * In GSM mac blocks, every bit can be 0 or 1, or L or H.  L/H are
 * defined relative to the 0x2b padding pattern */
enum bit_value {
	ZERO	= 0, 	/*!< A zero (0) bit */
	ONE	= 1,	/*!< A one (1) bit */
	L	= 2,	/*!< A CSN.1 "L" bit */
	H	= 3,	/*!< A CSN.1 "H" bit */
};

/*! structure describing a bit vector */
struct bitvec {
	unsigned int cur_bit;	/*!< cursor to the next unused bit */
	unsigned int data_len;	/*!< length of data array in bytes */
	uint8_t *data;		/*!< pointer to data array */
};

enum bit_value bitvec_get_bit_pos(const struct bitvec *bv, unsigned int bitnr);
enum bit_value bitvec_get_bit_pos_high(const struct bitvec *bv,
					unsigned int bitnr);
unsigned int bitvec_get_nth_set_bit(const struct bitvec *bv, unsigned int n);
int bitvec_set_bit_pos(struct bitvec *bv, unsigned int bitnum,
			enum bit_value bit);
int bitvec_set_bit(struct bitvec *bv, enum bit_value bit);
int bitvec_get_bit_high(struct bitvec *bv);
int bitvec_set_bits(struct bitvec *bv, const enum bit_value *bits, unsigned int count);
int bitvec_set_u64(struct bitvec *bv, uint64_t v, uint8_t num_bits, bool use_lh);
int bitvec_set_uint(struct bitvec *bv, unsigned int in, unsigned int count);
int bitvec_get_uint(struct bitvec *bv, unsigned int num_bits);
int bitvec_find_bit_pos(const struct bitvec *bv, unsigned int n, enum bit_value val);
int bitvec_spare_padding(struct bitvec *bv, unsigned int up_to_bit);
int bitvec_get_bytes(struct bitvec *bv, uint8_t *bytes, unsigned int count);
int bitvec_set_bytes(struct bitvec *bv, const uint8_t *bytes, unsigned int count);
/*struct bitvec *bitvec_alloc(unsigned int size, TALLOC_CTX *bvctx);*/
/*void bitvec_free(struct bitvec *bv);*/
int bitvec_unhex(struct bitvec *bv, const char *src);
unsigned int bitvec_pack(const struct bitvec *bv, uint8_t *buffer);
unsigned int bitvec_unpack(struct bitvec *bv, const uint8_t *buffer);
uint64_t bitvec_read_field(struct bitvec *bv, unsigned int *read_index, unsigned int len);
int bitvec_write_field(struct bitvec *bv, unsigned int *write_index, uint64_t val, unsigned int len);
int bitvec_fill(struct bitvec *bv, unsigned int num_bits, enum bit_value fill);
char bit_value_to_char(enum bit_value v);
void bitvec_to_string_r(const struct bitvec *bv, char *str);
void bitvec_zero(struct bitvec *bv);
unsigned bitvec_rl(const struct bitvec *bv, bool b);
unsigned bitvec_rl_curbit(struct bitvec *bv, bool b, int max_bits);
void bitvec_shiftl(struct bitvec *bv, unsigned int n);
int16_t bitvec_get_int16_msb(const struct bitvec *bv, unsigned int num_bits);
unsigned int bitvec_add_array(struct bitvec *bv, const uint32_t *array,
			      unsigned int array_len, bool dry_run,
			      unsigned int num_bits);

/*! @} */
