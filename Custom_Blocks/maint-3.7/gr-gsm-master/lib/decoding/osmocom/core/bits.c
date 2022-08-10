/*
 * (C) 2011 by Harald Welte <laforge@gnumonks.org>
 * (C) 2011 by Sylvain Munaut <tnt@246tNt.com>
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

#include <osmocom/core/bits.h>

/*! \addtogroup bits
 *  @{
 *  Osmocom bit level support code.
 *
 *  This module implements the notion of different bit-fields, such as
 *  - unpacked bits (\ref ubit_t), i.e. 1 bit per byte
 *  - packed bits (\ref pbit_t), i.e. 8 bits per byte
 *  - soft bits (\ref sbit_t), 1 bit per byte from -127 to 127
 *
 * \file bits.c */

/*! convert unpacked bits to packed bits, return length in bytes
 *  \param[out] out output buffer of packed bits
 *  \param[in] in input buffer of unpacked bits
 *  \param[in] num_bits number of bits
 */
int osmo_ubit2pbit(pbit_t *out, const ubit_t *in, unsigned int num_bits)
{
	unsigned int i;
	uint8_t curbyte = 0;
	pbit_t *outptr = out;

	for (i = 0; i < num_bits; i++) {
		uint8_t bitnum = 7 - (i % 8);

		curbyte |= (in[i] << bitnum);

		if(i % 8 == 7){
			*outptr++ = curbyte;
			curbyte = 0;
		}
	}
	/* we have a non-modulo-8 bitcount */
	if (i % 8)
		*outptr++ = curbyte;

	return outptr - out;
}

/*! Shift unaligned input to octet-aligned output
 *  \param[out] out output buffer, unaligned
 *  \param[in] in input buffer, octet-aligned
 *  \param[in] num_nibbles number of nibbles
 */
void osmo_nibble_shift_right(uint8_t *out, const uint8_t *in,
			     unsigned int num_nibbles)
{
	unsigned int i, num_whole_bytes = num_nibbles / 2;
	if (!num_whole_bytes)
		return;

	/* first byte: upper nibble empty, lower nibble from src */
	out[0] = (in[0] >> 4);

	/* bytes 1.. */
	for (i = 1; i < num_whole_bytes; i++)
		out[i] = ((in[i - 1] & 0xF) << 4) | (in[i] >> 4);

	/* shift the last nibble, in case there's an odd count */
	i = num_whole_bytes;
	if (num_nibbles & 1)
		out[i] = ((in[i - 1] & 0xF) << 4) | (in[i] >> 4);
	else
		out[i] = (in[i - 1] & 0xF) << 4;
}

/*! Shift unaligned input to octet-aligned output
 *  \param[out] out output buffer, octet-aligned
 *  \param[in] in input buffer, unaligned
 *  \param[in] num_nibbles number of nibbles
 */
void osmo_nibble_shift_left_unal(uint8_t *out, const uint8_t *in,
				unsigned int num_nibbles)
{
	unsigned int i, num_whole_bytes = num_nibbles / 2;
	if (!num_whole_bytes)
		return;

	for (i = 0; i < num_whole_bytes; i++)
		out[i] = ((in[i] & 0xF) << 4) | (in[i + 1] >> 4);

	/* shift the last nibble, in case there's an odd count */
	i = num_whole_bytes;
	if (num_nibbles & 1)
		out[i] = (in[i] & 0xF) << 4;
}

/*! convert unpacked bits to soft bits
 *  \param[out] out output buffer of soft bits
 *  \param[in] in input buffer of unpacked bits
 *  \param[in] num_bits number of bits
 */
void osmo_ubit2sbit(sbit_t *out, const ubit_t *in, unsigned int num_bits)
{
	unsigned int i;
	for (i = 0; i < num_bits; i++)
		out[i] = in[i] ? -127 : 127;
}

/*! convert soft bits to unpacked bits
 *  \param[out] out output buffer of unpacked bits
 *  \param[in] in input buffer of soft bits
 *  \param[in] num_bits number of bits
 */
void osmo_sbit2ubit(ubit_t *out, const sbit_t *in, unsigned int num_bits)
{
	unsigned int i;
	for (i = 0; i < num_bits; i++)
		out[i] = in[i] < 0;
}

/*! convert packed bits to unpacked bits, return length in bytes
 *  \param[out] out output buffer of unpacked bits
 *  \param[in] in input buffer of packed bits
 *  \param[in] num_bits number of bits
 *  \return number of bytes used in \ref out
 */
int osmo_pbit2ubit(ubit_t *out, const pbit_t *in, unsigned int num_bits)
{
	unsigned int i;
	ubit_t *cur = out;
	ubit_t *limit = out + num_bits;

	for (i = 0; i < (num_bits/8)+1; i++) {
		pbit_t byte = in[i];
		*cur++ = (byte >> 7) & 1;
		if (cur >= limit)
			break;
		*cur++ = (byte >> 6) & 1;
		if (cur >= limit)
			break;
		*cur++ = (byte >> 5) & 1;
		if (cur >= limit)
			break;
		*cur++ = (byte >> 4) & 1;
		if (cur >= limit)
			break;
		*cur++ = (byte >> 3) & 1;
		if (cur >= limit)
			break;
		*cur++ = (byte >> 2) & 1;
		if (cur >= limit)
			break;
		*cur++ = (byte >> 1) & 1;
		if (cur >= limit)
			break;
		*cur++ = (byte >> 0) & 1;
		if (cur >= limit)
			break;
	}
	return cur - out;
}

/*! convert unpacked bits to packed bits (extended options)
 *  \param[out] out output buffer of packed bits
 *  \param[in] out_ofs offset into output buffer
 *  \param[in] in input buffer of unpacked bits
 *  \param[in] in_ofs offset into input buffer
 *  \param[in] num_bits number of bits
 *  \param[in] lsb_mode Encode bits in LSB orde instead of MSB
 *  \returns length in bytes (max written offset of output buffer + 1)
 */
int osmo_ubit2pbit_ext(pbit_t *out, unsigned int out_ofs,
                       const ubit_t *in, unsigned int in_ofs,
                       unsigned int num_bits, int lsb_mode)
{
	int i, op, bn;
	for (i=0; i<num_bits; i++) {
		op = out_ofs + i;
		bn = lsb_mode ? (op&7) : (7-(op&7));
		if (in[in_ofs+i])
			out[op>>3] |= 1 << bn;
		else
			out[op>>3] &= ~(1 << bn);
	}
	return ((out_ofs + num_bits - 1) >> 3) + 1;
}

/*! convert packed bits to unpacked bits (extended options)
 *  \param[out] out output buffer of unpacked bits
 *  \param[in] out_ofs offset into output buffer
 *  \param[in] in input buffer of packed bits
 *  \param[in] in_ofs offset into input buffer
 *  \param[in] num_bits number of bits
 *  \param[in] lsb_mode Encode bits in LSB orde instead of MSB
 *  \returns length in bytes (max written offset of output buffer + 1)
 */
int osmo_pbit2ubit_ext(ubit_t *out, unsigned int out_ofs,
                       const pbit_t *in, unsigned int in_ofs,
                       unsigned int num_bits, int lsb_mode)
{
	int i, ip, bn;
	for (i=0; i<num_bits; i++) {
		ip = in_ofs + i;
		bn = lsb_mode ? (ip&7) : (7-(ip&7));
		out[out_ofs+i] = !!(in[ip>>3] & (1<<bn));
	}
	return out_ofs + num_bits;
}

/*! generalized bit reversal function
 *  \param[in] x the 32bit value to be reversed
 *  \param[in] k the type of reversal requested
 *  \returns the reversed 32bit dword
 *
 * This function reverses the bit order within a 32bit word. Depending
 * on "k", it either reverses all bits in a 32bit dword, or the bytes in
 * the dword, or the bits in each byte of a dword, or simply swaps the
 * two 16bit words in a dword.  See Chapter 7 "Hackers Delight"
 */
uint32_t osmo_bit_reversal(uint32_t x, enum osmo_br_mode k)
{
	if (k &  1) x = (x & 0x55555555) <<  1 | (x & 0xAAAAAAAA) >>  1;
	if (k &  2) x = (x & 0x33333333) <<  2 | (x & 0xCCCCCCCC) >>  2;
	if (k &  4) x = (x & 0x0F0F0F0F) <<  4 | (x & 0xF0F0F0F0) >>  4;
	if (k &  8) x = (x & 0x00FF00FF) <<  8 | (x & 0xFF00FF00) >>  8;
	if (k & 16) x = (x & 0x0000FFFF) << 16 | (x & 0xFFFF0000) >> 16;

	return x;
}

/*! reverse the bit-order in each byte of a dword
 *  \param[in] x 32bit input value
 *  \returns 32bit value where bits of each byte have been reversed
 *
 * See Chapter 7 "Hackers Delight"
 */
uint32_t osmo_revbytebits_32(uint32_t x)
{
	x = (x & 0x55555555) <<  1 | (x & 0xAAAAAAAA) >>  1;
	x = (x & 0x33333333) <<  2 | (x & 0xCCCCCCCC) >>  2;
	x = (x & 0x0F0F0F0F) <<  4 | (x & 0xF0F0F0F0) >>  4;

	return x;
}

/*! reverse the bit order in a byte
 *  \param[in] x 8bit input value
 *  \returns 8bit value where bits order has been reversed
 *
 * See Chapter 7 "Hackers Delight"
 */
uint32_t osmo_revbytebits_8(uint8_t x)
{
	x = (x & 0x55) <<  1 | (x & 0xAA) >>  1;
	x = (x & 0x33) <<  2 | (x & 0xCC) >>  2;
	x = (x & 0x0F) <<  4 | (x & 0xF0) >>  4;

	return x;
}

/*! reverse bit-order of each byte in a buffer
 *  \param[in] buf buffer containing bytes to be bit-reversed
 *  \param[in] len length of buffer in bytes
 *
 *  This function reverses the bits in each byte of the buffer
 */
void osmo_revbytebits_buf(uint8_t *buf, int len)
{
	unsigned int i;
	unsigned int unaligned_cnt;
	int len_remain = len;

	unaligned_cnt = ((unsigned long)buf & 3);
	for (i = 0; i < unaligned_cnt; i++) {
		buf[i] = osmo_revbytebits_8(buf[i]);
		len_remain--;
		if (len_remain <= 0)
			return;
	}

	for (i = unaligned_cnt; i + 3 < len; i += 4) {
		osmo_store32be(osmo_revbytebits_32(osmo_load32be(buf + i)), buf + i);
		len_remain -= 4;
	}

	for (i = len - len_remain; i < len; i++) {
		buf[i] = osmo_revbytebits_8(buf[i]);
		len_remain--;
	}
}

/*! @} */
