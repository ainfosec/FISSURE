/*
 * Copyright (C) 2011  Sylvain Munaut <tnt@246tNt.com>
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

/*! \addtogroup a5
 *  @{
 *  Osmocom GSM ciphering algorithm implementation
 *
 *  Full reimplementation of A5/1,2,3,4 (split and threadsafe).
 *
 *  The logic behind the algorithm is taken from "A pedagogical implementation
 *  of the GSM A5/1 and A5/2 "voice privacy" encryption algorithms." by
 *  Marc Briceno, Ian Goldberg, and David Wagner.
 */

#include <errno.h>
#include <string.h>
#include <stdbool.h>

#include <osmocom/gsm/a5.h>
#include <osmocom/gsm/kasumi.h>
#include <osmocom/crypt/auth.h>

/* Somme OS (like Nuttx) don't have ENOTSUP */
#ifndef ENOTSUP
#define ENOTSUP EINVAL
#endif

/* ------------------------------------------------------------------------ */
/* A5/3&4                                                                   */
/* ------------------------------------------------------------------------ */

/*! Generate a GSM A5/4 cipher stream
 *  \param[in] key 16 byte array for the key (as received from the SIM)
 *  \param[in] fn Frame number
 *  \param[out] dl Pointer to array of ubits to return Downlink cipher stream
 *  \param[out] ul Pointer to array of ubits to return Uplink cipher stream
 *  \param[in] fn_correct true if fn is a real GSM frame number and thus requires internal conversion
 *
 * Either (or both) of dl/ul should be NULL if not needed.
 *
 * Implementation based on specifications from 3GPP TS 55.216, 3GPP TR 55.919 and ETSI TS 135 202
 * with slight simplifications (CE hardcoded to 0).
 */
void
_a5_4(const uint8_t *ck, uint32_t fn, ubit_t *dl, ubit_t *ul, bool fn_correct)
{
       uint8_t i, gamma[32], uplink[15];
       uint32_t fn_count = (fn_correct) ? osmo_a5_fn_count(fn) : fn;

       if (ul) {
               _kasumi_kgcore(0xF, 0, fn_count, 0, ck, gamma, 228);
               for(i = 0; i < 15; i++) uplink[i] = (gamma[i + 14] << 2) + (gamma[i + 15] >> 6);
               osmo_pbit2ubit(ul, uplink, 114);
       }
       if (dl) {
               _kasumi_kgcore(0xF, 0, fn_count, 0, ck, gamma, 114);
               osmo_pbit2ubit(dl, gamma, 114);
       }
}

/*! Generate a GSM A5/3 cipher stream
 *  \param[in] key 8 byte array for the key (as received from the SIM)
 *  \param[in] fn Frame number
 *  \param[out] dl Pointer to array of ubits to return Downlink cipher stream
 *  \param[out] ul Pointer to array of ubits to return Uplink cipher stream
 *  \param[in] fn_correct true if fn is a real GSM frame number and thus requires internal conversion
 *
 * Either (or both) of dl/ul should be NULL if not needed.
 *
 * Implementation based on specifications from 3GPP TS 55.216, 3GPP TR 55.919 and ETSI TS 135 202
 * with slight simplifications (CE hardcoded to 0).
 */
void
_a5_3(const uint8_t *key, uint32_t fn, ubit_t *dl, ubit_t *ul, bool fn_correct)
{
       uint8_t ck[16];
       osmo_c4(ck, key);
       /* internal function require 128 bit key so we expand by concatenating supplied 64 bit key */
       _a5_4(ck, fn, dl, ul, fn_correct);
}

/* ------------------------------------------------------------------------ */
/* A5/1&2 common stuff                                                                     */
/* ------------------------------------------------------------------------ */

#define A5_R1_LEN	19
#define A5_R2_LEN	22
#define A5_R3_LEN	23
#define A5_R4_LEN	17	/* A5/2 only */

#define A5_R1_MASK	((1<<A5_R1_LEN)-1)
#define A5_R2_MASK	((1<<A5_R2_LEN)-1)
#define A5_R3_MASK	((1<<A5_R3_LEN)-1)
#define A5_R4_MASK	((1<<A5_R4_LEN)-1)

#define A5_R1_TAPS	0x072000 /* x^19 + x^18 + x^17 + x^14 + 1 */
#define A5_R2_TAPS	0x300000 /* x^22 + x^21 + 1 */
#define A5_R3_TAPS	0x700080 /* x^23 + x^22 + x^21 + x^8 + 1 */
#define A5_R4_TAPS	0x010800 /* x^17 + x^12 + 1 */

/*! Computes parity of a 32-bit word
 *  \param[in] x 32 bit word
 *  \return Parity bit (xor of all bits) as 0 or 1
 */
static inline uint32_t
_a5_12_parity(uint32_t x)
{
	x ^= x >> 16;
	x ^= x >> 8;
	x ^= x >> 4;
	x &= 0xf;
	return (0x6996 >> x) & 1;
}

/*! Compute majority bit from 3 taps
 *  \param[in] v1 LFSR state ANDed with tap-bit
 *  \param[in] v2 LFSR state ANDed with tap-bit
 *  \param[in] v3 LFSR state ANDed with tap-bit
 *  \return The majority bit (0 or 1)
 */
static inline uint32_t
_a5_12_majority(uint32_t v1, uint32_t v2, uint32_t v3)
{
	return (!!v1 + !!v2 + !!v3) >= 2;
}

/*! Compute the next LFSR state
 *  \param[in] r Current state
 *  \param[in] mask LFSR mask
 *  \param[in] taps LFSR taps
 *  \return Next state
 */
static inline uint32_t
_a5_12_clock(uint32_t r, uint32_t mask, uint32_t taps)
{
	return ((r << 1) & mask) | _a5_12_parity(r & taps);
}


/* ------------------------------------------------------------------------ */
/* A5/1                                                                     */
/* ------------------------------------------------------------------------ */

#define A51_R1_CLKBIT	0x000100
#define A51_R2_CLKBIT	0x000400
#define A51_R3_CLKBIT	0x000400

/*! GSM A5/1 Clocking function
 *  \param[in] r Register state
 *  \param[in] force Non-zero value disable conditional clocking
 */
static inline void
_a5_1_clock(uint32_t r[], int force)
{
	int cb[3], maj;

	cb[0] = !!(r[0] & A51_R1_CLKBIT);
	cb[1] = !!(r[1] & A51_R2_CLKBIT);
	cb[2] = !!(r[2] & A51_R3_CLKBIT);

	maj = _a5_12_majority(cb[0], cb[1], cb[2]);

	if (force || (maj == cb[0]))
		r[0] = _a5_12_clock(r[0], A5_R1_MASK, A5_R1_TAPS);

	if (force || (maj == cb[1]))
		r[1] = _a5_12_clock(r[1], A5_R2_MASK, A5_R2_TAPS);

	if (force || (maj == cb[2]))
		r[2] = _a5_12_clock(r[2], A5_R3_MASK, A5_R3_TAPS);
}

/*! GSM A5/1 Output function
 *  \param[in] r Register state
 *  \return The A5/1 output function bit
 */
static inline uint8_t
_a5_1_get_output(uint32_t r[])
{
	return	(r[0] >> (A5_R1_LEN-1)) ^
		(r[1] >> (A5_R2_LEN-1)) ^
		(r[2] >> (A5_R3_LEN-1));
}

/*! Generate a GSM A5/1 cipher stream
 *  \param[in] key 8 byte array for the key (as received from the SIM)
 *  \param[in] fn Frame number
 *  \param[out] dl Pointer to array of ubits to return Downlink cipher stream
 *  \param[out] ul Pointer to array of ubits to return Uplink cipher stream
 *
 * Either (or both) of dl/ul can be NULL if not needed.
 */
void
_a5_1(const uint8_t *key, uint32_t fn, ubit_t *dl, ubit_t *ul)
{
	uint32_t r[3] = {0, 0, 0};
	uint32_t fn_count;
	uint32_t b;
	int i;

	/* Key load */
	for (i=0; i<64; i++)
	{
		b = ( key[7 - (i>>3)] >> (i&7) ) & 1;

		_a5_1_clock(r, 1);

		r[0] ^= b;
		r[1] ^= b;
		r[2] ^= b;
	}

	/* Frame count load */
	fn_count = osmo_a5_fn_count(fn);

	for (i=0; i<22; i++)
	{
		b = (fn_count >> i) & 1;

		_a5_1_clock(r, 1);

		r[0] ^= b;
		r[1] ^= b;
		r[2] ^= b;
	}

	/* Mix */
	for (i=0; i<100; i++)
	{
		_a5_1_clock(r, 0);
	}

	/* Output */
	for (i=0; i<114; i++) {
		_a5_1_clock(r, 0);
		if (dl)
			dl[i] = _a5_1_get_output(r);
	}

	for (i=0; i<114; i++) {
		_a5_1_clock(r, 0);
		if (ul)
			ul[i] = _a5_1_get_output(r);
	}
}

void osmo_a5_1(const uint8_t *key, uint32_t fn, ubit_t *dl, ubit_t *ul)
{
	osmo_a5(1, key, fn, dl, ul);
}

/* ------------------------------------------------------------------------ */
/* A5/2                                                                     */
/* ------------------------------------------------------------------------ */

#define A52_R4_CLKBIT0	0x000400
#define A52_R4_CLKBIT1	0x000008
#define A52_R4_CLKBIT2	0x000080

/*! GSM A5/2 Clocking function
 *  \param[in] r Register state
 *  \param[in] force Non-zero value disable conditional clocking
 */
static inline void
_a5_2_clock(uint32_t r[], int force)
{
	int cb[3], maj;

	cb[0] = !!(r[3] & A52_R4_CLKBIT0);
	cb[1] = !!(r[3] & A52_R4_CLKBIT1);
	cb[2] = !!(r[3] & A52_R4_CLKBIT2);

	maj = (cb[0] + cb[1] + cb[2]) >= 2;

	if (force || (maj == cb[0]))
		r[0] = _a5_12_clock(r[0], A5_R1_MASK, A5_R1_TAPS);

	if (force || (maj == cb[1]))
		r[1] = _a5_12_clock(r[1], A5_R2_MASK, A5_R2_TAPS);

	if (force || (maj == cb[2]))
		r[2] = _a5_12_clock(r[2], A5_R3_MASK, A5_R3_TAPS);

	r[3] = _a5_12_clock(r[3], A5_R4_MASK, A5_R4_TAPS);
}

/*! GSM A5/2 Output function
 *  \param[in] r Register state
 *  \return The A5/2 output function bit
 */
static inline uint8_t
_a5_2_get_output(uint32_t r[])
{
	uint8_t b;

	b = (r[0] >> (A5_R1_LEN-1)) ^
	    (r[1] >> (A5_R2_LEN-1)) ^
	    (r[2] >> (A5_R3_LEN-1)) ^
	    _a5_12_majority( r[0] & 0x08000, ~r[0] & 0x04000,  r[0] & 0x1000) ^
	    _a5_12_majority(~r[1] & 0x10000,  r[1] & 0x02000,  r[1] & 0x0200) ^
	    _a5_12_majority( r[2] & 0x40000,  r[2] & 0x10000, ~r[2] & 0x2000);

	return b;
}

/*! Generate a GSM A5/1 cipher stream
 *  \param[in] key 8 byte array for the key (as received from the SIM)
 *  \param[in] fn Frame number
 *  \param[out] dl Pointer to array of ubits to return Downlink cipher stream
 *  \param[out] ul Pointer to array of ubits to return Uplink cipher stream
 *
 * Either (or both) of dl/ul can be NULL if not needed.
 */
void
_a5_2(const uint8_t *key, uint32_t fn, ubit_t *dl, ubit_t *ul)
{
	uint32_t r[4] = {0, 0, 0, 0};
	uint32_t fn_count;
	uint32_t b;
	int i;

	/* Key load */
	for (i=0; i<64; i++)
	{
		b = ( key[7 - (i>>3)] >> (i&7) ) & 1;

		_a5_2_clock(r, 1);

		r[0] ^= b;
		r[1] ^= b;
		r[2] ^= b;
		r[3] ^= b;
	}

	/* Frame count load */
	fn_count = osmo_a5_fn_count(fn);

	for (i=0; i<22; i++)
	{
		b = (fn_count >> i) & 1;

		_a5_2_clock(r, 1);

		r[0] ^= b;
		r[1] ^= b;
		r[2] ^= b;
		r[3] ^= b;
	}

	r[0] |= 1 << 15;
	r[1] |= 1 << 16;
	r[2] |= 1 << 18;
	r[3] |= 1 << 10;

	/* Mix */
	for (i=0; i<99; i++)
	{
		_a5_2_clock(r, 0);
	}

	/* Output */
	for (i=0; i<114; i++) {
		_a5_2_clock(r, 0);
		if (dl)
			dl[i] = _a5_2_get_output(r);
	}

	for (i=0; i<114; i++) {
		_a5_2_clock(r, 0);
		if (ul)
			ul[i] = _a5_2_get_output(r);
	}
}

void osmo_a5_2(const uint8_t *key, uint32_t fn, ubit_t *dl, ubit_t *ul)
{
	osmo_a5(2, key, fn, dl, ul);
}

/*! Main method to generate a A5/x cipher stream
 *  \param[in] n Which A5/x method to use
 *  \param[in] key 8 or 16 (for a5/4) byte array for the key (as received from the SIM)
 *  \param[in] fn Frame number
 *  \param[out] dl Pointer to array of ubits to return Downlink cipher stream
 *  \param[out] ul Pointer to array of ubits to return Uplink cipher stream
 *  \returns 0 for success, -ENOTSUP for invalid cipher selection.
 *
 * Currently A5/[0-4] are supported.
 * Either (or both) of dl/ul can be NULL if not needed.
 */
int
osmo_a5(int n, const uint8_t *key, uint32_t fn, ubit_t *dl, ubit_t *ul)
{
	switch (n)
	{
	case 0:
		if (dl)
			memset(dl, 0x00, 114);
		if (ul)
			memset(ul, 0x00, 114);
		break;

	case 1:
		_a5_1(key, fn, dl, ul);
		break;

	case 2:
		_a5_2(key, fn, dl, ul);
		break;

	case 3:
		_a5_3(key, fn, dl, ul, true);
		break;

	case 4:
		_a5_4(key, fn, dl, ul, true);
		break;

	default:
		/* a5/[5..7] not supported here/yet */
		return -ENOTSUP;
	}

	return 0;
}

/*! @} */
