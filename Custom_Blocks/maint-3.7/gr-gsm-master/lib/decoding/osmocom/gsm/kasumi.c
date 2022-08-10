/*! \file kasumi.c
 * Kasumi cipher and KGcore functions. */
/*
 * (C) 2013 by Max <Max.Suraev@fairwaves.ru>
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
#include <osmocom/gsm/kasumi.h>

/* See TS 135 202 for constants and full Kasumi spec. */
inline static uint16_t kasumi_FI(uint16_t I, uint16_t skey)
{
	static const uint16_t S7[] = {
		54, 50, 62, 56, 22, 34, 94, 96, 38, 6, 63, 93, 2, 18, 123, 33,
		55, 113, 39, 114, 21, 67, 65, 12, 47, 73, 46, 27, 25, 111, 124, 81,
		53, 9, 121, 79, 52, 60, 58, 48, 101, 127, 40, 120, 104, 70, 71, 43,
		20, 122, 72, 61, 23, 109, 13, 100, 77, 1, 16, 7, 82, 10, 105, 98,
		117, 116, 76, 11, 89, 106, 0,125,118, 99, 86, 69, 30, 57, 126, 87,
		112, 51, 17, 5, 95, 14, 90, 84, 91, 8, 35,103, 32, 97, 28, 66,
		102, 31, 26, 45, 75, 4, 85, 92, 37, 74, 80, 49, 68, 29, 115, 44,
		64, 107, 108, 24, 110, 83, 36, 78, 42, 19, 15, 41, 88, 119, 59, 3
	};
	static const uint16_t S9[] = {
		167, 239, 161, 379, 391, 334,  9, 338, 38, 226, 48, 358, 452, 385, 90, 397,
		183, 253, 147, 331, 415, 340, 51, 362, 306, 500, 262, 82, 216, 159, 356, 177,
		175, 241, 489, 37, 206, 17, 0, 333, 44, 254, 378, 58, 143, 220, 81, 400,
		95, 3, 315, 245, 54, 235, 218, 405, 472, 264, 172, 494, 371, 290, 399, 76,
		165, 197, 395, 121, 257, 480, 423, 212, 240, 28, 462, 176, 406, 507, 288, 223,
		501, 407, 249, 265, 89, 186, 221, 428,164, 74, 440, 196, 458, 421, 350, 163,
		232, 158, 134, 354, 13, 250, 491, 142,191, 69, 193, 425, 152, 227, 366, 135,
		344, 300, 276, 242, 437, 320, 113, 278, 11, 243, 87, 317, 36, 93, 496, 27,
		487, 446, 482, 41, 68, 156, 457, 131, 326, 403, 339, 20, 39, 115, 442, 124,
		475, 384, 508, 53, 112, 170, 479, 151, 126, 169, 73, 268, 279, 321, 168, 364,
		363, 292, 46, 499, 393, 327, 324, 24, 456, 267, 157, 460, 488, 426, 309, 229,
		439, 506, 208, 271, 349, 401, 434, 236, 16, 209, 359, 52, 56, 120, 199, 277,
		465, 416, 252, 287, 246,  6, 83, 305, 420, 345, 153,502, 65, 61, 244, 282,
		173, 222, 418, 67, 386, 368, 261, 101, 476, 291, 195,430, 49, 79, 166, 330,
		280, 383, 373, 128, 382, 408, 155, 495, 367, 388, 274, 107, 459, 417, 62, 454,
		132, 225, 203, 316, 234, 14, 301, 91, 503, 286, 424, 211, 347, 307, 140, 374,
		35, 103, 125, 427, 19, 214, 453, 146, 498, 314, 444, 230, 256, 329, 198, 285,
		50, 116, 78, 410, 10, 205, 510, 171, 231, 45, 139, 467, 29, 86, 505, 32,
		72, 26, 342, 150, 313, 490, 431, 238, 411, 325, 149, 473, 40, 119, 174, 355,
		185, 233, 389, 71, 448, 273, 372, 55, 110, 178, 322, 12, 469, 392, 369, 190,
		1, 109, 375, 137, 181, 88, 75, 308, 260, 484, 98, 272, 370, 275, 412, 111,
		336, 318, 4, 504, 492, 259, 304, 77, 337, 435, 21, 357, 303, 332, 483, 18,
		47, 85, 25, 497, 474, 289, 100, 269, 296, 478, 270, 106, 31, 104, 433, 84,
		414, 486, 394, 96, 99, 154, 511, 148, 413, 361, 409, 255, 162, 215, 302, 201,
		266, 351, 343, 144, 441, 365, 108, 298, 251, 34, 182, 509, 138, 210, 335, 133,
		311, 352, 328, 141, 396, 346, 123, 319, 450, 281, 429, 228, 443, 481, 92, 404,
		485, 422, 248, 297, 23, 213, 130, 466, 22, 217, 283, 70, 294, 360, 419, 127,
		312, 377, 7, 468, 194, 2, 117, 295, 463, 258, 224, 447, 247, 187, 80, 398,
		284, 353, 105, 390, 299, 471, 470, 184, 57, 200, 348, 63, 204, 188, 33, 451,
		97, 30, 310, 219, 94, 160, 129, 493, 64, 179, 263, 102, 189, 207, 114, 402,
		438, 477, 387, 122, 192, 42, 381, 5, 145, 118, 180, 449, 293, 323, 136, 380,
		43, 66, 60, 455, 341, 445, 202, 432, 8, 237, 15, 376, 436, 464, 59, 461
	};
	uint16_t L, R;

	/* Split 16 bit input into two unequal halves: 9 and 7 bits, same for subkey */
	L = I >> 7; /* take 9 bits */
	R = I & 0x7F; /* take 7 bits */

	L = S9[L]  ^ R;
	R = S7[R] ^ (L & 0x7F);

	L ^= (skey & 0x1FF);
	R ^= (skey >> 9);

	L = S9[L]  ^ R;
	R = S7[R] ^ (L & 0x7F);

	return (R << 9) + L;
}

inline static uint32_t kasumi_FO(uint32_t I, const uint16_t *KOi1, const uint16_t *KOi2, const uint16_t *KOi3, const uint16_t *KIi1, const uint16_t *KIi2, const uint16_t *KIi3, unsigned i)
{
	uint16_t L = I >> 16, R = I; /* Split 32 bit input into Left and Right parts */

	L ^= KOi1[i];
	L = kasumi_FI(L, KIi1[i]);
	L ^= R;

	R ^= KOi2[i];
	R = kasumi_FI(R, KIi2[i]);
	R ^= L;

	L ^= KOi3[i];
	L = kasumi_FI(L, KIi3[i]);
	L ^= R;

	return (((uint32_t)R) << 16) + L;
}

inline static uint32_t kasumi_FL(uint32_t I, const uint16_t *KLi1, const uint16_t *KLi2, unsigned i)
{
	uint16_t L = I >> 16, R = I, tmp; /* Split 32 bit input into Left and Right parts */

	tmp = L & KLi1[i];
	R ^= osmo_rol16(tmp, 1);

	tmp = R | KLi2[i];
	L ^= osmo_rol16(tmp, 1);

	return (((uint32_t)L) << 16) + R;
}

uint64_t _kasumi(uint64_t P, const uint16_t *KLi1, const uint16_t *KLi2, const uint16_t *KOi1, const uint16_t *KOi2, const uint16_t *KOi3, const uint16_t *KIi1, const uint16_t *KIi2, const uint16_t *KIi3)
{
	uint32_t i, L = P >> 32, R = P; /* Split 64 bit input into Left and Right parts */

	for (i = 0; i < 8; i++) {
		R ^= kasumi_FO(kasumi_FL(L, KLi1, KLi2, i), KOi1, KOi2, KOi3, KIi1, KIi2, KIi3, i); /* odd round */
		i++;
		L ^= kasumi_FL(kasumi_FO(R, KOi1, KOi2, KOi3, KIi1, KIi2, KIi3, i), KLi1, KLi2, i); /* even round */
	}
	return (((uint64_t)L) << 32) + R; /* Concatenate Left and Right 32 bits into 64 bit ciphertext */
}

void _kasumi_key_expand(const uint8_t *key, uint16_t *KLi1, uint16_t *KLi2, uint16_t *KOi1, uint16_t *KOi2, uint16_t *KOi3, uint16_t *KIi1, uint16_t *KIi2, uint16_t *KIi3)
{
	uint16_t i, C[] = { 0x0123, 0x4567, 0x89AB, 0xCDEF, 0xFEDC, 0xBA98, 0x7654, 0x3210 };

	/* Work with 16 bit subkeys and create prime subkeys */
	for (i = 0; i < 8; i++)
		C[i] ^= osmo_load16be(key + i * 2);
	/* C[] now stores K-prime[] */

	/* Create round-specific subkeys */
	for (i = 0; i < 8; i++) {
		KLi1[i] = osmo_rol16(osmo_load16be(key + i * 2), 1);
		KLi2[i] = C[(i + 2) & 0x7];

		KOi1[i] = osmo_rol16(osmo_load16be(key + ((2 * (i + 1)) & 0xE)), 5);
		KOi2[i] = osmo_rol16(osmo_load16be(key + ((2 * (i + 5)) & 0xE)), 8);
		KOi3[i] = osmo_rol16(osmo_load16be(key + ((2 * (i + 6)) & 0xE)), 13);

		KIi1[i] = C[(i + 4) & 0x7];
		KIi2[i] = C[(i + 3) & 0x7];
		KIi3[i] = C[(i + 7) & 0x7];
	}
}

void _kasumi_kgcore(uint8_t CA, uint8_t cb, uint32_t cc, uint8_t cd, const uint8_t *ck, uint8_t *co, uint16_t cl)
{
	uint16_t KLi1[8], KLi2[8], KOi1[8], KOi2[8], KOi3[8], KIi1[8], KIi2[8], KIi3[8], i;
	uint64_t A = ((uint64_t)cc) << 32, BLK = 0, _ca = ((uint64_t)CA << 16) ;
	A |= _ca;
	_ca = (uint64_t)((cb << 3) | (cd << 2)) << 24;
	A |= _ca;
	/* Register loading complete: see TR 55.919 8.2 and TS 55.216 3.2 */

	uint8_t ck_km[16];
	for (i = 0; i < 16; i++)
		ck_km[i] = ck[i] ^ 0x55;
	/* Modified key established */

	/* preliminary round with modified key */
	_kasumi_key_expand(ck_km, KLi1, KLi2, KOi1, KOi2, KOi3, KIi1, KIi2, KIi3);
	A = _kasumi(A, KLi1, KLi2, KOi1, KOi2, KOi3, KIi1, KIi2, KIi3);

	/* Run Kasumi in OFB to obtain enough data for gamma. */
	_kasumi_key_expand(ck, KLi1, KLi2, KOi1, KOi2, KOi3, KIi1, KIi2, KIi3);

	/* i is a block counter */
	for (i = 0; i < cl / 64 + 1; i++) {
		BLK = _kasumi(A ^ i ^ BLK, KLi1, KLi2, KOi1, KOi2, KOi3, KIi1, KIi2, KIi3);
		osmo_store64be(BLK, co + (i * 8));
	}
}
