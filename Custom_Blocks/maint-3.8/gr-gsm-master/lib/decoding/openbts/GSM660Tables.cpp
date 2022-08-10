/*
 * Copyright 2010  Sylvain Munaut <tnt@246tNt.com>
 * All Rights Reserved
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * This use of this software may be subject to additional restrictions.
 * See the LEGAL file in the main directory for details.
 */

/* EFR (GSM 06.60) importance bit ordering */

#include "GSM660Tables.h"

unsigned int GSM::g660BitOrder[260] = {
	 38,  39,  40,  41,  42,  43,		/*   0 -> LTP-LAG 1: b8..b3 */
	145, 146, 147, 148, 149, 150,		/*   6 -> LTP-LAG 3: b8..b3 */
	 93,  94,				/*  12 -> LTP-LAG 2: b5..b4 */
	200, 201,				/*  14 -> LTP-LAG 4: b5..b4 */
	 47,					/*  16 -> LTP-GAIN 1: b3    */
	 88,					/*  17 -> FCB-GAIN 1: b4    */
	 99,					/*  18 -> LTP-GAIN 2: b3    */
	140,					/*  19 -> FCB-GAIN 2: b4    */
	 44,					/*  20 -> LTP-LAG 1: b2     */
	151,					/*  21 -> LTP-LAG 3: b2     */
	 95,					/*  22 -> LTP-LAG 2: b3     */
	202,					/*  23 -> LTP-LAG 4: b3     */
	  1,   2,				/*  24 -> LPC 1: b5..b4     */
	  7,					/*  26 -> LPC 2: b7         */
	  9,					/*  27 -> LPC 2: b5         */
	 17,  18,				/*  28 -> LPC 3: b6..b5     */
	 23,					/*  30 -> LPC 3: b0         */
	 45,  46,				/*  31 -> LTP-LAG 1: b1..b0 */
	152, 153,				/*  33 -> LTP-LAG 3: b1..b0 */
	 96,					/*  35 -> LTP-LAG 2: b2     */
	203,					/*  36 -> LTP-LAG 4: b2     */
	  3,   4,				/*  37 -> LPC 1: b3..b2     */
	 10,  11,				/*  39 -> LPC 2: b4..b3     */
	 15,					/*  41 -> LPC 3: b8         */
	  8,					/*  42 -> LPC 2: b6         */
	  5,   6,				/*  43 -> LPC 1: b1..b0     */
	 12,					/*  45 -> LPC 2: b2         */
	 16,					/*  46 -> LPC 3: b7         */
	 19,					/*  47 -> LPC 3: b4         */
	 97,					/*  48 -> LTP-LAG 2: b1     */
	204,					/*  49 -> LTP-LAG 4: b1     */
	  0,					/*  50 -> LPC 1: b6         */
	 13,  14,				/*  51 -> LPC 2: b1..b0     */
	 20,					/*  53 -> LPC 3: b3         */
	 24,  25,				/*  54 -> LPC 4: b7..b6     */
	 27,					/*  56 -> LPC 4: b4         */
	154,					/*  57 -> LTP-GAIN 3: b3    */
	206,					/*  58 -> LTP-GAIN 4: b3    */
	195,					/*  59 -> FCB-GAIN 3: b4    */
	247,					/*  60 -> FCB-GAIN 4: b4    */
	 89,					/*  61 -> FCB-GAIN 1: b3    */
	141,					/*  62 -> FCB-GAIN 2: b3    */
	196,					/*  63 -> FCB-GAIN 3: b3    */
	248,					/*  64 -> FCB-GAIN 4: b3    */
	252, 253, 254, 255, 256, 257, 258, 259,	/*  65 -> CRC-POLY: b7..b0  */
	 48,					/*  73 -> LTP-GAIN 1: b2    */
	100,					/*  74 -> LTP-GAIN 2: b2    */
	155,					/*  75 -> LTP-GAIN 3: b2    */
	207,					/*  76 -> LTP-GAIN 4: b2    */
	 21,  22,				/*  77 -> LPC 3: b2..b1     */
	 26,					/*  79 -> LPC 4: b5         */
	 28,					/*  80 -> LPC 4: b3         */
	 51,					/*  81 -> PULSE 1_1: b3     */
	 55,					/*  82 -> PULSE 1_2: b3     */
	 59,					/*  83 -> PULSE 1_3: b3     */
	 63,					/*  84 -> PULSE 1_4: b3     */
	 67,					/*  85 -> PULSE 1_5: b3     */
	103,					/*  86 -> PULSE 2_1: b3     */
	107,					/*  87 -> PULSE 2_2: b3     */
	111,					/*  88 -> PULSE 2_3: b3     */
	115,					/*  89 -> PULSE 2_4: b3     */
	119,					/*  90 -> PULSE 2_5: b3     */
	158,					/*  91 -> PULSE 3_1: b3     */
	162,					/*  92 -> PULSE 3_2: b3     */
	166,					/*  93 -> PULSE 3_3: b3     */
	170,					/*  94 -> PULSE 3_4: b3     */
	174,					/*  95 -> PULSE 3_5: b3     */
	210,					/*  96 -> PULSE 4_1: b3     */
	214,					/*  97 -> PULSE 4_2: b3     */
	218,					/*  98 -> PULSE 4_3: b3     */
	222,					/*  99 -> PULSE 4_4: b3     */
	226,					/* 100 -> PULSE 4_5: b3     */
	 90,					/* 101 -> FCB-GAIN 1: b2    */
	142,					/* 102 -> FCB-GAIN 2: b2    */
	197,					/* 103 -> FCB-GAIN 3: b2    */
	249,					/* 104 -> FCB-GAIN 4: b2    */
	 49,					/* 105 -> LTP-GAIN 1: b1    */
	101,					/* 106 -> LTP-GAIN 2: b1    */
	156,					/* 107 -> LTP-GAIN 3: b1    */
	208,					/* 108 -> LTP-GAIN 4: b1    */
	 29,  30,  31,				/* 109 -> LPC 4: b2..b0     */
	 32,  33,  34,  35,			/* 112 -> LPC 5: b5..b2     */
	 98,					/* 116 -> LTP-LAG 2: b0     */
	205,					/* 117 -> LTP-LAG 4: b0     */
	 52,					/* 118 -> PULSE 1_1: b2     */
	 56,					/* 119 -> PULSE 1_2: b2     */
	 60,					/* 120 -> PULSE 1_3: b2     */
	 64,					/* 121 -> PULSE 1_4: b2     */
	 68,					/* 122 -> PULSE 1_5: b2     */
	104,					/* 123 -> PULSE 2_1: b2     */
	108,					/* 124 -> PULSE 2_2: b2     */
	112,					/* 125 -> PULSE 2_3: b2     */
	116,					/* 126 -> PULSE 2_4: b2     */
	120,					/* 127 -> PULSE 2_5: b2     */
	159,					/* 128 -> PULSE 3_1: b2     */
	163,					/* 129 -> PULSE 3_2: b2     */
	167,					/* 130 -> PULSE 3_3: b2     */
	171,					/* 131 -> PULSE 3_4: b2     */
	175,					/* 132 -> PULSE 3_5: b2     */
	211,					/* 133 -> PULSE 4_1: b2     */
	215,					/* 134 -> PULSE 4_2: b2     */
	219,					/* 135 -> PULSE 4_3: b2     */
	223,					/* 136 -> PULSE 4_4: b2     */
	227,					/* 137 -> PULSE 4_5: b2     */
	 53,					/* 138 -> PULSE 1_1: b1     */
	 57,					/* 139 -> PULSE 1_2: b1     */
	 61,					/* 140 -> PULSE 1_3: b1     */
	 65,					/* 141 -> PULSE 1_4: b1     */
	105,					/* 142 -> PULSE 2_1: b1     */
	109,					/* 143 -> PULSE 2_2: b1     */
	113,					/* 144 -> PULSE 2_3: b1     */
	117,					/* 145 -> PULSE 2_4: b1     */
	160,					/* 146 -> PULSE 3_1: b1     */
	164,					/* 147 -> PULSE 3_2: b1     */
	168,					/* 148 -> PULSE 3_3: b1     */
	172,					/* 149 -> PULSE 3_4: b1     */
	212,					/* 150 -> PULSE 4_1: b1     */
	220,					/* 151 -> PULSE 4_3: b1     */
	224,					/* 152 -> PULSE 4_4: b1     */
	 91,					/* 153 -> FCB-GAIN 1: b1    */
	143,					/* 154 -> FCB-GAIN 2: b1    */
	198,					/* 155 -> FCB-GAIN 3: b1    */
	250,					/* 156 -> FCB-GAIN 4: b1    */
	 50,					/* 157 -> LTP-GAIN 1: b0    */
	102,					/* 158 -> LTP-GAIN 2: b0    */
	157,					/* 159 -> LTP-GAIN 3: b0    */
	209,					/* 160 -> LTP-GAIN 4: b0    */
	 92,					/* 161 -> FCB-GAIN 1: b0    */
	144,					/* 162 -> FCB-GAIN 2: b0    */
	199,					/* 163 -> FCB-GAIN 3: b0    */
	251,					/* 164 -> FCB-GAIN 4: b0    */
	 54,					/* 165 -> PULSE 1_1: b0     */
	 58,					/* 166 -> PULSE 1_2: b0     */
	 62,					/* 167 -> PULSE 1_3: b0     */
	 66,					/* 168 -> PULSE 1_4: b0     */
	106,					/* 169 -> PULSE 2_1: b0     */
	110,					/* 170 -> PULSE 2_2: b0     */
	114,					/* 171 -> PULSE 2_3: b0     */
	118,					/* 172 -> PULSE 2_4: b0     */
	161,					/* 173 -> PULSE 3_1: b0     */
	165,					/* 174 -> PULSE 3_2: b0     */
	169,					/* 175 -> PULSE 3_3: b0     */
	173,					/* 176 -> PULSE 3_4: b0     */
	213,					/* 177 -> PULSE 4_1: b0     */
	221,					/* 178 -> PULSE 4_3: b0     */
	225,					/* 179 -> PULSE 4_4: b0     */
	 36,  37,				/* 180 -> LPC 5: b1..b0     */
	 69,					/* 182 -> PULSE 1_5: b1     */
	 71,  72,				/* 183 -> PULSE 1_5: b1..b1 */
	121,					/* 185 -> PULSE 2_5: b1     */
	123, 124,				/* 186 -> PULSE 2_5: b1..b1 */
	176,					/* 188 -> PULSE 3_5: b1     */
	178, 179,				/* 189 -> PULSE 3_5: b1..b1 */
	228,					/* 191 -> PULSE 4_5: b1     */
	230, 231,				/* 192 -> PULSE 4_5: b1..b1 */
	216, 217,				/* 194 -> PULSE 4_2: b1..b0 */
	 70,					/* 196 -> PULSE 1_5: b0     */
	122,					/* 197 -> PULSE 2_5: b0     */
	177,					/* 198 -> PULSE 3_5: b0     */
	229,					/* 199 -> PULSE 4_5: b0     */
	 73,					/* 200 -> PULSE 1_6: b2     */
	 76,					/* 201 -> PULSE 1_7: b2     */
	 79,					/* 202 -> PULSE 1_8: b2     */
	 82,					/* 203 -> PULSE 1_9: b2     */
	 85,					/* 204 -> PULSE 1_10: b2    */
	125,					/* 205 -> PULSE 2_6: b2     */
	128,					/* 206 -> PULSE 2_7: b2     */
	131,					/* 207 -> PULSE 2_8: b2     */
	134,					/* 208 -> PULSE 2_9: b2     */
	137,					/* 209 -> PULSE 2_10: b2    */
	180,					/* 210 -> PULSE 3_6: b2     */
	183,					/* 211 -> PULSE 3_7: b2     */
	186,					/* 212 -> PULSE 3_8: b2     */
	189,					/* 213 -> PULSE 3_9: b2     */
	192,					/* 214 -> PULSE 3_10: b2    */
	232,					/* 215 -> PULSE 4_6: b2     */
	235,					/* 216 -> PULSE 4_7: b2     */
	238,					/* 217 -> PULSE 4_8: b2     */
	241,					/* 218 -> PULSE 4_9: b2     */
	244,					/* 219 -> PULSE 4_10: b2    */
	 74,					/* 220 -> PULSE 1_6: b1     */
	 77,					/* 221 -> PULSE 1_7: b1     */
	 80,					/* 222 -> PULSE 1_8: b1     */
	 83,					/* 223 -> PULSE 1_9: b1     */
	 86,					/* 224 -> PULSE 1_10: b1    */
	126,					/* 225 -> PULSE 2_6: b1     */
	129,					/* 226 -> PULSE 2_7: b1     */
	132,					/* 227 -> PULSE 2_8: b1     */
	135,					/* 228 -> PULSE 2_9: b1     */
	138,					/* 229 -> PULSE 2_10: b1    */
	181,					/* 230 -> PULSE 3_6: b1     */
	184,					/* 231 -> PULSE 3_7: b1     */
	187,					/* 232 -> PULSE 3_8: b1     */
	190,					/* 233 -> PULSE 3_9: b1     */
	193,					/* 234 -> PULSE 3_10: b1    */
	233,					/* 235 -> PULSE 4_6: b1     */
	236,					/* 236 -> PULSE 4_7: b1     */
	239,					/* 237 -> PULSE 4_8: b1     */
	242,					/* 238 -> PULSE 4_9: b1     */
	245,					/* 239 -> PULSE 4_10: b1    */
	 75,					/* 240 -> PULSE 1_6: b0     */
	 78,					/* 241 -> PULSE 1_7: b0     */
	 81,					/* 242 -> PULSE 1_8: b0     */
	 84,					/* 243 -> PULSE 1_9: b0     */
	 87,					/* 244 -> PULSE 1_10: b0    */
	127,					/* 245 -> PULSE 2_6: b0     */
	130,					/* 246 -> PULSE 2_7: b0     */
	133,					/* 247 -> PULSE 2_8: b0     */
	136,					/* 248 -> PULSE 2_9: b0     */
	139,					/* 249 -> PULSE 2_10: b0    */
	182,					/* 250 -> PULSE 3_6: b0     */
	185,					/* 251 -> PULSE 3_7: b0     */
	188,					/* 252 -> PULSE 3_8: b0     */
	191,					/* 253 -> PULSE 3_9: b0     */
	194,					/* 254 -> PULSE 3_10: b0    */
	234,					/* 255 -> PULSE 4_6: b0     */
	237,					/* 256 -> PULSE 4_7: b0     */
	240,					/* 257 -> PULSE 4_8: b0     */
	243,					/* 258 -> PULSE 4_9: b0     */
	246,					/* 259 -> PULSE 4_10: b0    */
};
