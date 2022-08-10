
/*
 * Copyright (C) 2011-2016 Sylvain Munaut <tnt@246tNt.com>
 * Copyright (C) 2016 sysmocom s.f.m.c. GmbH
 *
 * All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
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

#include <stdint.h>
#include <osmocom/core/conv.h>

/*! structure describing xCCH convolutional code:.
 * 228 bits blocks, rate 1/2, k = 5
 * G0 = 1 + D3 + D4
 * G1 = 1 + D + D3 + D4
 */
extern const struct osmo_conv_code gsm0503_xcch;

/*! structure describing RACH convolutional code.
 */
extern const struct osmo_conv_code gsm0503_rach;

/*! structure describing Extended RACH (11 bit) convolutional code.
 */
//extern const struct osmo_conv_code gsm0503_rach_ext;

/*! structure describing SCH convolutional code.
 */
extern const struct osmo_conv_code gsm0503_sch;

/*! structure describing CS2 convolutional code:.
 * G0 = 1 + D3 + D4
 * G1 = 1 + D + D3 + D4
 */
extern const struct osmo_conv_code gsm0503_cs2;

/*! structure describing CS3 convolutional code:.
 * G0 = 1 + D3 + D4
 * G1 = 1 + D + D3 + D4
 */
extern const struct osmo_conv_code gsm0503_cs3;

/*! structure describing CS2 convolutional code (non-punctured):.
 * G0 = 1 + D3 + D4
 * G1 = 1 + D + D3 + D4
 */
//extern const struct osmo_conv_code gsm0503_cs2_np;

/*! structure describing CS3 convolutional code (non-punctured):.
 * G0 = 1 + D3 + D4
 * G1 = 1 + D + D3 + D4
 */
//extern const struct osmo_conv_code gsm0503_cs3_np;

/*! structure describing TCH/AFS 12.2 kbits convolutional code:.
 * 250 bits block, rate 1/2, punctured
 * G0/G0 = 1
 * G1/G0 = 1 + D + D3 + D4 / 1 + D3 + D4
 */
extern const struct osmo_conv_code gsm0503_tch_afs_12_2;

/*! structure describing TCH/AFS 10.2 kbits convolutional code:.
 * G1/G3 = 1 + D + D3 + D4 / 1 + D + D2 + D3 + D4
 * G2/G3 = 1 + D2 + D4     / 1 + D + D2 + D3 + D4
 * G3/G3 = 1
 */
extern const struct osmo_conv_code gsm0503_tch_afs_10_2;

/*! structure describing TCH/AFS 7.95 kbits convolutional code:.
 * G4/G4 = 1
 * G5/G4 = 1 + D + D4 + D6           / 1 + D2 + D3 + D5 + D6
 * G6/G4 = 1 + D + D2 + D3 + D4 + D6 / 1 + D2 + D3 + D5 + D6
 */
extern const struct osmo_conv_code gsm0503_tch_afs_7_95;

/*! structure describing TCH/AFS 7.4 kbits convolutional code:.
 * G1/G3 = 1 + D + D3 + D4 / 1 + D + D2 + D3 + D4
 * G2/G3 = 1 + D2 + D4     / 1 + D + D2 + D3 + D4
 * G3/G3 = 1
 */
extern const struct osmo_conv_code gsm0503_tch_afs_7_4;

/*! structure describing TCH/AFS 6.7 kbits convolutional code:.
 * G1/G3 = 1 + D + D3 + D4 / 1 + D + D2 + D3 + D4
 * G2/G3 = 1 + D2 + D4     / 1 + D + D2 + D3 + D4
 * G3/G3 = 1
 * G3/G3 = 1
 */
extern const struct osmo_conv_code gsm0503_tch_afs_6_7;

/*! structure describing TCH/AFS 5.9 kbits convolutional code:.
 * 124 bits
 * G4/G6 = 1 + D2 + D3 + D5 + D6 / 1 + D + D2 + D3 + D4 + D6
 * G5/G6 = 1 + D + D4 + D6       / 1 + D + D2 + D3 + D4 + D6
 * G6/G6 = 1
 * G6/G6 = 1
 */
extern const struct osmo_conv_code gsm0503_tch_afs_5_9;

/*! structure describing TCH/AFS 5.15 kbits convolutional code:.
 * G1/G3 = 1 + D + D3 + D4 / 1 + D + D2 + D3 + D4
 * G1/G3 = 1 + D + D3 + D4 / 1 + D + D2 + D3 + D4
 * G2/G3 = 1 + D2 + D4     / 1 + D + D2 + D3 + D4
 * G3/G3 = 1
 * G3/G3 = 1
 */
extern const struct osmo_conv_code gsm0503_tch_afs_5_15;

/*! structure describing TCH/AFS 4.75 kbits convolutional code:.
 * G4/G6 = 1 + D2 + D3 + D5 + D6 / 1 + D + D2 + D3 + D4 + D6
 * G4/G6 = 1 + D2 + D3 + D5 + D6 / 1 + D + D2 + D3 + D4 + D6
 * G5/G6 = 1 + D + D4 + D6       / 1 + D + D2 + D3 + D4 + D6
 * G6/G6 = 1
 * G6/G6 = 1
 */
extern const struct osmo_conv_code gsm0503_tch_afs_4_75;

/*! structure describing TCH/F convolutional code.
 */
extern const struct osmo_conv_code gsm0503_tch_fr;

/*! structure describing TCH/H convolutional code.
 */
extern const struct osmo_conv_code gsm0503_tch_hr;

/*! structure describing TCH/AHS 7.95 kbits convolutional code.
 */
extern const struct osmo_conv_code gsm0503_tch_ahs_7_95;

/*! structure describing TCH/AHS 7.4 kbits convolutional code.
 */
extern const struct osmo_conv_code gsm0503_tch_ahs_7_4;

/*! structure describing TCH/AHS 6.7 kbits convolutional code.
 */
extern const struct osmo_conv_code gsm0503_tch_ahs_6_7;

/*! structure describing TCH/AHS 5.9 kbits convolutional code.
 */
extern const struct osmo_conv_code gsm0503_tch_ahs_5_9;

/*! structure describing TCH/AHS 5.15 kbits convolutional code.
 */
extern const struct osmo_conv_code gsm0503_tch_ahs_5_15;

/*! structure describing TCH/AHS 4.75 kbits convolutional code.
 */
extern const struct osmo_conv_code gsm0503_tch_ahs_4_75;

/*! structure describing EDGE MCS-1 DL header convolutional code:.
 * 42 bits blocks, rate 1/3, k = 7
 * G4 = 1 + D2 + D3 + D5 + D6
 * G7 = 1 + D + D2 + D3 + D6
 * G5 = 1 + D + D4 + D6
 */
extern const struct osmo_conv_code gsm0503_mcs1_dl_hdr;

/*! structure describing EDGE MCS-1 UL header convolutional code:.
 * 45 bits blocks, rate 1/3, k = 7
 * G4 = 1 + D2 + D3 + D5 + D6
 * G7 = 1 + D + D2 + D3 + D6
 * G5 = 1 + D + D4 + D6
 */
extern const struct osmo_conv_code gsm0503_mcs1_ul_hdr;

/*! structure describing EDGE MCS-1 data convolutional code:.
 * 196 bits blocks, rate 1/3, k = 7
 * G4 = 1 + D2 + D3 + D5 + D6
 * G7 = 1 + D + D2 + D3 + D6
 * G5 = 1 + D + D4 + D6
 */
extern const struct osmo_conv_code gsm0503_mcs1;

/*! structure describing EDGE MCS-2 data convolutional code:.
 * 244 bits blocks, rate 1/3, k = 7
 * G4 = 1 + D2 + D3 + D5 + D6
 * G7 = 1 + D + D2 + D3 + D6
 * G5 = 1 + D + D4 + D6
 */
extern const struct osmo_conv_code gsm0503_mcs2;

/*! structure describing EDGE MCS-3 data convolutional code:.
 * 316 bits blocks, rate 1/3, k = 7
 * G4 = 1 + D2 + D3 + D5 + D6
 * G7 = 1 + D + D2 + D3 + D6
 * G5 = 1 + D + D4 + D6
 */
extern const struct osmo_conv_code gsm0503_mcs3;

/*! structure describing EDGE MCS-4 data convolutional code:.
 * 372 bits blocks, rate 1/3, k = 7
 * G4 = 1 + D2 + D3 + D5 + D6
 * G7 = 1 + D + D2 + D3 + D6
 * G5 = 1 + D + D4 + D6
 */
extern const struct osmo_conv_code gsm0503_mcs4;

/*! structure describing EDGE MCS-5 DL header convolutional code:.
 * 39 bits blocks, rate 1/3, k = 7
 * G4 = 1 + D2 + D3 + D5 + D6
 * G7 = 1 + D + D2 + D3 + D6
 * G5 = 1 + D + D4 + D6
 */
extern const struct osmo_conv_code gsm0503_mcs5_dl_hdr;

/*! structure describing EDGE MCS-5 UL header convolutional code:.
 * 51 bits blocks, rate 1/3, k = 7
 * G4 = 1 + D2 + D3 + D5 + D6
 * G7 = 1 + D + D2 + D3 + D6
 * G5 = 1 + D + D4 + D6
 */
extern const struct osmo_conv_code gsm0503_mcs5_ul_hdr;

/*! structure describing EDGE MCS-5 data convolutional code:.
 * 468 bits blocks, rate 1/3, k = 7
 * G4 = 1 + D2 + D3 + D5 + D6
 * G7 = 1 + D + D2 + D3 + D6
 * G5 = 1 + D + D4 + D6
 */
extern const struct osmo_conv_code gsm0503_mcs5;

/*! structure describing EDGE MCS-6 data convolutional code:.
 * 612 bits blocks, rate 1/3, k = 7
 * G4 = 1 + D2 + D3 + D5 + D6
 * G7 = 1 + D + D2 + D3 + D6
 * G5 = 1 + D + D4 + D6
 */
extern const struct osmo_conv_code gsm0503_mcs6;

/*! structure describing EDGE MCS-7 DL header convolutional code:.
 * 51 bits blocks, rate 1/3, k = 7
 * G4 = 1 + D2 + D3 + D5 + D6
 * G7 = 1 + D + D2 + D3 + D6
 * G5 = 1 + D + D4 + D6
 */
extern const struct osmo_conv_code gsm0503_mcs7_dl_hdr;

/*! structure describing EDGE MCS-7 UL header convolutional code:.
 * 60 bits blocks, rate 1/3, k = 7
 * G4 = 1 + D2 + D3 + D5 + D6
 * G7 = 1 + D + D2 + D3 + D6
 * G5 = 1 + D + D4 + D6
 */
extern const struct osmo_conv_code gsm0503_mcs7_ul_hdr;

/*! structure describing EDGE MCS-7 data convolutional code:.
 * 468 bits blocks, rate 1/3, k = 7
 * G4 = 1 + D2 + D3 + D5 + D6
 * G7 = 1 + D + D2 + D3 + D6
 * G5 = 1 + D + D4 + D6
 */
extern const struct osmo_conv_code gsm0503_mcs7;

/*! structure describing EDGE MCS-8 data convolutional code:.
 * 564 bits blocks, rate 1/3, k = 7
 * G4 = 1 + D2 + D3 + D5 + D6
 * G7 = 1 + D + D2 + D3 + D6
 * G5 = 1 + D + D4 + D6
 */
extern const struct osmo_conv_code gsm0503_mcs8;

/*! structure describing EDGE MCS-9 data convolutional code:.
 * 612 bits blocks, rate 1/3, k = 7
 * G4 = 1 + D2 + D3 + D5 + D6
 * G7 = 1 + D + D2 + D3 + D6
 * G5 = 1 + D + D4 + D6
 */
extern const struct osmo_conv_code gsm0503_mcs9;

