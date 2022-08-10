/*! \file gsm0503_tables.h
 *  GSM TS 05.03 tables.
 */

#pragma once

#include <stdint.h>
#include <osmocom/core/bits.h>
//#include "bits.h"

/*! \addtogroup tables
 *  @{
 * \file gsm0503_tables.h */

extern const ubit_t gsm0503_pdtch_hl_hn_ubit[4][8];
extern const ubit_t gsm0503_pdtch_edge_hl_hn_ubit[3][8];
extern const sbit_t gsm0503_pdtch_hl_hn_sbit[4][8];
extern const sbit_t gsm0503_pdtch_edge_hl_hn_sbit[3][8];
extern const ubit_t gsm0503_usf2six[8][6];
extern const ubit_t gsm0503_usf2twelve_ubit[8][12];
extern const sbit_t gsm0503_usf2twelve_sbit[8][12];
extern const uint8_t gsm0503_puncture_cs2[588];
extern const uint8_t gsm0503_puncture_cs3[676];
extern const uint8_t gsm0503_puncture_mcs1_dl_hdr[108];
extern const uint8_t gsm0503_puncture_mcs1_ul_hdr[117];
extern const uint8_t gsm0503_puncture_mcs1_p1[588];
extern const uint8_t gsm0503_puncture_mcs1_p2[588];
extern const uint8_t gsm0503_puncture_mcs2_p1[732];
extern const uint8_t gsm0503_puncture_mcs2_p2[732];
extern const uint8_t gsm0503_puncture_mcs3_p1[948];
extern const uint8_t gsm0503_puncture_mcs3_p2[948];
extern const uint8_t gsm0503_puncture_mcs3_p3[948];
extern const uint8_t gsm0503_puncture_mcs4_p1[1116];
extern const uint8_t gsm0503_puncture_mcs4_p2[1116];
extern const uint8_t gsm0503_puncture_mcs4_p3[1116];
extern const uint8_t gsm0503_puncture_mcs5_p1[1404];
extern const uint8_t gsm0503_puncture_mcs5_p2[1404];
extern const uint8_t gsm0503_puncture_mcs6_p1[1836];
extern const uint8_t gsm0503_puncture_mcs6_p2[1836];
extern const uint8_t gsm0503_puncture_mcs7_dl_hdr[135];
extern const uint8_t gsm0503_puncture_mcs7_ul_hdr[162];
extern const uint8_t gsm0503_puncture_mcs7_p1[1404];
extern const uint8_t gsm0503_puncture_mcs7_p2[1404];
extern const uint8_t gsm0503_puncture_mcs7_p3[1404];
extern const uint8_t gsm0503_puncture_mcs8_p1[1692];
extern const uint8_t gsm0503_puncture_mcs8_p2[1692];
extern const uint8_t gsm0503_puncture_mcs8_p3[1692];
extern const uint8_t gsm0503_puncture_mcs9_p1[1836];
extern const uint8_t gsm0503_puncture_mcs9_p2[1836];
extern const uint8_t gsm0503_puncture_mcs9_p3[1836];
extern const uint16_t gsm0503_interleave_mcs5[1248];
extern const uint8_t gsm0503_gsm_fr_map[76];
extern const uint8_t gsm0503_gsm_efr_protected_bits[65];
extern const ubit_t gsm0503_afs_ic_ubit[4][8];
extern const sbit_t gsm0503_afs_ic_sbit[4][8];
extern const ubit_t gsm0503_ahs_ic_ubit[4][4];
extern const sbit_t gsm0503_ahs_ic_sbit[4][4];
extern const uint8_t gsm0503_tch_hr_interleaving[228][2];
extern const ubit_t gsm0503_mcs5_usf_precode_table[8][36];

/*! @} */
