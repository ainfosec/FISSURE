/*! \file gsm0503_coding.h
 *  GSM TS 05.03 coding
 */

#pragma once

#include <stdint.h>

#include <osmocom/core/defs.h>
#include <osmocom/core/bits.h>

#include <stdbool.h> //!!

/*! \addtogroup coding
 *  @{
 * \file gsm0503_coding.h */

#define GSM0503_GPRS_BURSTS_NBITS	(116 * 4)
#define GSM0503_EGPRS_BURSTS_NBITS	(348 * 4)

enum gsm0503_egprs_mcs {
	EGPRS_MCS0,
	EGPRS_MCS1,
	EGPRS_MCS2,
	EGPRS_MCS3,
	EGPRS_MCS4,
	EGPRS_MCS5,
	EGPRS_MCS6,
	EGPRS_MCS7,
	EGPRS_MCS8,
	EGPRS_MCS9,
	EGPRS_NUM_MCS,
};

int gsm0503_xcch_encode(ubit_t *bursts, const uint8_t *l2_data);
int gsm0503_xcch_decode(uint8_t *l2_data, const sbit_t *bursts,
	int *n_errors, int *n_bits_total);

int gsm0503_pdtch_encode(ubit_t *bursts, const uint8_t *l2_data, uint8_t l2_len);
int gsm0503_pdtch_decode(uint8_t *l2_data, const sbit_t *bursts, uint8_t *usf_p,
	int *n_errors, int *n_bits_total);

int gsm0503_pdtch_egprs_encode(ubit_t *bursts, const uint8_t *l2_data,
	uint8_t l2_len);
int gsm0503_pdtch_egprs_decode(uint8_t *l2_data, const sbit_t *bursts,
	uint16_t nbits, uint8_t *usf_p, int *n_errors, int *n_bits_total);

int gsm0503_tch_fr_encode(ubit_t *bursts, const uint8_t *tch_data, int len,
	int net_order);
int gsm0503_tch_fr_decode(uint8_t *tch_data, const sbit_t *bursts, int net_order,
	int efr, int *n_errors, int *n_bits_total);

int gsm0503_tch_hr_encode(ubit_t *bursts, const uint8_t *tch_data, int len);
int gsm0503_tch_hr_decode(uint8_t *tch_data, const sbit_t *bursts, int odd,
	int *n_errors, int *n_bits_total);

int gsm0503_tch_afs_encode(ubit_t *bursts, const uint8_t *tch_data, int len,
	int codec_mode_req, uint8_t *codec, int codecs, uint8_t ft,
	uint8_t cmr);
int gsm0503_tch_afs_decode(uint8_t *tch_data, const sbit_t *bursts,
	int codec_mode_req, uint8_t *codec, int codecs, uint8_t *ft,
	uint8_t *cmr, int *n_errors, int *n_bits_total);

int gsm0503_tch_ahs_encode(ubit_t *bursts, const uint8_t *tch_data, int len,
	int codec_mode_req, uint8_t *codec, int codecs, uint8_t ft, uint8_t cmr);
int gsm0503_tch_ahs_decode(uint8_t *tch_data, const sbit_t *bursts, int odd,
	int codec_mode_req, uint8_t *codec, int codecs, uint8_t *ft,
	uint8_t *cmr, int *n_errors, int *n_bits_total);

//int gsm0503_rach_ext_encode(ubit_t *burst, uint16_t ra, uint8_t bsic, bool is_11bit);
//int gsm0503_rach_encode(ubit_t *burst, const uint8_t *ra, uint8_t bsic) OSMO_DEPRECATED("Use gsm0503_rach_ext_encode() instead");

//int gsm0503_rach_decode(uint8_t *ra, const sbit_t *burst, uint8_t bsic)
//	OSMO_DEPRECATED("Use gsm0503_rach_decode_ber() instead");
//int gsm0503_rach_decode_ber(uint8_t *ra, const sbit_t *burst, uint8_t bsic,
			    //int *n_errors, int *n_bits_total);
//int gsm0503_rach_ext_decode(uint16_t *ra, const sbit_t *burst, uint8_t bsic)
//	OSMO_DEPRECATED("Use gsm0503_rach_ext_decode_ber() instead");
//int gsm0503_rach_ext_decode_ber(uint16_t *ra, const sbit_t *burst, uint8_t bsic,
//				int *n_errors, int *n_bits_total);

int gsm0503_sch_encode(ubit_t *burst, const uint8_t *sb_info);
int gsm0503_sch_decode(uint8_t *sb_info, const sbit_t *burst);

/*! @} */
