/*! \file gsm0503_interleaving.h
 *  GSM TS 05.03 interleaving.
 */

#pragma once

#include <osmocom/core/bits.h>

/*! \addtogroup interleaving
 *  @{
 * \file gsm0503_interleaving.h */

void gsm0503_xcch_deinterleave(sbit_t *cB, const sbit_t *iB);
void gsm0503_xcch_interleave(const ubit_t *cB, ubit_t *iB);

void gsm0503_tch_fr_deinterleave(sbit_t *cB, const sbit_t *iB);
void gsm0503_tch_fr_interleave(const ubit_t *cB, ubit_t *iB);

void gsm0503_tch_hr_deinterleave(sbit_t *cB, const sbit_t *iB);
void gsm0503_tch_hr_interleave(const ubit_t *cB, ubit_t *iB);

void gsm0503_mcs1_ul_deinterleave(sbit_t *hc, sbit_t *dc, const sbit_t *iB);
void gsm0503_mcs1_ul_interleave(const ubit_t *hc,
	const ubit_t *dc, ubit_t *iB);

void gsm0503_mcs1_dl_deinterleave(sbit_t *u, sbit_t *hc,
	sbit_t *dc, const sbit_t *iB);
void gsm0503_mcs1_dl_interleave(const ubit_t *up, const ubit_t *hc,
	const ubit_t *dc, ubit_t *iB);

void gsm0503_mcs5_ul_deinterleave(sbit_t *hc, sbit_t *dc,
	const sbit_t *hi, const sbit_t *di);
void gsm0503_mcs5_ul_interleave(const ubit_t *hc, const ubit_t *dc,
	ubit_t *hi, ubit_t *di);

void gsm0503_mcs5_dl_deinterleave(sbit_t *hc, sbit_t *dc,
	const sbit_t *hi, const sbit_t *di);
void gsm0503_mcs5_dl_interleave(const ubit_t *hc, const ubit_t *dc,
	ubit_t *hi, ubit_t *di);

void gsm0503_mcs7_ul_deinterleave(sbit_t *hc, sbit_t *c1, sbit_t *c2,
	const sbit_t *hi, const sbit_t *di);
void gsm0503_mcs7_ul_interleave(const ubit_t *hc, const ubit_t *c1,
	const ubit_t *c2, ubit_t *hi, ubit_t *di);

void gsm0503_mcs7_dl_deinterleave(sbit_t *hc, sbit_t *c1, sbit_t *c2,
	const sbit_t *hi, const sbit_t *di);
void gsm0503_mcs7_dl_interleave(const ubit_t *hc, const ubit_t *c1,
	const ubit_t *c2, ubit_t *hi, ubit_t *di);

void gsm0503_mcs8_ul_deinterleave(sbit_t *hc, sbit_t *c1, sbit_t *c2,
	const sbit_t *hi, const sbit_t *di);
void gsm0503_mcs8_ul_interleave(const ubit_t *hc, const ubit_t *c1,
	const ubit_t *c2, ubit_t *hi, ubit_t *di);

void gsm0503_mcs8_dl_deinterleave(sbit_t *hc, sbit_t *c1, sbit_t *c2,
	const sbit_t *hi, const sbit_t *di);
void gsm0503_mcs8_dl_interleave(const ubit_t *hc, const ubit_t *c1,
	const ubit_t *c2, ubit_t *hi, ubit_t *di);

/*! @} */
