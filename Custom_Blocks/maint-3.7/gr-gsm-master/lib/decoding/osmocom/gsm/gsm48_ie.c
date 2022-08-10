/*! \file gsm48_ie.c
 * GSM Mobile Radio Interface Layer 3 messages.
 * 3GPP TS 04.08 version 7.21.0 Release 1998 / ETSI TS 100 940 V7.21.0. */
/*
 * (C) 2008 by Harald Welte <laforge@gnumonks.org>
 * (C) 2009-2010 by Andreas Eversberg
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
#include <string.h>
#include <errno.h>

#include <osmocom/core/utils.h>
/*#include <osmocom/core/msgb.h>*/
/* #include <osmocom/gsm/tlv.h> */
/* #include <osmocom/gsm/mncc.h> */
#include <osmocom/gsm/protocol/gsm_04_08.h>
#include <osmocom/gsm/gsm48_ie.h>

/*! \addtogroup gsm0408
 *  @{
 */

//static const char bcd_num_digits[] = {
//	'0', '1', '2', '3', '4', '5', '6', '7',
//	'8', '9', '*', '#', 'a', 'b', 'c', '\0'
//};

///*! decode a 'called/calling/connect party BCD number' as in 10.5.4.7
// *  \param[out] Caller-provided output buffer
// *  \param[in] bcd_lv Length-Value portion of to-be-decoded IE
// *  \param[in] h_len Length of an optional heder between L and V portion
// *  \returns - in case of success; negative on error */
//int gsm48_decode_bcd_number(char *output, int output_len,
//			    const uint8_t *bcd_lv, int h_len)
//{
//	uint8_t in_len = bcd_lv[0];
//	int i;

//	for (i = 1 + h_len; i <= in_len; i++) {
//		/* lower nibble */
//		output_len--;
//		if (output_len <= 1)
//			break;
//		*output++ = bcd_num_digits[bcd_lv[i] & 0xf];

//		/* higher nibble */
//		output_len--;
//		if (output_len <= 1)
//			break;
//		*output++ = bcd_num_digits[bcd_lv[i] >> 4];
//	}
//	if (output_len >= 1)
//		*output++ = '\0';

//	return 0;
//}

///*! convert a single ASCII character to call-control BCD */
//static int asc_to_bcd(const char asc)
//{
//	int i;

//	for (i = 0; i < ARRAY_SIZE(bcd_num_digits); i++) {
//		if (bcd_num_digits[i] == asc)
//			return i;
//	}
//	return -EINVAL;
//}

///*! convert a ASCII phone number to 'called/calling/connect party BCD number'
// *  \param[out] bcd_lv Caller-provided output buffer
// *  \param[in] max_len Maximum Length of \a bcd_lv
// *  \param[in] h_len Length of an optional heder between L and V portion
// *  \param[in] input phone number as 0-terminated ASCII
// *  \returns number of bytes used in \a bcd_lv */
//int gsm48_encode_bcd_number(uint8_t *bcd_lv, uint8_t max_len,
//		      int h_len, const char *input)
//{
//	int in_len = strlen(input);
//	int i;
//	uint8_t *bcd_cur = bcd_lv + 1 + h_len;

//	/* two digits per byte, plus type byte */
//	bcd_lv[0] = in_len/2 + h_len;
//	if (in_len % 2)
//		bcd_lv[0]++;

//	if (bcd_lv[0] > max_len)
//		return -EIO;

//	for (i = 0; i < in_len; i++) {
//		int rc = asc_to_bcd(input[i]);
//		if (rc < 0)
//			return rc;
//		if (i % 2 == 0)
//			*bcd_cur = rc;
//		else
//			*bcd_cur++ |= (rc << 4);
//	}
//	/* append padding nibble in case of odd length */
//	if (i % 2)
//		*bcd_cur++ |= 0xf0;

//	/* return how many bytes we used */
//	return (bcd_cur - bcd_lv);
//}

///*! Decode TS 04.08 Bearer Capability IE (10.5.4.5)
// *  \param[out] Caller-provided memory for decoded output
// *  \[aram[in] LV portion of TS 04.08 Bearer Capability
// *  \returns 0 on success; negative on error */
//int gsm48_decode_bearer_cap(struct gsm_mncc_bearer_cap *bcap,
//			     const uint8_t *lv)
//{
//	uint8_t in_len = lv[0];
//	int i, s;

//	if (in_len < 1)
//		return -EINVAL;

//	bcap->speech_ver[0] = -1; /* end of list, of maximum 7 values */

//	/* octet 3 */
//	bcap->transfer = lv[1] & 0x07;
//	bcap->mode = (lv[1] & 0x08) >> 3;
//	bcap->coding = (lv[1] & 0x10) >> 4;
//	bcap->radio = (lv[1] & 0x60) >> 5;

//	switch (bcap->transfer) {
//	case GSM_MNCC_BCAP_SPEECH:
//		i = 1;
//		s = 0;
//		while(!(lv[i] & 0x80)) {
//			i++; /* octet 3a etc */
//			if (in_len < i)
//				return 0;
//			bcap->speech_ver[s++] = lv[i] & 0x0f;
//			bcap->speech_ver[s] = -1; /* end of list */
//			if (i == 2) /* octet 3a */
//				bcap->speech_ctm = (lv[i] & 0x20) >> 5;
//			if (s == 7) /* maximum speech versions + end of list */
//				return 0;
//		}
//		break;
//	case GSM_MNCC_BCAP_UNR_DIG:
//	case GSM_MNCC_BCAP_FAX_G3:
//		i = 1;
//		while(!(lv[i] & 0x80)) {
//			i++; /* octet 3a etc */
//			if (in_len < i)
//				return 0;
//			/* ignore them */
//		}
//		/* octet 4: skip */
//		i++;
//		/* octet 5 */
//		i++;
//		if (in_len < i)
//			return 0;
//		bcap->data.rate_adaption = (lv[i] >> 3) & 3;
//		bcap->data.sig_access = lv[i] & 7;
//		while(!(lv[i] & 0x80)) {
//			i++; /* octet 5a etc */
//			if (in_len < i)
//				return 0;
//			/* ignore them */
//		}
//		/* octet 6 */
//		i++;
//		if (in_len < i)
//			return 0;
//		bcap->data.async = lv[i] & 1;
//		if (!(lv[i] & 0x80)) {
//			i++;
//			if (in_len < i)
//				return 0;
//			/* octet 6a */
//			bcap->data.nr_stop_bits = ((lv[i] >> 7) & 1) + 1;
//			if (lv[i] & 0x10)
//				bcap->data.nr_data_bits = 8;
//			else
//				bcap->data.nr_data_bits = 7;
//			bcap->data.user_rate = lv[i]  & 0xf;

//			if (!(lv[i] & 0x80)) {
//				i++;
//				if (in_len < i)
//					return 0;
//				/* octet 6b */
//				bcap->data.parity = lv[i] & 7;
//				bcap->data.interm_rate = (lv[i] >> 5) & 3;

//				/* octet 6c */
//				if (!(lv[i] & 0x80)) {
//					i++;
//					if (in_len < i)
//						return 0;
//					bcap->data.transp = (lv[i] >> 5) & 3;
//					bcap->data.modem_type = lv[i] & 0x1F;
//				}
//			}

//		}
//		break;
//	default:
//		i = 1;
//		while (!(lv[i] & 0x80)) {
//			i++; /* octet 3a etc */
//			if (in_len < i)
//				return 0;
//			/* ignore them */
//		}
//		/* FIXME: implement OCTET 4+ parsing */
//		break;
//	}

//	return 0;
//}

///*! Encode TS 04.08 Bearer Capability IE (10.5.4.5)
// *  \param[out] msg Message Buffer to which IE is to be appended
// *  \param[in] lv_only Write only LV portion (1) or TLV (0)
// *  \param[in] bcap Decoded Bearer Capability to be encoded
// *  \returns 0 on success; negative on error */
//int gsm48_encode_bearer_cap(struct msgb *msg, int lv_only,
//			     const struct gsm_mncc_bearer_cap *bcap)
//{
//	uint8_t lv[32 + 1];
//	int i = 1, s;

//	lv[1] = bcap->transfer;
//	lv[1] |= bcap->mode << 3;
//	lv[1] |= bcap->coding << 4;
//	lv[1] |= bcap->radio << 5;

//	switch (bcap->transfer) {
//	case GSM_MNCC_BCAP_SPEECH:
//		for (s = 0; bcap->speech_ver[s] >= 0; s++) {
//			i++; /* octet 3a etc */
//			lv[i] = bcap->speech_ver[s];
//			if (i == 2) /* octet 3a */
//				lv[i] |= bcap->speech_ctm << 5;
//		}
//		lv[i] |= 0x80; /* last IE of octet 3 etc */
//		break;
//	case GSM48_BCAP_ITCAP_UNR_DIG_INF:
//	case GSM48_BCAP_ITCAP_FAX_G3:
//		lv[i++] |= 0x80; /* last IE of octet 3 etc */
//		/* octet 4 */
//		lv[i++] = 0xb8;
//		/* octet 5 */
//		lv[i++] = 0x80 | ((bcap->data.rate_adaption & 3) << 3)
//			  | (bcap->data.sig_access & 7);
//		/* octet 6 */
//		lv[i++] = 0x20 | (bcap->data.async & 1);
//		/* octet 6a */
//		lv[i++] = (bcap->data.user_rate & 0xf) |
//			  (bcap->data.nr_data_bits == 8 ? 0x10 : 0x00) |
//			  (bcap->data.nr_stop_bits == 2 ? 0x40 : 0x00);
//		/* octet 6b */
//		lv[i++] = (bcap->data.parity & 7) |
//			  ((bcap->data.interm_rate & 3) << 5);
//		/* octet 6c */
//		lv[i] = 0x80 | (bcap->data.modem_type & 0x1f);
//		break;
//	default:
//		return -EINVAL;
//	}

//	lv[0] = i;
//	if (lv_only)
//		msgb_lv_put(msg, lv[0], lv+1);
//	else
//		msgb_tlv_put(msg, GSM48_IE_BEARER_CAP, lv[0], lv+1);

//	return 0;
//}

///*! Decode TS 04.08 Call Control Capabilities IE (10.5.4.5a)
// *  \param[out] Caller-provided memory for decoded CC capabilities
// *  \param[in] lv Length-Value of IE
// *  \retursns 0 on success; negative on error */
//int gsm48_decode_cccap(struct gsm_mncc_cccap *ccap, const uint8_t *lv)
//{
//	uint8_t in_len = lv[0];

//	if (in_len < 1)
//		return -EINVAL;

//	/* octet 3 */
//	ccap->dtmf = lv[1] & 0x01;
//	ccap->pcp = (lv[1] & 0x02) >> 1;

//	return 0;
//}

///*! Encodoe TS 04.08 Call Control Capabilities (10.5.4.5a)
// *  \param[out] msg Message Buffer to which to append IE (as TLV)
// *  \param[in] ccap Decoded CC Capabilities to be encoded
// *  \returns 0 on success; negative on error */
//int gsm48_encode_cccap(struct msgb *msg,
//			const struct gsm_mncc_cccap *ccap)
//{
//	uint8_t lv[2];

//	lv[0] = 1;
//	lv[1] = 0;
//	if (ccap->dtmf)
//		lv [1] |= 0x01;
//	if (ccap->pcp)
//		lv [1] |= 0x02;

//	msgb_tlv_put(msg, GSM48_IE_CC_CAP, lv[0], lv+1);

//	return 0;
//}

///*! Decode TS 04.08 Called Party BCD Number IE (10.5.4.7)
// *  \param[out] called Caller-provided memory for decoded number
// *  \param[in] lv Length-Value portion of IE
// *  \returns 0 on success; negative on error */
//int gsm48_decode_called(struct gsm_mncc_number *called,
//			 const uint8_t *lv)
//{
//	uint8_t in_len = lv[0];

//	if (in_len < 1)
//		return -EINVAL;

//	/* octet 3 */
//	called->plan = lv[1] & 0x0f;
//	called->type = (lv[1] & 0x70) >> 4;

//	/* octet 4..N */
//	gsm48_decode_bcd_number(called->number, sizeof(called->number), lv, 1);

//	return 0;
//}

///*! Encode TS 04.08 Called Party IE (10.5.4.7)
// *  \param[out] msg Mesage Buffer to which to append IE (as TLV)
// *  \param[in] called MNCC Number to encode/append
// *  \returns 0 on success; negative on error */
//int gsm48_encode_called(struct msgb *msg,
//			 const struct gsm_mncc_number *called)
//{
//	uint8_t lv[18];
//	int ret;

//	/* octet 3 */
//	lv[1] = 0x80; /* no extension */
//	lv[1] |= called->plan;
//	lv[1] |= called->type << 4;

//	/* octet 4..N, octet 2 */
//	ret = gsm48_encode_bcd_number(lv, sizeof(lv), 1, called->number);
//	if (ret < 0)
//		return ret;

//	msgb_tlv_put(msg, GSM48_IE_CALLED_BCD, lv[0], lv+1);

//	return 0;
//}

///*! Decode TS 04.08 Caller ID
// *  \param[out] called Caller-provided memory for decoded number
// *  \param[in] lv Length-Value portion of IE
// *  \returns 0 on success; negative on error */
//int gsm48_decode_callerid(struct gsm_mncc_number *callerid,
//			 const uint8_t *lv)
//{
//	uint8_t in_len = lv[0];
//	int i = 1;

//	if (in_len < 1)
//		return -EINVAL;

//	/* octet 3 */
//	callerid->plan = lv[1] & 0x0f;
//	callerid->type = (lv[1] & 0x70) >> 4;

//	/* octet 3a */
//	if (!(lv[1] & 0x80)) {
//		callerid->screen = lv[2] & 0x03;
//		callerid->present = (lv[2] & 0x60) >> 5;
//		i = 2;
//	}

//	/* octet 4..N */
//	gsm48_decode_bcd_number(callerid->number, sizeof(callerid->number), lv, i);

//	return 0;
//}

///*! Encode TS 04.08 Caller ID IE
// *  \param[out] msg Mesage Buffer to which to append IE (as TLV)
// *  \param[in] ie IE Identifier (tag)
// *  \param[in] max_len maximum generated output in bytes
// *  \param[in] callerid MNCC Number to encode/append
// *  \returns 0 on success; negative on error */
//int gsm48_encode_callerid(struct msgb *msg, int ie, int max_len,
//			   const struct gsm_mncc_number *callerid)
//{
//	uint8_t * lv = malloc(sizeof(uint8_t)*(max_len - 1));
//	int h_len = 1;
//	int ret;

//	/* octet 3 */
//	lv[1] = callerid->plan;
//	lv[1] |= callerid->type << 4;

//	if (callerid->present || callerid->screen) {
//		/* octet 3a */
//		lv[2] = callerid->screen;
//		lv[2] |= callerid->present << 5;
//		lv[2] |= 0x80;
//		h_len++;
//	} else
//		lv[1] |= 0x80;

//	/* octet 4..N, octet 2 */
//	ret = gsm48_encode_bcd_number(lv, sizeof(lv), h_len, callerid->number);
//	if (ret < 0)
//		return ret;

//	msgb_tlv_put(msg, ie, lv[0], lv+1);
//	free(lv);
//	return 0;
//}

///*! Decode TS 04.08 Cause IE (10.5.4.11)
// *  \param[out] cause Caller-provided memory for output
// *  \param[in] lv LV portion of Cause IE
// *  \returns 0 on success; negative on error */
//int gsm48_decode_cause(struct gsm_mncc_cause *cause,
//			const uint8_t *lv)
//{
//	uint8_t in_len = lv[0];
//	int i;

//	if (in_len < 2)
//		return -EINVAL;

//	cause->diag_len = 0;

//	/* octet 3 */
//	cause->location = lv[1] & 0x0f;
//	cause->coding = (lv[1] & 0x60) >> 5;

//	i = 1;
//	if (!(lv[i] & 0x80)) {
//		i++; /* octet 3a */
//		if (in_len < i+1)
//			return 0;
//		cause->rec = 1;
//		cause->rec_val = lv[i] & 0x7f;
//	}
//	i++;

//	/* octet 4 */
//	cause->value = lv[i] & 0x7f;
//	i++;

//	if (in_len < i) /* no diag */
//		return 0;

//	if (in_len - (i-1) > 32) /* maximum 32 octets */
//		return 0;

//	/* octet 5-N */
//	memcpy(cause->diag, lv + i, in_len - (i-1));
//	cause->diag_len = in_len - (i-1);

//	return 0;
//}

///*! Encode TS 04.08 Cause IE (10.5.4.11)
// *  \param[out] msg Message Buffer to which to append IE
// *  \param[in] lv_only Encode as LV (1) or TLV (0)
// *  \param[in] cause Cause value to be encoded
// *  \returns 0 on success; negative on error */
//int gsm48_encode_cause(struct msgb *msg, int lv_only,
//			const struct gsm_mncc_cause *cause)
//{
//	uint8_t lv[32+4];
//	int i;

//	if (cause->diag_len > 32)
//		return -EINVAL;

//	/* octet 3 */
//	lv[1] = cause->location;
//	lv[1] |= cause->coding << 5;

//	i = 1;
//	if (cause->rec) {
//		i++; /* octet 3a */
//		lv[i] = cause->rec_val;
//	}
//	lv[i] |= 0x80; /* end of octet 3 */

//	/* octet 4 */
//	i++;
//	lv[i] = 0x80 | cause->value;

//	/* octet 5-N */
//	if (cause->diag_len) {
//		memcpy(lv + i, cause->diag, cause->diag_len);
//		i += cause->diag_len;
//	}

//	lv[0] = i;
//	if (lv_only)
//		msgb_lv_put(msg, lv[0], lv+1);
//	else
//		msgb_tlv_put(msg, GSM48_IE_CAUSE, lv[0], lv+1);

//	return 0;
//}

///*! Decode TS 04.08 Calling Number IE (10.5.4.9) */
//int gsm48_decode_calling(struct gsm_mncc_number *calling,
//			 const uint8_t *lv)
//{
//	return gsm48_decode_callerid(calling, lv);
//}

///*! Encode TS 04.08 Calling Number IE (10.5.4.9) */
//int gsm48_encode_calling(struct msgb *msg, 
//			  const struct gsm_mncc_number *calling)
//{
//	return gsm48_encode_callerid(msg, GSM48_IE_CALLING_BCD, 14, calling);
//}

///*! Decode TS 04.08 Connected Number IE (10.5.4.13) */
//int gsm48_decode_connected(struct gsm_mncc_number *connected,
//			 const uint8_t *lv)
//{
//	return gsm48_decode_callerid(connected, lv);
//}

///*! Encode TS 04.08 Connected Number IE (10.5.4.13) */
//int gsm48_encode_connected(struct msgb *msg,
//			    const struct gsm_mncc_number *connected)
//{
//	return gsm48_encode_callerid(msg, GSM48_IE_CONN_BCD, 14, connected);
//}

///*! Decode TS 04.08 Redirecting Number IE (10.5.4.21b) */
//int gsm48_decode_redirecting(struct gsm_mncc_number *redirecting,
//			 const uint8_t *lv)
//{
//	return gsm48_decode_callerid(redirecting, lv);
//}

///*! Encode TS 04.08 Redirecting Number IE (10.5.4.21b) */
//int gsm48_encode_redirecting(struct msgb *msg,
//			      const struct gsm_mncc_number *redirecting)
//{
//	return gsm48_encode_callerid(msg, GSM48_IE_REDIR_BCD, 19, redirecting);
//}

///*! Decode TS 04.08 Facility IE (10.5.4.15) */
//int gsm48_decode_facility(struct gsm_mncc_facility *facility,
//			   const uint8_t *lv)
//{
//	uint8_t in_len = lv[0];

//	if (in_len < 1)
//		return -EINVAL;

//	if (in_len > sizeof(facility->info))
//		return -EINVAL;

//	memcpy(facility->info, lv+1, in_len);
//	facility->len = in_len;

//	return 0;
//}

///*! Encode TS 04.08 Facility IE (10.5.4.15) */
//int gsm48_encode_facility(struct msgb *msg, int lv_only,
//			   const struct gsm_mncc_facility *facility)
//{
//	uint8_t lv[GSM_MAX_FACILITY + 1];

//	if (facility->len < 1 || facility->len > GSM_MAX_FACILITY)
//		return -EINVAL;

//	memcpy(lv+1, facility->info, facility->len);
//	lv[0] = facility->len;
//	if (lv_only)
//		msgb_lv_put(msg, lv[0], lv+1);
//	else
//		msgb_tlv_put(msg, GSM48_IE_FACILITY, lv[0], lv+1);

//	return 0;
//}

///*! Decode TS 04.08 Notify IE (10.5.4.20) */
//int gsm48_decode_notify(int *notify, const uint8_t *v)
//{
//	*notify = v[0] & 0x7f;

//	return 0;
//}

///*! Encode TS 04.08 Notify IE (10.5.4.20) */
//int gsm48_encode_notify(struct msgb *msg, int notify)
//{
//	msgb_v_put(msg, notify | 0x80);

//	return 0;
//}

///*! Decode TS 04.08 Signal IE (10.5.4.23) */
//int gsm48_decode_signal(int *signal, const uint8_t *v)
//{
//	*signal = v[0];

//	return 0;
//}

///*! Encode TS 04.08 Signal IE (10.5.4.23) */
//int gsm48_encode_signal(struct msgb *msg, int signal)
//{
//	msgb_tv_put(msg, GSM48_IE_SIGNAL, signal);

//	return 0;
//}

///*! Decode TS 04.08 Keypad IE (10.5.4.17) */
//int gsm48_decode_keypad(int *keypad, const uint8_t *lv)
//{
//	uint8_t in_len = lv[0];

//	if (in_len < 1)
//		return -EINVAL;

//	*keypad = lv[1] & 0x7f;

//	return 0;
//}

///*! Encode TS 04.08 Keypad IE (10.5.4.17) */
//int gsm48_encode_keypad(struct msgb *msg, int keypad)
//{
//	msgb_tv_put(msg, GSM48_IE_KPD_FACILITY, keypad);

//	return 0;
//}

///*! Decode TS 04.08 Progress IE (10.5.4.21) */
//int gsm48_decode_progress(struct gsm_mncc_progress *progress,
//			   const uint8_t *lv)
//{
//	uint8_t in_len = lv[0];

//	if (in_len < 2)
//		return -EINVAL;

//	progress->coding = (lv[1] & 0x60) >> 5;
//	progress->location = lv[1] & 0x0f;
//	progress->descr = lv[2] & 0x7f;

//	return 0;
//}

///*! Encode TS 04.08 Progress IE (10.5.4.21) */
//int gsm48_encode_progress(struct msgb *msg, int lv_only,
//			   const struct gsm_mncc_progress *p)
//{
//	uint8_t lv[3];

//	lv[0] = 2;
//	lv[1] = 0x80 | ((p->coding & 0x3) << 5) | (p->location & 0xf);
//	lv[2] = 0x80 | (p->descr & 0x7f);
//	if (lv_only)
//		msgb_lv_put(msg, lv[0], lv+1);
//	else
//		msgb_tlv_put(msg, GSM48_IE_PROGR_IND, lv[0], lv+1);

//	return 0;
//}

///*! Decode TS 04.08 User-User IE (10.5.4.25) */
//int gsm48_decode_useruser(struct gsm_mncc_useruser *uu,
//			   const uint8_t *lv)
//{
//	uint8_t in_len = lv[0];
//	char *info = uu->info;
//	int info_len = sizeof(uu->info);
//	int i;

//	if (in_len < 1)
//		return -EINVAL;

//	uu->proto = lv[1];

//	for (i = 2; i <= in_len; i++) {
//		info_len--;
//		if (info_len <= 1)
//			break;
//		*info++ = lv[i];
//	}
//	if (info_len >= 1)
//		*info++ = '\0';

//	return 0;
//}

///*! Encode TS 04.08 User-User IE (10.5.4.25) */
//int gsm48_encode_useruser(struct msgb *msg, int lv_only,
//			   const struct gsm_mncc_useruser *uu)
//{
//	uint8_t lv[GSM_MAX_USERUSER + 2];

//	if (strlen(uu->info) > GSM_MAX_USERUSER)
//		return -EINVAL;

//	lv[0] = 1 + strlen(uu->info);
//	lv[1] = uu->proto;
//	memcpy(lv + 2, uu->info, strlen(uu->info));
//	if (lv_only)
//		msgb_lv_put(msg, lv[0], lv+1);
//	else
//		msgb_tlv_put(msg, GSM48_IE_USER_USER, lv[0], lv+1);

//	return 0;
//}

///*! Decode TS 04.08 SS Version IE (10.5.4.24) */
//int gsm48_decode_ssversion(struct gsm_mncc_ssversion *ssv,
//			    const uint8_t *lv)
//{
//	uint8_t in_len = lv[0];

//	if (in_len < 1 || in_len < sizeof(ssv->info))
//		return -EINVAL;

//	memcpy(ssv->info, lv + 1, in_len);
//	ssv->len = in_len;

//	return 0;
//}

///*! Encode TS 04.08 SS Version IE (10.5.4.24) */
//int gsm48_encode_ssversion(struct msgb *msg,
//			   const struct gsm_mncc_ssversion *ssv)
//{
//	uint8_t lv[GSM_MAX_SSVERSION + 1];

//	if (ssv->len > GSM_MAX_SSVERSION)
//		return -EINVAL;

//	lv[0] = ssv->len;
//	memcpy(lv + 1, ssv->info, ssv->len);
//	msgb_tlv_put(msg, GSM48_IE_SS_VERS, lv[0], lv+1);

//	return 0;
//}

///* decode 'more data' does not require a function, because it has no value */

///*! Encode TS 04.08 More Data IE (10.5.4.19) */
//int gsm48_encode_more(struct msgb *msg)
//{
//	uint8_t *ie;

//	ie = msgb_put(msg, 1);
//	ie[0] = GSM48_IE_MORE_DATA;

//	return 0;
//}

static int32_t smod(int32_t n, int32_t m)
{
	int32_t res;

	res = n % m;

	if (res <= 0)
		res += m;

	return res;
}

/*! Decode TS 04.08 Cell Channel Description IE (10.5.2.1b) and other frequency lists
 *  \param[out] f Caller-provided output memory
 *  \param[in] cd Cell Channel Description IE
 *  \param[in] len Length of \a cd in bytes
 *  \returns 0 on success; negative on error */
int gsm48_decode_freq_list(struct gsm_sysinfo_freq *f, uint8_t *cd,
			   uint8_t len, uint8_t mask, uint8_t frqt)
{
	int i;

	/* NOTES:
	 *
	 * The Range format uses "SMOD" computation.
	 * e.g. "n SMOD m" equals "((n - 1) % m) + 1"
	 * A cascade of multiple SMOD computations is simpified:
	 * "(n SMOD m) SMOD o" equals "(((n - 1) % m) % o) + 1"
	 *
	 * The Range format uses 16 octets of data in SYSTEM INFORMATION.
	 * When used in dedicated messages, the length can be less.
	 * In this case the ranges are decoded for all frequencies that
	 * fit in the block of given length.
	 */

	/* tabula rasa */
	for (i = 0; i < 1024; i++)
		f[i].mask &= ~frqt;

	/* 00..XXX. */
	if ((cd[0] & 0xc0 & mask) == 0x00) {
		/* Bit map 0 format */
		if (len < 16)
			return -EINVAL;
		for (i = 1; i <= 124; i++)
			if ((cd[15 - ((i-1) >> 3)] & (1 << ((i-1) & 7))))
				f[i].mask |= frqt;

		return 0;
	}

	/* 10..0XX. */
	if ((cd[0] & 0xc8 & mask) == 0x80) {
		/* Range 1024 format */
		uint16_t w[17]; /* 1..16 */
		struct gsm48_range_1024 *r = (struct gsm48_range_1024 *)cd;

		if (len < 2)
			return -EINVAL;
		memset(w, 0, sizeof(w));
		if (r->f0)
			f[0].mask |= frqt;
		w[1] = (r->w1_hi << 8) | r->w1_lo;
		if (len >= 4)
			w[2] = (r->w2_hi << 1) | r->w2_lo;
		if (len >= 5)
			w[3] = (r->w3_hi << 2) | r->w3_lo;
		if (len >= 6)
			w[4] = (r->w4_hi << 2) | r->w4_lo;
		if (len >= 7)
			w[5] = (r->w5_hi << 2) | r->w5_lo;
		if (len >= 8)
			w[6] = (r->w6_hi << 2) | r->w6_lo;
		if (len >= 9)
			w[7] = (r->w7_hi << 2) | r->w7_lo;
		if (len >= 10)
			w[8] = (r->w8_hi << 1) | r->w8_lo;
		if (len >= 10)
			w[9] = r->w9;
		if (len >= 11)
			w[10] = r->w10;
		if (len >= 12)
			w[11] = (r->w11_hi << 6) | r->w11_lo;
		if (len >= 13)
			w[12] = (r->w12_hi << 5) | r->w12_lo;
		if (len >= 14)
			w[13] = (r->w13_hi << 4) | r->w13_lo;
		if (len >= 15)
			w[14] = (r->w14_hi << 3) | r->w14_lo;
		if (len >= 16)
			w[15] = (r->w15_hi << 2) | r->w15_lo;
		if (len >= 16)
			w[16] = r->w16;
		if (w[1])
			f[w[1]].mask |= frqt;
		if (w[2])
			f[smod(w[1] - 512 + w[2], 1023)].mask |= frqt;
		if (w[3])
			f[smod(w[1]       + w[3], 1023)].mask |= frqt;
		if (w[4])
			f[smod(w[1] - 512 + smod(w[2] - 256 + w[4], 511), 1023)].mask |= frqt;
		if (w[5])
			f[smod(w[1]       + smod(w[3] - 256 + w[5], 511), 1023)].mask |= frqt;
		if (w[6])
			f[smod(w[1] - 512 + smod(w[2]       + w[6], 511), 1023)].mask |= frqt;
		if (w[7])
			f[smod(w[1]       + smod(w[3]       + w[7], 511), 1023)].mask |= frqt;
		if (w[8])
			f[smod(w[1] - 512 + smod(w[2] - 256 + smod(w[4] - 128 + w[8] , 255), 511), 1023)].mask |= frqt;
		if (w[9])
			f[smod(w[1]       + smod(w[3] - 256 + smod(w[5] - 128 + w[9] , 255), 511), 1023)].mask |= frqt;
		if (w[10])
			f[smod(w[1] - 512 + smod(w[2]       + smod(w[6] - 128 + w[10], 255), 511), 1023)].mask |= frqt;
		if (w[11])
			f[smod(w[1]       + smod(w[3]       + smod(w[7] - 128 + w[11], 255), 511), 1023)].mask |= frqt;
		if (w[12])
			f[smod(w[1] - 512 + smod(w[2] - 256 + smod(w[4]       + w[12], 255), 511), 1023)].mask |= frqt;
		if (w[13])
			f[smod(w[1]       + smod(w[3] - 256 + smod(w[5]       + w[13], 255), 511), 1023)].mask |= frqt;
		if (w[14])
			f[smod(w[1] - 512 + smod(w[2]       + smod(w[6]       + w[14], 255), 511), 1023)].mask |= frqt;
		if (w[15])
			f[smod(w[1]       + smod(w[3]       + smod(w[7]       + w[15], 255), 511), 1023)].mask |= frqt;
		if (w[16])
			f[smod(w[1] - 512 + smod(w[2] - 256 + smod(w[4] - 128 + smod(w[8] - 64 + w[16], 127), 255), 511), 1023)].mask |= frqt;

		return 0;
	}
	/* 10..100. */
	if ((cd[0] & 0xce & mask) == 0x88) {
		/* Range 512 format */
		uint16_t w[18]; /* 1..17 */
		struct gsm48_range_512 *r = (struct gsm48_range_512 *)cd;

		if (len < 4)
			return -EINVAL;
		memset(w, 0, sizeof(w));
		w[0] = (r->orig_arfcn_hi << 9) | (r->orig_arfcn_mid << 1) | r->orig_arfcn_lo;
		w[1] = (r->w1_hi << 2) | r->w1_lo;
		if (len >= 5)
			w[2] = (r->w2_hi << 2) | r->w2_lo;
		if (len >= 6)
			w[3] = (r->w3_hi << 2) | r->w3_lo;
		if (len >= 7)
			w[4] = (r->w4_hi << 1) | r->w4_lo;
		if (len >= 7)
			w[5] = r->w5;
		if (len >= 8)
			w[6] = r->w6;
		if (len >= 9)
			w[7] = (r->w7_hi << 6) | r->w7_lo;
		if (len >= 10)
			w[8] = (r->w8_hi << 4) | r->w8_lo;
		if (len >= 11)
			w[9] = (r->w9_hi << 2) | r->w9_lo;
		if (len >= 11)
			w[10] = r->w10;
		if (len >= 12)
			w[11] = r->w11;
		if (len >= 13)
			w[12] = (r->w12_hi << 4) | r->w12_lo;
		if (len >= 14)
			w[13] = (r->w13_hi << 2) | r->w13_lo;
		if (len >= 14)
			w[14] = r->w14;
		if (len >= 15)
			w[15] = r->w15;
		if (len >= 16)
			w[16] = (r->w16_hi << 3) | r->w16_lo;
		if (len >= 16)
			w[17] = r->w17;
		f[w[0]].mask |= frqt;
		if (w[1])
			f[(w[0] + w[1]) % 1024].mask |= frqt;
		if (w[2])
			f[(w[0] + smod(w[1] - 256 + w[2], 511)) % 1024].mask |= frqt;
		if (w[3])
			f[(w[0] + smod(w[1]       + w[3], 511)) % 1024].mask |= frqt;
		if (w[4])
			f[(w[0] + smod(w[1] - 256 + smod(w[2] - 128 + w[4], 255), 511)) % 1024].mask |= frqt;
		if (w[5])
			f[(w[0] + smod(w[1]       + smod(w[3] - 128 + w[5], 255), 511)) % 1024].mask |= frqt;
		if (w[6])
			f[(w[0] + smod(w[1] - 256 + smod(w[2]       + w[6], 255), 511)) % 1024].mask |= frqt;
		if (w[7])
			f[(w[0] + smod(w[1]       + smod(w[3]       + w[7], 255), 511)) % 1024].mask |= frqt;
		if (w[8])
			f[(w[0] + smod(w[1] - 256 + smod(w[2] - 128 + smod(w[4] - 64 + w[8] , 127), 255), 511)) % 1024].mask |= frqt;
		if (w[9])
			f[(w[0] + smod(w[1]       + smod(w[3] - 128 + smod(w[5] - 64 + w[9] , 127), 255), 511)) % 1024].mask |= frqt;
		if (w[10])
			f[(w[0] + smod(w[1] - 256 + smod(w[2]       + smod(w[6] - 64 + w[10], 127), 255), 511)) % 1024].mask |= frqt;
		if (w[11])
			f[(w[0] + smod(w[1]       + smod(w[3]       + smod(w[7] - 64 + w[11], 127), 255), 511)) % 1024].mask |= frqt;
		if (w[12])
			f[(w[0] + smod(w[1] - 256 + smod(w[2] - 128 + smod(w[4]      + w[12], 127), 255), 511)) % 1024].mask |= frqt;
		if (w[13])
			f[(w[0] + smod(w[1]       + smod(w[3] - 128 + smod(w[5]      + w[13], 127), 255), 511)) % 1024].mask |= frqt;
		if (w[14])
			f[(w[0] + smod(w[1] - 256 + smod(w[2]       + smod(w[6]      + w[14], 127), 255), 511)) % 1024].mask |= frqt;
		if (w[15])
			f[(w[0] + smod(w[1]       + smod(w[3]       + smod(w[7]      + w[15], 127), 255), 511)) % 1024].mask |= frqt;
		if (w[16])
			f[(w[0] + smod(w[1] - 256 + smod(w[2] - 128 + smod(w[4] - 64 + smod(w[8] - 32 + w[16], 63), 127), 255), 511)) % 1024].mask |= frqt;
		if (w[17])
			f[(w[0] + smod(w[1]       + smod(w[3] - 128 + smod(w[5] - 64 + smod(w[9] - 32 + w[17], 63), 127), 255), 511)) % 1024].mask |= frqt;

		return 0;
	}
	/* 10..101. */
	if ((cd[0] & 0xce & mask) == 0x8a) {
		/* Range 256 format */
		uint16_t w[22]; /* 1..21 */
		struct gsm48_range_256 *r = (struct gsm48_range_256 *)cd;

		if (len < 4)
			return -EINVAL;
		memset(w, 0, sizeof(w));
		w[0] = (r->orig_arfcn_hi << 9) | (r->orig_arfcn_mid << 1) | r->orig_arfcn_lo;
		w[1] = (r->w1_hi << 1) | r->w1_lo;
		if (len >= 4)
			w[2] = r->w2;
		if (len >= 5)
			w[3] = r->w3;
		if (len >= 6)
			w[4] = (r->w4_hi << 5) | r->w4_lo;
		if (len >= 7)
			w[5] = (r->w5_hi << 3) | r->w5_lo;
		if (len >= 8)
			w[6] = (r->w6_hi << 1) | r->w6_lo;
		if (len >= 8)
			w[7] = r->w7;
		if (len >= 9)
			w[8] = (r->w8_hi << 4) | r->w8_lo;
		if (len >= 10)
			w[9] = (r->w9_hi << 1) | r->w9_lo;
		if (len >= 10)
			w[10] = r->w10;
		if (len >= 11)
			w[11] = (r->w11_hi << 3) | r->w11_lo;
		if (len >= 11)
			w[12] = r->w12;
		if (len >= 12)
			w[13] = r->w13;
		if (len >= 13)
			w[14] = (r->w14_hi << 2) | r->w14_lo;
		if (len >= 13)
			w[15] = r->w15;
		if (len >= 14)
			w[16] = (r->w16_hi << 3) | r->w16_lo;
		if (len >= 14)
			w[17] = r->w17;
		if (len >= 15)
			w[18] = (r->w18_hi << 3) | r->w18_lo;
		if (len >= 15)
			w[19] = r->w19;
		if (len >= 16)
			w[20] = (r->w20_hi << 3) | r->w20_lo;
		if (len >= 16)
			w[21] = r->w21;
		f[w[0]].mask |= frqt;
		if (w[1])
			f[(w[0] + w[1]) % 1024].mask |= frqt;
		if (w[2])
			f[(w[0] + smod(w[1] - 128 + w[2], 255)) % 1024].mask |= frqt;
		if (w[3])
			f[(w[0] + smod(w[1]       + w[3], 255)) % 1024].mask |= frqt;
		if (w[4])
			f[(w[0] + smod(w[1] - 128 + smod(w[2] - 64 + w[4], 127), 255)) % 1024].mask |= frqt;
		if (w[5])
			f[(w[0] + smod(w[1]       + smod(w[3] - 64 + w[5], 127), 255)) % 1024].mask |= frqt;
		if (w[6])
			f[(w[0] + smod(w[1] - 128 + smod(w[2]      + w[6], 127), 255)) % 1024].mask |= frqt;
		if (w[7])
			f[(w[0] + smod(w[1]       + smod(w[3]      + w[7], 127), 255)) % 1024].mask |= frqt;
		if (w[8])
			f[(w[0] + smod(w[1] - 128 + smod(w[2] - 64 + smod(w[4] - 32 + w[8] , 63), 127), 255)) % 1024].mask |= frqt;
		if (w[9])
			f[(w[0] + smod(w[1]       + smod(w[3] - 64 + smod(w[5] - 32 + w[9] , 63), 127), 255)) % 1024].mask |= frqt;
		if (w[10])
			f[(w[0] + smod(w[1] - 128 + smod(w[2]      + smod(w[6] - 32 + w[10], 63), 127), 255)) % 1024].mask |= frqt;
		if (w[11])
			f[(w[0] + smod(w[1]       + smod(w[3]      + smod(w[7] - 32 + w[11], 63), 127), 255)) % 1024].mask |= frqt;
		if (w[12])
			f[(w[0] + smod(w[1] - 128 + smod(w[2] - 64 + smod(w[4]      + w[12], 63), 127), 255)) % 1024].mask |= frqt;
		if (w[13])
			f[(w[0] + smod(w[1]       + smod(w[3] - 64 + smod(w[5]      + w[13], 63), 127), 255)) % 1024].mask |= frqt;
		if (w[14])
			f[(w[0] + smod(w[1] - 128 + smod(w[2]      + smod(w[6]      + w[14], 63), 127), 255)) % 1024].mask |= frqt;
		if (w[15])
			f[(w[0] + smod(w[1]       + smod(w[3]      + smod(w[7]      + w[15], 63), 127), 255)) % 1024].mask |= frqt;
		if (w[16])
			f[(w[0] + smod(w[1] - 128 + smod(w[2] - 64 + smod(w[4] - 32 + smod(w[8]  - 16 + w[16], 31), 63), 127), 255)) % 1024].mask |= frqt;
		if (w[17])
			f[(w[0] + smod(w[1]       + smod(w[3] - 64 + smod(w[5] - 32 + smod(w[9]  - 16 + w[17], 31), 63), 127), 255)) % 1024].mask |= frqt;
		if (w[18])
			f[(w[0] + smod(w[1] - 128 + smod(w[2]      + smod(w[6] - 32 + smod(w[10] - 16 + w[18], 31), 63), 127), 255)) % 1024].mask |= frqt;
		if (w[19])
			f[(w[0] + smod(w[1]       + smod(w[3]      + smod(w[7] - 32 + smod(w[11] - 16 + w[19], 31), 63), 127), 255)) % 1024].mask |= frqt;
		if (w[20])
			f[(w[0] + smod(w[1] - 128 + smod(w[2] - 64 + smod(w[4]      + smod(w[12] - 16 + w[20], 31), 63), 127), 255)) % 1024].mask |= frqt;
		if (w[21])
			f[(w[0] + smod(w[1]       + smod(w[3] - 64 + smod(w[5]      + smod(w[13] - 16 + w[21], 31), 63), 127), 255)) % 1024].mask |= frqt;

		return 0;
	}
	/* 10..110. */
	if ((cd[0] & 0xce & mask) == 0x8c) {
		/* Range 128 format */
		uint16_t w[29]; /* 1..28 */
		struct gsm48_range_128 *r = (struct gsm48_range_128 *)cd;

		if (len < 3)
			return -EINVAL;
		memset(w, 0, sizeof(w));
		w[0] = (r->orig_arfcn_hi << 9) | (r->orig_arfcn_mid << 1) | r->orig_arfcn_lo;
		w[1] = r->w1;
		if (len >= 4)
			w[2] = r->w2;
		if (len >= 5)
			w[3] = (r->w3_hi << 4) | r->w3_lo;
		if (len >= 6)
			w[4] = (r->w4_hi << 1) | r->w4_lo;
		if (len >= 6)
			w[5] = r->w5;
		if (len >= 7)
			w[6] = (r->w6_hi << 3) | r->w6_lo;
		if (len >= 7)
			w[7] = r->w7;
		if (len >= 8)
			w[8] = r->w8;
		if (len >= 8)
			w[9] = r->w9;
		if (len >= 9)
			w[10] = r->w10;
		if (len >= 9)
			w[11] = r->w11;
		if (len >= 10)
			w[12] = r->w12;
		if (len >= 10)
			w[13] = r->w13;
		if (len >= 11)
			w[14] = r->w14;
		if (len >= 11)
			w[15] = r->w15;
		if (len >= 12)
			w[16] = r->w16;
		if (len >= 12)
			w[17] = r->w17;
		if (len >= 13)
			w[18] = (r->w18_hi << 1) | r->w18_lo;
		if (len >= 13)
			w[19] = r->w19;
		if (len >= 13)
			w[20] = r->w20;
		if (len >= 14)
			w[21] = (r->w21_hi << 2) | r->w21_lo;
		if (len >= 14)
			w[22] = r->w22;
		if (len >= 14)
			w[23] = r->w23;
		if (len >= 15)
			w[24] = r->w24;
		if (len >= 15)
			w[25] = r->w25;
		if (len >= 16)
			w[26] = (r->w26_hi << 1) | r->w26_lo;
		if (len >= 16)
			w[27] = r->w27;
		if (len >= 16)
			w[28] = r->w28;
		f[w[0]].mask |= frqt;
		if (w[1])
			f[(w[0] + w[1]) % 1024].mask |= frqt;
		if (w[2])
			f[(w[0] + smod(w[1] - 64 + w[2], 127)) % 1024].mask |= frqt;
		if (w[3])
			f[(w[0] + smod(w[1]      + w[3], 127)) % 1024].mask |= frqt;
		if (w[4])
			f[(w[0] + smod(w[1] - 64 + smod(w[2] - 32 + w[4], 63), 127)) % 1024].mask |= frqt;
		if (w[5])
			f[(w[0] + smod(w[1]      + smod(w[3] - 32 + w[5], 63), 127)) % 1024].mask |= frqt;
		if (w[6])
			f[(w[0] + smod(w[1] - 64 + smod(w[2]      + w[6], 63), 127)) % 1024].mask |= frqt;
		if (w[7])
			f[(w[0] + smod(w[1]      + smod(w[3]      + w[7], 63), 127)) % 1024].mask |= frqt;
		if (w[8])
			f[(w[0] + smod(w[1] - 64 + smod(w[2] - 32 + smod(w[4] - 16 + w[8] , 31), 63), 127)) % 1024].mask |= frqt;
		if (w[9])
			f[(w[0] + smod(w[1]      + smod(w[3] - 32 + smod(w[5] - 16 + w[9] , 31), 63), 127)) % 1024].mask |= frqt;
		if (w[10])
			f[(w[0] + smod(w[1] - 64 + smod(w[2]      + smod(w[6] - 16 + w[10], 31), 63), 127)) % 1024].mask |= frqt;
		if (w[11])
			f[(w[0] + smod(w[1]      + smod(w[3]      + smod(w[7] - 16 + w[11], 31), 63), 127)) % 1024].mask |= frqt;
		if (w[12])
			f[(w[0] + smod(w[1] - 64 + smod(w[2] - 32 + smod(w[4]      + w[12], 31), 63), 127)) % 1024].mask |= frqt;
		if (w[13])
			f[(w[0] + smod(w[1]      + smod(w[3] - 32 + smod(w[5]      + w[13], 31), 63), 127)) % 1024].mask |= frqt;
		if (w[14])
			f[(w[0] + smod(w[1] - 64 + smod(w[2]      + smod(w[6]      + w[14], 31), 63), 127)) % 1024].mask |= frqt;
		if (w[15])
			f[(w[0] + smod(w[1]      + smod(w[3]      + smod(w[7]      + w[15], 31), 63), 127)) % 1024].mask |= frqt;
		if (w[16])
			f[(w[0] + smod(w[1] - 64 + smod(w[2] - 32 + smod(w[4] - 16 + smod(w[8]  - 8 + w[16], 15), 31), 63), 127)) % 1024].mask |= frqt;
		if (w[17])
			f[(w[0] + smod(w[1]      + smod(w[3] - 32 + smod(w[5] - 16 + smod(w[9]  - 8 + w[17], 15), 31), 63), 127)) % 1024].mask |= frqt;
		if (w[18])
			f[(w[0] + smod(w[1] - 64 + smod(w[2]      + smod(w[6] - 16 + smod(w[10] - 8 + w[18], 15), 31), 63), 127)) % 1024].mask |= frqt;
		if (w[19])
			f[(w[0] + smod(w[1]      + smod(w[3]      + smod(w[7] - 16 + smod(w[11] - 8 + w[19], 15), 31), 63), 127)) % 1024].mask |= frqt;
		if (w[20])
			f[(w[0] + smod(w[1] - 64 + smod(w[2] - 32 + smod(w[4]      + smod(w[12] - 8 + w[20], 15), 31), 63), 127)) % 1024].mask |= frqt;
		if (w[21])
			f[(w[0] + smod(w[1]      + smod(w[3] - 32 + smod(w[5]      + smod(w[13] - 8 + w[21], 15), 31), 63), 127)) % 1024].mask |= frqt;
		if (w[22])
			f[(w[0] + smod(w[1] - 64 + smod(w[2]      + smod(w[6]      + smod(w[14] - 8 + w[22], 15), 31), 63), 127)) % 1024].mask |= frqt;
		if (w[23])
			f[(w[0] + smod(w[1]      + smod(w[3]      + smod(w[7]      + smod(w[15] - 8 + w[23], 15), 31), 63), 127)) % 1024].mask |= frqt;
		if (w[24])
			f[(w[0] + smod(w[1] - 64 + smod(w[2] - 32 + smod(w[4] - 16 + smod(w[8]      + w[24], 15), 31), 63), 127)) % 1024].mask |= frqt;
		if (w[25])
			f[(w[0] + smod(w[1]      + smod(w[3] - 32 + smod(w[5] - 16 + smod(w[9]      + w[25], 15), 31), 63), 127)) % 1024].mask |= frqt;
		if (w[26])
			f[(w[0] + smod(w[1] - 64 + smod(w[2]      + smod(w[6] - 16 + smod(w[10]     + w[26], 15), 31), 63), 127)) % 1024].mask |= frqt;
		if (w[27])
			f[(w[0] + smod(w[1]      + smod(w[3]      + smod(w[7] - 16 + smod(w[11]     + w[27], 15), 31), 63), 127)) % 1024].mask |= frqt;
		if (w[28])
			f[(w[0] + smod(w[1] - 64 + smod(w[2] - 32 + smod(w[4]      + smod(w[12]     + w[28], 15), 31), 63), 127)) % 1024].mask |= frqt;

		return 0;
	}
	/* 10..111. */
	if ((cd[0] & 0xce & mask) == 0x8e) {
		/* Variable bitmap format (can be any length >= 3) */
		uint16_t orig = 0;
		struct gsm48_var_bit *r = (struct gsm48_var_bit *)cd;

		if (len < 3)
			return -EINVAL;
		orig = (r->orig_arfcn_hi << 9) | (r->orig_arfcn_mid << 1) | r->orig_arfcn_lo;
		f[orig].mask |= frqt;
		for (i = 1; 2 + (i >> 3) < len; i++)
			if ((cd[2 + (i >> 3)] & (0x80 >> (i & 7))))
				f[(orig + i) % 1024].mask |= frqt;

		return 0;
	}

	return 0;
}
/*! @} */
