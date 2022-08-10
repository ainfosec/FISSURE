/*! \file gsm48_ie.h */

#pragma once

#include <stdint.h>
#include <string.h>
#include <errno.h>

/* #include <osmocom/core/msgb.h> */
/* #include <osmocom/gsm/tlv.h> */
/* #include <osmocom/gsm/mncc.h> */
#include <osmocom/gsm/protocol/gsm_04_08.h>

/* decode a 'called/calling/connect party BCD number' as in 10.5.4.7 */
//int gsm48_decode_bcd_number(char *output, int output_len,
//			    const uint8_t *bcd_lv, int h_len);

///* convert a ASCII phone number to 'called/calling/connect party BCD number' */
//int gsm48_encode_bcd_number(uint8_t *bcd_lv, uint8_t max_len,
//			    int h_len, const char *input);
///* decode 'bearer capability' */
//int gsm48_decode_bearer_cap(struct gsm_mncc_bearer_cap *bcap,
//			     const uint8_t *lv);
///* encode 'bearer capability' */
//int gsm48_encode_bearer_cap(struct msgb *msg, int lv_only,
//			     const struct gsm_mncc_bearer_cap *bcap);
///* decode 'call control cap' */
//int gsm48_decode_cccap(struct gsm_mncc_cccap *ccap, const uint8_t *lv);
///* encode 'call control cap' */
//int gsm48_encode_cccap(struct msgb *msg,
//			const struct gsm_mncc_cccap *ccap);
///* decode 'called party BCD number' */
//int gsm48_decode_called(struct gsm_mncc_number *called,
//			 const uint8_t *lv);
///* encode 'called party BCD number' */
//int gsm48_encode_called(struct msgb *msg,
//			 const struct gsm_mncc_number *called);
///* decode callerid of various IEs */
//int gsm48_decode_callerid(struct gsm_mncc_number *callerid,
//			 const uint8_t *lv);
///* encode callerid of various IEs */
//int gsm48_encode_callerid(struct msgb *msg, int ie, int max_len,
//			   const struct gsm_mncc_number *callerid);
///* decode 'cause' */
//int gsm48_decode_cause(struct gsm_mncc_cause *cause,
//			const uint8_t *lv);
///* encode 'cause' */
//int gsm48_encode_cause(struct msgb *msg, int lv_only,
//			const struct gsm_mncc_cause *cause);
///* decode 'calling number' */
//int gsm48_decode_calling(struct gsm_mncc_number *calling,
//			 const uint8_t *lv);
///* encode 'calling number' */
//int gsm48_encode_calling(struct msgb *msg, 
//			  const struct gsm_mncc_number *calling);
///* decode 'connected number' */
//int gsm48_decode_connected(struct gsm_mncc_number *connected,
//			 const uint8_t *lv);
///* encode 'connected number' */
//int gsm48_encode_connected(struct msgb *msg,
//			    const struct gsm_mncc_number *connected);
///* decode 'redirecting number' */
//int gsm48_decode_redirecting(struct gsm_mncc_number *redirecting,
//			 const uint8_t *lv);
///* encode 'redirecting number' */
//int gsm48_encode_redirecting(struct msgb *msg,
//			      const struct gsm_mncc_number *redirecting);
///* decode 'facility' */
//int gsm48_decode_facility(struct gsm_mncc_facility *facility,
//			   const uint8_t *lv);
///* encode 'facility' */
//int gsm48_encode_facility(struct msgb *msg, int lv_only,
//			   const struct gsm_mncc_facility *facility);
///* decode 'notify' */
//int gsm48_decode_notify(int *notify, const uint8_t *v);
///* encode 'notify' */
//int gsm48_encode_notify(struct msgb *msg, int notify);
///* decode 'signal' */
//int gsm48_decode_signal(int *signal, const uint8_t *v);
///* encode 'signal' */
//int gsm48_encode_signal(struct msgb *msg, int signal);
///* decode 'keypad' */
//int gsm48_decode_keypad(int *keypad, const uint8_t *lv);
///* encode 'keypad' */
//int gsm48_encode_keypad(struct msgb *msg, int keypad);
///* decode 'progress' */
//int gsm48_decode_progress(struct gsm_mncc_progress *progress,
//			   const uint8_t *lv);
///* encode 'progress' */
//int gsm48_encode_progress(struct msgb *msg, int lv_only,
//			   const struct gsm_mncc_progress *p);
///* decode 'user-user' */
//int gsm48_decode_useruser(struct gsm_mncc_useruser *uu,
//			   const uint8_t *lv);
///* encode 'useruser' */
//int gsm48_encode_useruser(struct msgb *msg, int lv_only,
//			   const struct gsm_mncc_useruser *uu);
///* decode 'ss version' */
//int gsm48_decode_ssversion(struct gsm_mncc_ssversion *ssv,
//			    const uint8_t *lv);
///* encode 'ss version' */
//int gsm48_encode_ssversion(struct msgb *msg,
//			   const struct gsm_mncc_ssversion *ssv);
///* decode 'more data' does not require a function, because it has no value */
///* encode 'more data' */
//int gsm48_encode_more(struct msgb *msg);

/* structure of one frequency */
struct gsm_sysinfo_freq {
	/* if the frequency included in the sysinfo */
	uint8_t	mask;
};

/* decode "Cell Channel Description" (10.5.2.1b) and other frequency lists */
int gsm48_decode_freq_list(struct gsm_sysinfo_freq *f, uint8_t *cd,
			   uint8_t len, uint8_t mask, uint8_t frqt);
