/*! \file gsm_04_08.h
 * GSM TS 04.08  definitions. */

#pragma once

#include <stdint.h>
#include <stdbool.h>

#include <osmocom/core/utils.h>
#include <osmocom/core/endian.h>

struct gsm_lchan;

/* Chapter 10.5.1.5 */
struct gsm48_classmark1 {
	uint8_t pwr_lev:3,
		 a5_1:1,
		 es_ind:1,
		 rev_lev:2,
		 spare:1;
} __attribute__ ((packed));

/* Chapter 10.5.1.6 */
struct gsm48_classmark2 {
	uint8_t pwr_lev:3,
		 a5_1:1,
		 es_ind:1,
		 rev_lev:2,
		 spare:1;
	uint8_t	fc:1,
		 vgcs:1,
		 vbs:1,
		 sm_cap:1,
		 ss_scr:2,
		 ps_cap:1,
		 spare2:1;
	uint8_t	a5_2:1,
		 a5_3:1,
		 cmsp:1,
		 solsa:1,
		 spare3:1,
		 lcsva_cap:1,
		 spare4:1,
		 cm3:1;
} __attribute__ ((packed));

/* Chapter 10.5.2.1b.3 */
#if OSMO_IS_LITTLE_ENDIAN == 1
struct gsm48_range_1024 {
	uint8_t	w1_hi:2,
		 f0:1,
		 form_id:5;
	uint8_t	w1_lo;
	uint8_t	w2_hi;
	uint8_t	w3_hi:7,
		 w2_lo:1;
	uint8_t	w4_hi:6,
		 w3_lo:2;
	uint8_t	w5_hi:6,
		 w4_lo:2;
	uint8_t	w6_hi:6,
		 w5_lo:2;
	uint8_t	w7_hi:6,
		 w6_lo:2;
	uint8_t	w8_hi:6,
		 w7_lo:2;
	uint8_t	w9:7,
		 w8_lo:1;
	uint8_t	w11_hi:1,
		 w10:7;
	uint8_t	w12_hi:2,
		 w11_lo:6;
	uint8_t	w13_hi:3,
		 w12_lo:5;
	uint8_t	w14_hi:4,
		 w13_lo:4;
	uint8_t	w15_hi:5,
		 w14_lo:3;
	uint8_t	w16:6,
		 w15_lo:2;
} __attribute__ ((packed));
#else
struct gsm48_range_1024 {
	uint8_t	 form_id:5,
		f0:1,
		w1_hi:2;
	uint8_t	w1_lo;
	uint8_t	w2_hi;
	uint8_t	 w2_lo:1,
		w3_hi:7;
	uint8_t	 w3_lo:2,
		w4_hi:6;
	uint8_t	 w4_lo:2,
		w5_hi:6;
	uint8_t	 w5_lo:2,
		w6_hi:6;
	uint8_t	 w6_lo:2,
		w7_hi:6;
	uint8_t	 w7_lo:2,
		w8_hi:6;
	uint8_t	 w8_lo:1,
		w9:7;
	uint8_t	 w10:7,
		w11_hi:1;
	uint8_t	 w11_lo:6,
		w12_hi:2;
	uint8_t	 w12_lo:5,
		w13_hi:3;
	uint8_t	 w13_lo:4,
		w14_hi:4;
	uint8_t	 w14_lo:3,
		w15_hi:5;
	uint8_t	 w15_lo:2,
		w16:6;
} __attribute__ ((packed));
#endif

/* Chapter 10.5.2.1b.4 */
#if OSMO_IS_LITTLE_ENDIAN == 1
struct gsm48_range_512 {
	uint8_t	orig_arfcn_hi:1,
		 form_id:7;
	uint8_t	orig_arfcn_mid;
	uint8_t	w1_hi:7,
		 orig_arfcn_lo:1;
	uint8_t	w2_hi:6,
		 w1_lo:2;
	uint8_t	w3_hi:6,
		 w2_lo:2;
	uint8_t	w4_hi:6,
		 w3_lo:2;
	uint8_t	w5:7,
		 w4_lo:1;
	uint8_t	w7_hi:1,
		 w6:7;
	uint8_t	w8_hi:2,
		 w7_lo:6;
	uint8_t	w9_hi:4,
		 w8_lo:4;
	uint8_t	w10:6,
		 w9_lo:2;
	uint8_t	w12_hi:2,
		 w11:6;
	uint8_t	w13_hi:4,
		 w12_lo:4;
	uint8_t	w14:6,
		 w13_lo:2;
	uint8_t	w16_hi:2,
		 w15:6;
	uint8_t	w17:5,
		 w16_lo:3;
} __attribute__ ((packed));
#else
struct gsm48_range_512 {
	uint8_t	 form_id:7,
		orig_arfcn_hi:1;
	uint8_t	orig_arfcn_mid;
	uint8_t	 orig_arfcn_lo:1,
		w1_hi:7;
	uint8_t	 w1_lo:2,
		w2_hi:6;
	uint8_t	 w2_lo:2,
		w3_hi:6;
	uint8_t	 w3_lo:2,
		w4_hi:6;
	uint8_t	 w4_lo:1,
		w5:7;
	uint8_t	 w6:7,
		w7_hi:1;
	uint8_t	 w7_lo:6,
		w8_hi:2;
	uint8_t	 w8_lo:4,
		w9_hi:4;
	uint8_t	 w9_lo:2,
		w10:6;
	uint8_t	 w11:6,
		w12_hi:2;
	uint8_t	 w12_lo:4,
		w13_hi:4;
	uint8_t	 w13_lo:2,
		w14:6;
	uint8_t	 w15:6,
		w16_hi:2;
	uint8_t	 w16_lo:3,
		w17:5;
} __attribute__ ((packed));
#endif

/* Chapter 10.5.2.1b.5 */
#if OSMO_IS_LITTLE_ENDIAN == 1
struct gsm48_range_256 {
	uint8_t	orig_arfcn_hi:1,
		 form_id:7;
	uint8_t	orig_arfcn_mid;
	uint8_t	w1_hi:7,
		 orig_arfcn_lo:1;
	uint8_t	w2:7,
		 w1_lo:1;
	uint8_t	w4_hi:1,
		 w3:7;
	uint8_t	w5_hi:3,
		 w4_lo:5;
	uint8_t	w6_hi:5,
		 w5_lo:3;
	uint8_t	w8_hi:1,
		 w7:6,
		 w6_lo:1;
	uint8_t	w9_hi:4,
		 w8_lo:4;
	uint8_t	w11_hi:2,
		 w10:5,
		 w9_lo:1;
	uint8_t	w12:5,
		 w11_lo:3;
	uint8_t	w14_hi:3,
		 w13:5;
	uint8_t	w16_hi:1,
		 w15:5,
		 w14_lo:2;
	uint8_t	w18_hi:1,
		 w17:4,
		 w16_lo:3;
	uint8_t	w20_hi:1,
		 w19:4,
		 w18_lo:3;
	uint8_t	spare:1,
		 w21:4,
		 w20_lo:3;
} __attribute__ ((packed));
#else
struct gsm48_range_256 {
	uint8_t	 form_id:7,
		orig_arfcn_hi:1;
	uint8_t	orig_arfcn_mid;
	uint8_t	 orig_arfcn_lo:1,
		w1_hi:7;
	uint8_t	 w1_lo:1,
		w2:7;
	uint8_t	 w3:7,
		w4_hi:1;
	uint8_t	 w4_lo:5,
		w5_hi:3;
	uint8_t	 w5_lo:3,
		w6_hi:5;
	uint8_t	 w6_lo:1,
		 w7:6,
		w8_hi:1;
	uint8_t	 w8_lo:4,
		w9_hi:4;
	uint8_t	 w9_lo:1,
		 w10:5,
		w11_hi:2;
	uint8_t	 w11_lo:3,
		w12:5;
	uint8_t	 w13:5,
		w14_hi:3;
	uint8_t	 w14_lo:2,
		 w15:5,
		w16_hi:1;
	uint8_t	 w16_lo:3,
		 w17:4,
		w18_hi:1;
	uint8_t	 w18_lo:3,
		 w19:4,
		w20_hi:1;
	uint8_t	 w20_lo:3,
		 w21:4,
		spare:1;
} __attribute__ ((packed));
#endif

/* Chapter 10.5.2.1b.6 */
#if OSMO_IS_LITTLE_ENDIAN == 1
struct gsm48_range_128 {
	uint8_t	orig_arfcn_hi:1,
		 form_id:7;
	uint8_t	orig_arfcn_mid;
	uint8_t	w1:7,
		 orig_arfcn_lo:1;
	uint8_t	w3_hi:2,
		 w2:6;
	uint8_t	w4_hi:4,
		 w3_lo:4;
	uint8_t	w6_hi:2,
		 w5:5,
		 w4_lo:1;
	uint8_t	w7:5,
		 w6_lo:3;
	uint8_t	w9:4,
		 w8:4;
	uint8_t	w11:4,
		 w10:4;
	uint8_t	w13:4,
		 w12:4;
	uint8_t	w15:4,
		 w14:4;
	uint8_t	w18_hi:2,
		 w17:3,
		 w16:3;
	uint8_t	w21_hi:1,
		 w20:3,
		 w19:3,
		 w18_lo:1;
	uint8_t	w23:3,
		 w22:3,
		 w21_lo:2;
	uint8_t	w26_hi:2,
		 w25:3,
		 w24:3;
	uint8_t	spare:1,
		 w28:3,
		 w27:3,
		 w26_lo:1;
} __attribute__ ((packed));
#else
struct gsm48_range_128 {
	uint8_t	 form_id:7,
		orig_arfcn_hi:1;
	uint8_t	orig_arfcn_mid;
	uint8_t	 orig_arfcn_lo:1,
		w1:7;
	uint8_t	 w2:6,
		w3_hi:2;
	uint8_t	 w3_lo:4,
		w4_hi:4;
	uint8_t	 w4_lo:1,
		 w5:5,
		w6_hi:2;
	uint8_t	 w6_lo:3,
		w7:5;
	uint8_t	 w8:4,
		w9:4;
	uint8_t	 w10:4,
		w11:4;
	uint8_t	 w12:4,
		w13:4;
	uint8_t	 w14:4,
		w15:4;
	uint8_t	 w16:3,
		 w17:3,
		w18_hi:2;
	uint8_t	 w18_lo:1,
		 w19:3,
		 w20:3,
		w21_hi:1;
	uint8_t	 w21_lo:2,
		 w22:3,
		w23:3;
	uint8_t	 w24:3,
		 w25:3,
		w26_hi:2;
	uint8_t	 w26_lo:1,
		 w27:3,
		 w28:3,
		spare:1;
} __attribute__ ((packed));
#endif

/* Chapter 10.5.2.1b.7 */
struct gsm48_var_bit {
	uint8_t	orig_arfcn_hi:1,
		 form_id:7;
	uint8_t	orig_arfcn_mid;
	uint8_t	rrfcn1_7:7,
		 orig_arfcn_lo:1;
	uint8_t rrfcn8_111[13];
} __attribute__ ((packed));

/* Chapter 10.5.2.5 */
struct gsm48_chan_desc {
	uint8_t chan_nr;
	union {
		struct {
			uint8_t maio_high:4,
				 h:1,
				 tsc:3;
			uint8_t hsn:6,
				 maio_low:2;
		} __attribute__ ((packed)) h1;
		struct {
			uint8_t arfcn_high:2,
				 spare:2,
				 h:1,
				 tsc:3;
			uint8_t arfcn_low;
		} __attribute__ ((packed)) h0;
	} __attribute__ ((packed));
} __attribute__ ((packed));

/* Chapter 10.5.2.20 */
struct gsm48_meas_res {
	uint8_t	rxlev_full:6,
		 dtx_used:1,
		 ba_used:1;
	uint8_t	rxlev_sub:6,
		 meas_valid:1,
		 spare:1;
	uint8_t	no_nc_n_hi:1,
		 rxqual_sub:3,
		 rxqual_full:3,
		 spare2:1;
	uint8_t	rxlev_nc1:6,
		 no_nc_n_lo:2;
	uint8_t	bsic_nc1_hi:3,
		 bcch_f_nc1:5;
	uint8_t	rxlev_nc2_hi:5,
		 bsic_nc1_lo:3;
	uint8_t	bsic_nc2_hi:2,
		 bcch_f_nc2:5,
		 rxlev_nc2_lo:1;
	uint8_t	rxlev_nc3_hi:4,
		 bsic_nc2_lo:4;
	uint8_t	bsic_nc3_hi:1,
		 bcch_f_nc3:5,
		 rxlev_nc3_lo:2;
	uint8_t	rxlev_nc4_hi:3,
		 bsic_nc3_lo:5;
	uint8_t	bcch_f_nc4:5,
		 rxlev_nc4_lo:3;
	uint8_t	rxlev_nc5_hi:2,
		 bsic_nc4:6;
	uint8_t	bcch_f_nc5_hi:4,
		 rxlev_nc5_lo:4;
	uint8_t	rxlev_nc6_hi:1,
		 bsic_nc5:6,
		 bcch_f_nc5_lo:1;
	uint8_t	bcch_f_nc6_hi:3,
		 rxlev_nc6_lo:5;
	uint8_t	bsic_nc6:6,
		 bcch_f_nc6_lo:2;
} __attribute__ ((packed));

/* Chapter 10.5.2.21aa */
struct gsm48_multi_rate_conf {
	uint8_t smod : 2,
		 spare: 1,
		 icmi : 1,
		 nscb : 1,
		 ver : 3;
	uint8_t m4_75 : 1,
		 m5_15 : 1,
		 m5_90 : 1,
		 m6_70 : 1,
		 m7_40 : 1,
		 m7_95 : 1,
		 m10_2 : 1,
		 m12_2 : 1;
} __attribute__((packed));

/* Chapter 10.5.2.28(a) */
struct gsm48_power_cmd {
	uint8_t power_level:5,
		 spare:2,
		 atc:1;
} __attribute__((packed));

/* Chapter 10.5.2.29 */
struct gsm48_rach_control {
	uint8_t re :1,
		 cell_bar :1,
		 tx_integer :4,
		 max_trans :2;
	uint8_t t2; /* ACC 8-15 barred flags */
	uint8_t t3; /* ACC 0-7 barred flags */
} __attribute__ ((packed));


/* Chapter 10.5.2.30 */
struct gsm48_req_ref {
	uint8_t ra;
	uint8_t t3_high:3,
		 t1:5;
	uint8_t t2:5,
		 t3_low:3;
} __attribute__ ((packed));

/* Chapter 10.5.2.38 */
struct gsm48_start_time {
	uint8_t t3_high:3,
		 t1:5;
	uint8_t t2:5,
		 t3_low:3;
} __attribute__ ((packed));

/* Chapter 10.5.2.39 */
struct gsm48_sync_ind {
	uint8_t si:2,
		 rot:1,
		 nci:1,
		 sync_ie:4;
} __attribute__((packed));

/*
 * Chapter 9.1.5/9.1.6
 *
 * For 9.1.6 the chan_desc has the meaning of 10.5.2.5a
 */
struct gsm48_chan_mode_modify {
	struct gsm48_chan_desc chan_desc;
	uint8_t mode;
} __attribute__ ((packed));

enum gsm48_chan_mode {
	GSM48_CMODE_SIGN	= 0x00,
	GSM48_CMODE_SPEECH_V1	= 0x01,
	GSM48_CMODE_SPEECH_EFR	= 0x21,
	GSM48_CMODE_SPEECH_AMR	= 0x41,
	GSM48_CMODE_DATA_14k5	= 0x0f,
	GSM48_CMODE_DATA_12k0	= 0x03,
	GSM48_CMODE_DATA_6k0	= 0x0b,
	GSM48_CMODE_DATA_3k6	= 0x13,
};

extern const struct value_string gsm48_chan_mode_names[];

/* Chapter 9.1.2 */
struct gsm48_ass_cmd {
	/* Semantic is from 10.5.2.5a */
	struct gsm48_chan_desc chan_desc;
	uint8_t power_command;
	uint8_t data[0];
} __attribute__((packed));

/* Chapter 9.1.13 */
struct gsm48_frq_redef {
	/* Semantic is from 10.5.2.5a */
	struct gsm48_chan_desc chan_desc;
	uint8_t mob_alloc_len;
	uint8_t mob_alloc[0];
} __attribute__((packed));

/* Chapter 9.1.13b GPRS suspension request */
struct gsm48_gprs_susp_req {
	uint32_t tlli;
	uint8_t ra_id[6];
	uint8_t cause;
	uint8_t options[0];
} __attribute__ ((packed));

/* Chapter 10.5.2.2 */
struct gsm48_cell_desc {
	uint8_t bcc:3,
		 ncc:3,
		 arfcn_hi:2;
	uint8_t arfcn_lo;
} __attribute__((packed));

/* Chapter 9.1.15 */
struct gsm48_ho_cmd {
	struct gsm48_cell_desc cell_desc;
	struct gsm48_chan_desc chan_desc;
	uint8_t ho_ref;
	uint8_t power_command;
	uint8_t data[0];
} __attribute__((packed));

/* Chapter 9.1.18 */
struct gsm48_imm_ass {
	uint8_t l2_plen;
	uint8_t proto_discr;
	uint8_t msg_type;
	uint8_t page_mode;
	struct gsm48_chan_desc chan_desc;
	struct gsm48_req_ref req_ref;
	uint8_t timing_advance;
	uint8_t mob_alloc_len;
	uint8_t mob_alloc[0];
} __attribute__ ((packed));

/* Chapter 9.1.25 */
struct gsm48_pag_resp {
	uint8_t spare:4,
		 key_seq:4;
	uint32_t classmark2;
	uint8_t mi_len;
	uint8_t mi[0];
} __attribute__ ((packed));

/* Chapter 10.5.1.3 */
struct gsm48_loc_area_id {
	uint8_t digits[3];	/* BCD! */
	uint16_t lac;
} __attribute__ ((packed));

/* Section 9.2.2 */
struct gsm48_auth_req {
	uint8_t key_seq:4,
	         spare:4;
	uint8_t rand[16];
} __attribute__ ((packed));

/* Section 9.2.3 */
struct gsm48_auth_resp {
	uint8_t sres[4];
} __attribute__ ((packed));

/* Section 9.2.15 */
struct gsm48_loc_upd_req {
	uint8_t type:4,
		 key_seq:4;
	struct gsm48_loc_area_id lai;
	struct gsm48_classmark1 classmark1;
	uint8_t mi_len;
	uint8_t mi[0];
} __attribute__ ((packed));

/* Section 10.1 */
struct gsm48_hdr {
	uint8_t proto_discr;
	uint8_t msg_type;
	uint8_t data[0];
} __attribute__ ((packed));

/* Section 9.1.3x System information Type header */
struct gsm48_system_information_type_header {
	uint8_t l2_plen;
	uint8_t rr_protocol_discriminator :4,
		skip_indicator:4; 
	uint8_t system_information;
} __attribute__ ((packed));

/* Section 10.5.2.4 Cell Selection Parameters */
struct gsm48_cell_sel_par {
	uint8_t ms_txpwr_max_ccch:5,	/* GSM 05.08 MS-TXPWR-MAX-CCCH */
		 cell_resel_hyst:3;	/* GSM 05.08 CELL-RESELECT-HYSTERESIS */
	uint8_t rxlev_acc_min:6,	/* GSM 05.08 RXLEV-ACCESS-MIN */
		 neci:1,
		 acs:1;
} __attribute__ ((packed));

/* 3GPP TS 44.018 Section 10.5.2.11 Control Channel Description */
struct gsm48_control_channel_descr {
	uint8_t ccch_conf :3,
		bs_ag_blks_res :3,
		att :1,
		mscr :1;
	uint8_t bs_pa_mfrms : 3,
		spare_1 :2,
		cbq3 :2,
		spare_2 :1;
	uint8_t t3212;
} __attribute__ ((packed));

enum gsm48_dtx_mode {
	GSM48_DTX_MAY_BE_USED,
	GSM48_DTX_SHALL_BE_USED,
	GSM48_DTX_SHALL_NOT_BE_USED
};

/* Cell Options for SI6, SACCH (10.5.2.3a.2) or SI3, BCCH (Table 10.5.2.3.1),
   3GPP TS 44.018 */
struct gsm48_cell_options {
	uint8_t radio_link_timeout:4,
		 dtx:2,
		 pwrc:1,
	/* either DN-IND or top bit of DTX IND */
		 d:1;
} __attribute__ ((packed));

/* Section 9.2.9 CM service request */
struct gsm48_service_request {
	uint8_t cm_service_type : 4,
		 cipher_key_seq  : 4;
	/* length + 3 bytes */
	uint32_t classmark;
	uint8_t mi_len;
	uint8_t mi[0];
	/* optional priority level */
} __attribute__ ((packed));

/* Section 9.1.31 System information Type 1 */
struct gsm48_system_information_type_1 {
	struct gsm48_system_information_type_header header;
	uint8_t cell_channel_description[16];
	struct gsm48_rach_control rach_control;
	uint8_t rest_octets[0]; /* NCH position on the CCCH */
} __attribute__ ((packed));

/* Section 9.1.32 System information Type 2 */
struct gsm48_system_information_type_2 {
	struct gsm48_system_information_type_header header;
	uint8_t bcch_frequency_list[16];
	uint8_t ncc_permitted;
	struct gsm48_rach_control rach_control;
} __attribute__ ((packed));

/* Section 9.1.33 System information Type 2bis */
struct gsm48_system_information_type_2bis {
	struct gsm48_system_information_type_header header;
	uint8_t bcch_frequency_list[16];
	struct gsm48_rach_control rach_control;
	uint8_t rest_octets[0];
} __attribute__ ((packed));

/* Section 9.1.34 System information Type 2ter */
struct gsm48_system_information_type_2ter {
	struct gsm48_system_information_type_header header;
	uint8_t ext_bcch_frequency_list[16];
	uint8_t rest_octets[0];
} __attribute__ ((packed));

/* Section 9.1.34a System information Type 2quater */
struct gsm48_system_information_type_2quater {
	struct gsm48_system_information_type_header header;
	uint8_t rest_octets[0];
} __attribute__ ((packed));

/* Section 9.1.35 System information Type 3 */
struct gsm48_system_information_type_3 {
	struct gsm48_system_information_type_header header;
	uint16_t cell_identity;
	struct gsm48_loc_area_id lai;
	struct gsm48_control_channel_descr control_channel_desc;
	struct gsm48_cell_options cell_options;
	struct gsm48_cell_sel_par cell_sel_par;
	struct gsm48_rach_control rach_control;
	uint8_t rest_octets[0];
} __attribute__ ((packed));

/* Section 9.1.36 System information Type 4 */
struct gsm48_system_information_type_4 {
	struct gsm48_system_information_type_header header;
	struct gsm48_loc_area_id lai;
	struct gsm48_cell_sel_par cell_sel_par;
	struct gsm48_rach_control rach_control;
	/*	optional CBCH conditional CBCH... followed by
		mandantory SI 4 Reset Octets
	 */
	uint8_t data[0];
} __attribute__ ((packed));

/* Section 9.1.37 System information Type 5 */
struct gsm48_system_information_type_5 {
	uint8_t rr_protocol_discriminator :4,
		skip_indicator:4; 
	uint8_t system_information;
	uint8_t bcch_frequency_list[16];
} __attribute__ ((packed));

/* Section 9.1.38 System information Type 5bis */
struct gsm48_system_information_type_5bis {
        uint8_t rr_protocol_discriminator :4,
		 skip_indicator:4;
	uint8_t system_information;
	uint8_t bcch_frequency_list[16];
} __attribute__ ((packed));

/* Section 9.1.39 System information Type 5ter */
struct gsm48_system_information_type_5ter {
        uint8_t rr_protocol_discriminator :4,
		 skip_indicator:4;
	uint8_t system_information;
	uint8_t bcch_frequency_list[16];
} __attribute__ ((packed));

/* Section 9.1.40 System information Type 6 */
struct gsm48_system_information_type_6 {
	uint8_t rr_protocol_discriminator :4,
		skip_indicator:4; 
	uint8_t system_information;
	uint16_t cell_identity;
	struct gsm48_loc_area_id lai;
	struct gsm48_cell_options cell_options;
	uint8_t ncc_permitted;
	uint8_t rest_octets[0];
} __attribute__ ((packed));

/* Section 9.1.43a System Information type 13 */
struct gsm48_system_information_type_13 {
	struct gsm48_system_information_type_header header;
	uint8_t rest_octets[0];
} __attribute__ ((packed));

/* Section 9.2.12 IMSI Detach Indication */
struct gsm48_imsi_detach_ind {
	struct gsm48_classmark1 classmark1;
	uint8_t mi_len;
	uint8_t mi[0];
} __attribute__ ((packed));

/* Section 9.1.1 */
struct gsm48_add_ass {
	/* Semantic is from 10.5.2.5 */
	struct gsm48_chan_desc chan_desc;
	uint8_t data[0];
} __attribute__((packed));

/* Section 9.1.3 */
struct gsm48_ass_cpl {
	uint8_t rr_cause;
} __attribute__((packed));

/* Section 9.1.4 */
struct gsm48_ass_fail {
	uint8_t rr_cause;
} __attribute__((packed));

/* Section 9.1.3 */
struct gsm48_ho_cpl {
	uint8_t rr_cause;
	uint8_t data[0];
} __attribute__((packed));

/* Section 9.1.4 */
struct gsm48_ho_fail {
	uint8_t rr_cause;
} __attribute__((packed));

/* Section 9.1.7 */
struct gsm48_chan_rel {
	uint8_t rr_cause;
	uint8_t data[0];
} __attribute__((packed));

/* Section 9.1.9 */
struct gsm48_cip_mode_cmd {
	uint8_t sc:1,
		 alg_id:3,
		 cr:1,
		 spare:3;
} __attribute__((packed));

/* Section 9.1.11 */
struct gsm48_cm_change {
	uint8_t cm2_len;
	struct gsm48_classmark2 cm2;
	uint8_t data[0];
} __attribute__((packed));

/* Section 9.1.19 */
struct gsm48_imm_ass_ext {
	uint8_t l2_plen;
	uint8_t proto_discr;
	uint8_t msg_type;
	uint8_t page_mode;
	struct gsm48_chan_desc chan_desc1;
	struct gsm48_req_ref req_ref1;
	uint8_t timing_advance1;
	struct gsm48_chan_desc chan_desc2;
	struct gsm48_req_ref req_ref2;
	uint8_t timing_advance2;
	uint8_t mob_alloc_len;
	uint8_t mob_alloc[0];
} __attribute__ ((packed));

/* Section 9.1.20 */
struct gsm48_imm_ass_rej {
	uint8_t l2_plen;
	uint8_t proto_discr;
	uint8_t msg_type;
	uint8_t page_mode;
	struct gsm48_req_ref req_ref1;
	uint8_t wait_ind1;
	struct gsm48_req_ref req_ref2;
	uint8_t wait_ind2;
	struct gsm48_req_ref req_ref3;
	uint8_t wait_ind3;
	struct gsm48_req_ref req_ref4;
	uint8_t wait_ind4;
	uint8_t rest[0];
} __attribute__ ((packed));

/* Section 9.1.22 */
struct gsm48_paging1 {
	uint8_t l2_plen;
	uint8_t proto_discr;
	uint8_t msg_type;
	uint8_t pag_mode:2,
		 spare:2,
		 cneed1:2,
		 cneed2:2;
	uint8_t data[0];
} __attribute__((packed));

/* Section 9.1.23 */
struct gsm48_paging2 {
	uint8_t l2_plen;
	uint8_t proto_discr;
	uint8_t msg_type;
	uint8_t pag_mode:2,
		 spare:2,
		 cneed1:2,
		 cneed2:2;
	uint32_t tmsi1;
	uint32_t tmsi2;
	uint8_t data[0];
} __attribute__((packed));

/* Section 9.1.24 */
struct gsm48_paging3 {
	uint8_t l2_plen;
	uint8_t proto_discr;
	uint8_t msg_type;
	uint8_t pag_mode:2,
		 spare:2,
		 cneed1:2,
		 cneed2:2;
	uint32_t tmsi1;
	uint32_t tmsi2;
	uint32_t tmsi3;
	uint32_t tmsi4;
	uint8_t cneed3:2,
		 cneed4:2,
		 spare2:4;
	uint8_t rest[0];
} __attribute__((packed));

/* Section 9.1.25 */
struct gsm48_pag_rsp {
	uint8_t key_seq:3,
		 spare:5;
	uint8_t cm2_len;
	struct gsm48_classmark2 cm2;
	uint8_t data[0];
} __attribute__((packed));

/* Section 9.1.29 */
struct gsm48_rr_status {
	uint8_t rr_cause;
} __attribute__((packed));

/* Section 10.2 + GSM 04.07 12.2.3.1.1 + 3GPP TS 24.007 11.2.3.1.1 */
#define GSM48_PDISC_GROUP_CC	0x00
#define GSM48_PDISC_BCAST_CC	0x01
#define GSM48_PDISC_PDSS1	0x02	/* 04.07 only */
#define GSM48_PDISC_CC		0x03
#define GSM48_PDISC_PDSS2	0x04	/* 04.07 only */
#define GSM48_PDISC_GTTP	0x04	/* 24.007 only */
#define GSM48_PDISC_MM		0x05
#define GSM48_PDISC_RR		0x06
#define GSM48_PDISC_MM_GPRS	0x08
#define GSM48_PDISC_SMS		0x09
#define GSM48_PDISC_SM_GPRS	0x0a
#define GSM48_PDISC_NC_SS	0x0b
#define GSM48_PDISC_LOC		0x0c
#define GSM48_PDISC_EXTEND	0x0e
#define GSM48_PDISC_TEST	0x0f	/* as per 11.10, 04.14 */
#define GSM48_PDISC_MASK	0x0f
#define GSM48_PDISC_USSD	0x11

extern const struct value_string gsm48_pdisc_names[];
/*static inline const char *gsm48_pdisc_name(uint8_t val)
{ return get_value_string(gsm48_pdisc_names, val); }*/

bool gsm48_hdr_gmm_cipherable(const struct gsm48_hdr *hdr);

static inline uint8_t gsm48_hdr_pdisc(const struct gsm48_hdr *hdr)
{
	/*
	 * 3GPP TS 24.007 version 12.0.0 Release 12,
	 * 11.2.3.1.1 Protocol discriminator
	 */
	uint8_t pdisc = hdr->proto_discr & GSM48_PDISC_MASK;
	if (pdisc == GSM48_PDISC_EXTEND)
		return hdr->proto_discr;
	return pdisc;
}

static inline uint8_t gsm48_hdr_trans_id(const struct gsm48_hdr *hdr)
{
	/*
	 * 3GPP TS 24.007 version 12.0.0 Release 12,
	 * 11.2.3.1.3 Transaction identifier
	 */
	return (hdr->proto_discr & 0xf0) >> 4;
}

#define GSM48_TA_INVALID 220

/*! Check if TA is valid according to 3GPP TS 44.018 § 10.5.2.40
 *  \param[in] ta Timing Advance value
 *  \returns true if ta is valid, false otherwise
 *  Note: Rules for GSM400 band are ignored as it's not implemented in practice.
 */
static inline bool gsm48_ta_is_valid(uint8_t ta)
{
	return (ta < 64);
}

static inline uint8_t gsm48_hdr_trans_id_flip_ti(const struct gsm48_hdr *hdr)
{
	return gsm48_hdr_trans_id(hdr) ^ 0x08;
}

static inline uint8_t gsm48_hdr_trans_id_no_ti(const struct gsm48_hdr *hdr)
{
	return gsm48_hdr_trans_id(hdr) & 0x07;
}

static inline uint8_t gsm48_hdr_msg_type_r98(const struct gsm48_hdr *hdr)
{
	/*
	 * 3GPP TS 24.007 version 12.0.0 Release 12,
	 * 11.2.3.2.1 Message type octet (when accessing Release 98 and older
	 * networks only)
	 */
	switch (gsm48_hdr_pdisc(hdr)) {
	case GSM48_PDISC_MM:
	case GSM48_PDISC_CC:
	case GSM48_PDISC_NC_SS:
	case GSM48_PDISC_GROUP_CC:
	case GSM48_PDISC_BCAST_CC:
	case GSM48_PDISC_LOC:
		return hdr->msg_type & 0x3f;
	default:
		return hdr->msg_type;
	}
}

static inline uint8_t gsm48_hdr_msg_type_r99(const struct gsm48_hdr *hdr)
{
	/*
	 * 3GPP TS 24.007 version 12.0.0 Release 12,
	 * 11.2.3.2.2 Message type octet (when accessing Release 99 and newer
	 * networks)
	 */
	switch (gsm48_hdr_pdisc(hdr)) {
	case GSM48_PDISC_MM:
	case GSM48_PDISC_CC:
	case GSM48_PDISC_NC_SS:
		return hdr->msg_type & 0x3f;
	case GSM48_PDISC_GROUP_CC:
	case GSM48_PDISC_BCAST_CC:
	case GSM48_PDISC_LOC:
		return hdr->msg_type & 0x3f;
	default:
		return hdr->msg_type;
	}
}

void gsm48_set_dtx(struct gsm48_cell_options *op, enum gsm48_dtx_mode full,
		   enum gsm48_dtx_mode half, bool is_bcch);

#define gsm48_hdr_msg_type gsm48_hdr_msg_type_r99

/* Section 10.4 */
#define GSM48_MT_RR_INIT_REQ		0x3c
#define GSM48_MT_RR_ADD_ASS		0x3b
#define GSM48_MT_RR_IMM_ASS		0x3f
#define GSM48_MT_RR_IMM_ASS_EXT		0x39
#define GSM48_MT_RR_IMM_ASS_REJ		0x3a
#define GSM48_MT_RR_DTM_ASS_FAIL	0x48
#define GSM48_MT_RR_DTM_REJECT		0x49
#define GSM48_MT_RR_DTM_REQUEST		0x4A
#define GSM48_MT_RR_PACKET_ASS		0x4B

#define GSM48_MT_RR_CIPH_M_CMD		0x35
#define GSM48_MT_RR_CIPH_M_COMPL	0x32

#define GSM48_MT_RR_CFG_CHG_CMD		0x30
#define GSM48_MT_RR_CFG_CHG_ACK		0x31
#define GSM48_MT_RR_CFG_CHG_REJ		0x33

#define GSM48_MT_RR_ASS_CMD		0x2e
#define GSM48_MT_RR_ASS_COMPL		0x29
#define GSM48_MT_RR_ASS_FAIL		0x2f
#define GSM48_MT_RR_HANDO_CMD		0x2b
#define GSM48_MT_RR_HANDO_COMPL		0x2c
#define GSM48_MT_RR_HANDO_FAIL		0x28
#define GSM48_MT_RR_HANDO_INFO		0x2d
#define GSM48_MT_RR_HANDO_INFO		0x2d
#define GSM48_MT_RR_DTM_ASS_CMD		0x4c

#define GSM48_MT_RR_CELL_CHG_ORDER	0x08
#define GSM48_MT_RR_PDCH_ASS_CMD	0x23

#define GSM48_MT_RR_CHAN_REL		0x0d
#define GSM48_MT_RR_PART_REL		0x0a
#define GSM48_MT_RR_PART_REL_COMP	0x0f

#define GSM48_MT_RR_PAG_REQ_1		0x21
#define GSM48_MT_RR_PAG_REQ_2		0x22
#define GSM48_MT_RR_PAG_REQ_3		0x24
#define GSM48_MT_RR_PAG_RESP		0x27
#define GSM48_MT_RR_NOTIF_NCH		0x20
#define GSM48_MT_RR_NOTIF_FACCH		0x25 /* (Reserved) */
#define GSM48_MT_RR_NOTIF_RESP		0x26
#define GSM48_MT_RR_PACKET_NOTIF	0x4e
#define GSM48_MT_RR_UTRAN_CLSM_CHG	0x60
#define GSM48_MT_RR_CDMA2K_CLSM_CHG	0x62
#define GSM48_MT_RR_IS_TO_UTRAN_HANDO	0x63
#define GSM48_MT_RR_IS_TO_CDMA2K_HANDO	0x64

#define GSM48_MT_RR_SYSINFO_8		0x18
#define GSM48_MT_RR_SYSINFO_1		0x19
#define GSM48_MT_RR_SYSINFO_2		0x1a
#define GSM48_MT_RR_SYSINFO_3		0x1b
#define GSM48_MT_RR_SYSINFO_4		0x1c
#define GSM48_MT_RR_SYSINFO_5		0x1d
#define GSM48_MT_RR_SYSINFO_6		0x1e
#define GSM48_MT_RR_SYSINFO_7		0x1f

#define GSM48_MT_RR_SYSINFO_2bis	0x02
#define GSM48_MT_RR_SYSINFO_2ter	0x03
#define GSM48_MT_RR_SYSINFO_2quater	0x07
#define GSM48_MT_RR_SYSINFO_5bis	0x05
#define GSM48_MT_RR_SYSINFO_5ter	0x06
#define GSM48_MT_RR_SYSINFO_9		0x04
#define GSM48_MT_RR_SYSINFO_13		0x00

#define GSM48_MT_RR_SYSINFO_16		0x3d
#define GSM48_MT_RR_SYSINFO_17		0x3e

#define GSM48_MT_RR_SYSINFO_18		0x40
#define GSM48_MT_RR_SYSINFO_19		0x41
#define GSM48_MT_RR_SYSINFO_20		0x42

#define GSM48_MT_RR_CHAN_MODE_MODIF	0x10
#define GSM48_MT_RR_STATUS		0x12
#define GSM48_MT_RR_CHAN_MODE_MODIF_ACK	0x17
#define GSM48_MT_RR_FREQ_REDEF		0x14
#define GSM48_MT_RR_MEAS_REP		0x15
#define GSM48_MT_RR_CLSM_CHG		0x16
#define GSM48_MT_RR_CLSM_ENQ		0x13
#define GSM48_MT_RR_EXT_MEAS_REP	0x36
#define GSM48_MT_RR_EXT_MEAS_REP_ORD	0x37
#define GSM48_MT_RR_GPRS_SUSP_REQ	0x34
#define GSM48_MT_RR_DTM_INFO		0x4d

#define GSM48_MT_RR_VGCS_UPL_GRANT	0x09
#define GSM48_MT_RR_UPLINK_RELEASE	0x0e
#define GSM48_MT_RR_UPLINK_FREE		0x0c
#define GSM48_MT_RR_UPLINK_BUSY		0x2a
#define GSM48_MT_RR_TALKER_IND		0x11

#define GSM48_MT_RR_APP_INFO		0x38

/* Table 10.2/3GPP TS 04.08 */
#define GSM48_MT_MM_IMSI_DETACH_IND	0x01
#define GSM48_MT_MM_LOC_UPD_ACCEPT	0x02
#define GSM48_MT_MM_LOC_UPD_REJECT	0x04
#define GSM48_MT_MM_LOC_UPD_REQUEST	0x08

#define GSM48_MT_MM_AUTH_REJ		0x11
#define GSM48_MT_MM_AUTH_REQ		0x12
#define GSM48_MT_MM_AUTH_RESP		0x14
#define GSM48_MT_MM_AUTH_FAIL		0x1c
#define GSM48_MT_MM_ID_REQ		0x18
#define GSM48_MT_MM_ID_RESP		0x19
#define GSM48_MT_MM_TMSI_REALL_CMD	0x1a
#define GSM48_MT_MM_TMSI_REALL_COMPL	0x1b

#define GSM48_MT_MM_CM_SERV_ACC		0x21
#define GSM48_MT_MM_CM_SERV_REJ		0x22
#define GSM48_MT_MM_CM_SERV_ABORT	0x23
#define GSM48_MT_MM_CM_SERV_REQ		0x24
#define GSM48_MT_MM_CM_SERV_PROMPT	0x25
#define GSM48_MT_MM_CM_REEST_REQ	0x28
#define GSM48_MT_MM_ABORT		0x29

#define GSM48_MT_MM_NULL		0x30
#define GSM48_MT_MM_STATUS		0x31
#define GSM48_MT_MM_INFO		0x32

/* Table 10.3/3GPP TS 04.08 */
#define GSM48_MT_CC_ALERTING		0x01
#define GSM48_MT_CC_CALL_CONF		0x08
#define GSM48_MT_CC_CALL_PROC		0x02
#define GSM48_MT_CC_CONNECT		0x07
#define GSM48_MT_CC_CONNECT_ACK		0x0f
#define GSM48_MT_CC_EMERG_SETUP		0x0e
#define GSM48_MT_CC_PROGRESS		0x03
#define GSM48_MT_CC_ESTAB		0x04
#define GSM48_MT_CC_ESTAB_CONF		0x06
#define GSM48_MT_CC_RECALL		0x0b
#define GSM48_MT_CC_START_CC		0x09
#define GSM48_MT_CC_SETUP		0x05

#define GSM48_MT_CC_MODIFY		0x17
#define GSM48_MT_CC_MODIFY_COMPL	0x1f
#define GSM48_MT_CC_MODIFY_REJECT	0x13
#define GSM48_MT_CC_USER_INFO		0x10
#define GSM48_MT_CC_HOLD		0x18
#define GSM48_MT_CC_HOLD_ACK		0x19
#define GSM48_MT_CC_HOLD_REJ		0x1a
#define GSM48_MT_CC_RETR		0x1c
#define GSM48_MT_CC_RETR_ACK		0x1d
#define GSM48_MT_CC_RETR_REJ		0x1e

#define GSM48_MT_CC_DISCONNECT		0x25
#define GSM48_MT_CC_RELEASE		0x2d
#define GSM48_MT_CC_RELEASE_COMPL	0x2a

#define GSM48_MT_CC_CONG_CTRL		0x39
#define GSM48_MT_CC_NOTIFY		0x3e
#define GSM48_MT_CC_STATUS		0x3d
#define GSM48_MT_CC_STATUS_ENQ		0x34
#define GSM48_MT_CC_START_DTMF		0x35
#define GSM48_MT_CC_STOP_DTMF		0x31
#define GSM48_MT_CC_STOP_DTMF_ACK	0x32
#define GSM48_MT_CC_START_DTMF_ACK	0x36
#define GSM48_MT_CC_START_DTMF_REJ	0x37
#define GSM48_MT_CC_FACILITY		0x3a

extern const struct value_string gsm48_rr_msgtype_names[];
extern const struct value_string gsm48_mm_msgtype_names[];
extern const struct value_string gsm48_cc_msgtype_names[];
const char *gsm48_pdisc_msgtype_name(uint8_t pdisc, uint8_t msg_type);

/* FIXME: Table 10.4 / 10.4a (GPRS) */

/* Section 10.5.3.3 CM service type */
#define GSM48_CMSERV_MO_CALL_PACKET	1
#define GSM48_CMSERV_EMERGENCY		2
#define GSM48_CMSERV_SMS		4
#define GSM48_CMSERV_SUP_SERV		8
#define GSM48_CMSERV_VGCS		9
#define GSM48_CMSERV_VBS		10
#define GSM48_CMSERV_LOC_SERV		11

/* Section 10.5.2.26, Table 10.5.64 */
#define GSM48_PM_MASK		0x03
#define GSM48_PM_NORMAL		0x00
#define GSM48_PM_EXTENDED	0x01
#define GSM48_PM_REORG		0x02
#define GSM48_PM_SAME		0x03

/* Chapter 10.5.3.5 / Table 10.5.93 */
#define GSM48_LUPD_NORMAL	0x0
#define GSM48_LUPD_PERIODIC	0x1
#define GSM48_LUPD_IMSI_ATT	0x2
#define GSM48_LUPD_RESERVED	0x3

/* Table 10.5.4 */
#define GSM_MI_TYPE_MASK	0x07
#define GSM_MI_TYPE_NONE	0x00
#define GSM_MI_TYPE_IMSI	0x01
#define GSM_MI_TYPE_IMEI	0x02
#define GSM_MI_TYPE_IMEISV	0x03
#define GSM_MI_TYPE_TMSI	0x04
#define GSM_MI_ODD		0x08

#define GSM48_IE_MOBILE_ID	0x17	/* 10.5.1.4 */
#define GSM48_IE_NAME_LONG	0x43	/* 10.5.3.5a */
#define GSM48_IE_NAME_SHORT	0x45	/* 10.5.3.5a */
#define GSM48_IE_UTC		0x46	/* 10.5.3.8 */
#define GSM48_IE_NET_TIME_TZ	0x47	/* 10.5.3.9 */
#define GSM48_IE_LSA_IDENT	0x48	/* 10.5.3.11 */
#define GSM48_IE_NET_DST	0x49	/* 10.5.3.12 [24.008] */

#define GSM48_IE_BEARER_CAP	0x04	/* 10.5.4.5 */
#define GSM48_IE_CAUSE		0x08	/* 10.5.4.11 */
#define GSM48_IE_CC_CAP		0x15	/* 10.5.4.5a */
#define GSM48_IE_ALERT		0x19	/* 10.5.4.26 */
#define GSM48_IE_FACILITY	0x1c	/* 10.5.4.15 */
#define GSM48_IE_PROGR_IND	0x1e	/* 10.5.4.21 */
#define GSM48_IE_AUX_STATUS	0x24	/* 10.5.4.4 */
#define GSM48_IE_NOTIFY		0x27	/* 10.5.4.20 */
#define GSM48_IE_KPD_FACILITY	0x2c	/* 10.5.4.17 */
#define GSM48_IE_SIGNAL		0x34	/* 10.5.4.23 */
#define GSM48_IE_CONN_BCD	0x4c	/* 10.5.4.13 */
#define GSM48_IE_CONN_SUB	0x4d	/* 10.5.4.14 */
#define GSM48_IE_CALLING_BCD	0x5c	/* 10.5.4.9 */
#define GSM48_IE_CALLING_SUB	0x5d	/* 10.5.4.10 */
#define GSM48_IE_CALLED_BCD	0x5e	/* 10.5.4.7 */
#define GSM48_IE_CALLED_SUB	0x6d	/* 10.5.4.8 */
#define GSM48_IE_REDIR_BCD	0x74	/* 10.5.4.21a */
#define GSM48_IE_REDIR_SUB	0x75	/* 10.5.4.21b */
#define GSM48_IE_LOWL_COMPAT	0x7c	/* 10.5.4.18 */
#define GSM48_IE_HIGHL_COMPAT	0x7d	/* 10.5.4.16 */
#define GSM48_IE_USER_USER	0x7e	/* 10.5.4.25 */
#define GSM48_IE_SS_VERS	0x7f	/* 10.5.4.24 */
#define GSM48_IE_MORE_DATA	0xa0	/* 10.5.4.19 */
#define GSM48_IE_CLIR_SUPP	0xa1	/* 10.5.4.11a */
#define GSM48_IE_CLIR_INVOC	0xa2	/* 10.5.4.11b */
#define GSM48_IE_REV_C_SETUP	0xa3	/* 10.5.4.22a */
#define GSM48_IE_REPEAT_CIR	0xd1	/* 10.5.4.22 */
#define GSM48_IE_REPEAT_SEQ	0xd3	/* 10.5.4.22 */

/* Section 10.5.4.11 / Table 10.5.122 */
#define GSM48_CAUSE_CS_GSM	0x60

/* Section 9.1.2 / Table 9.3 */
/* RR elements */
#define GSM48_IE_VGCS_TARGET	0x01
//#define GSM48_IE_VGCS_T_MODE_I	0x01
#define GSM48_IE_FRQSHORT_AFTER	0x02
#define GSM48_IE_MUL_RATE_CFG	0x03	/* 10.5.2.21aa */
#define GSM48_IE_FREQ_L_AFTER	0x05
#define GSM48_IE_MSLOT_DESC	0x10
#define GSM48_IE_CHANMODE_2	0x11
#define GSM48_IE_FRQSHORT_BEFORE 0x12
//#define GSM48_IE_FRQSHORT_BEFOR 0x12
#define GSM48_IE_CHANMODE_3	0x13
#define GSM48_IE_CHANMODE_4	0x14
#define GSM48_IE_CHANMODE_5	0x15
#define GSM48_IE_CHANMODE_6	0x16
#define GSM48_IE_CHANMODE_7	0x17
#define GSM48_IE_CHANMODE_8	0x18
#define GSM48_IE_CHANDESC_2	0x64
#define GSM48_IE_MA_AFTER	0x72
#define GSM48_IE_START_TIME	0x7c
#define GSM48_IE_FREQ_L_BEFORE	0x19
//#define GSM48_IE_FRQLIST_BEFORE	0x19
#define GSM48_IE_CH_DESC_1_BEFORE	0x1c
//#define GSM48_IE_CHDES_1_BEFORE 0x1c
#define GSM48_IE_CH_DESC_2_BEFORE	0x1d
//#define GSM48_IE_CHDES_2_BEFORE	0x1d
#define GSM48_IE_F_CH_SEQ_BEFORE	0x1e
//#define GSM48_IE_FRQSEQ_BEFORE	0x1e
#define GSM48_IE_CLASSMARK3	0x20
#define GSM48_IE_MA_BEFORE	0x21
#define GSM48_IE_RR_PACKET_UL	0x22
#define GSM48_IE_RR_PACKET_DL	0x23
#define GSM48_IE_CELL_CH_DESC	0x62
#define GSM48_IE_CHANMODE_1	0x63
#define GSM48_IE_CHDES_2_AFTER	0x64
#define GSM48_IE_MODE_SEC_CH	0x66
#define GSM48_IE_F_CH_SEQ_AFTER	0x69
#define GSM48_IE_MA_AFTER	0x72
#define GSM48_IE_BA_RANGE	0x73
#define GSM48_IE_GROUP_CHDES	0x74
#define GSM48_IE_BA_LIST_PREF	0x75
#define GSM48_IE_MOB_OVSERV_DIF	0x77
#define GSM48_IE_REALTIME_DIFF	0x7b
#define GSM48_IE_START_TIME	0x7c
#define GSM48_IE_TIMING_ADVANCE	0x7d
#define GSM48_IE_GROUP_CIP_SEQ	0x80
#define GSM48_IE_CIP_MODE_SET	0x90
#define GSM48_IE_GPRS_RESUMPT	0xc0
#define GSM48_IE_SYNC_IND	0xd0
/* System Information 4 (types are equal IEs above) */
#define GSM48_IE_CBCH_CHAN_DESC	0x64
#define GSM48_IE_CBCH_MOB_AL	0x72

/* Additional MM elements */
#define GSM48_IE_LOCATION_AREA	0x13
#define GSM48_IE_AUTN		0x20
#define GSM48_IE_AUTH_RES_EXT	0x21
#define GSM48_IE_AUTS		0x22
#define GSM48_IE_PRIORITY_LEV	0x80
#define GSM48_IE_FOLLOW_ON_PROC	0xa1
#define GSM48_IE_CTS_PERMISSION	0xa2

/* Section 10.5.4.23 / Table 10.5.130 */
enum gsm48_signal_val {
	GSM48_SIGNAL_DIALTONE	= 0x00,
	GSM48_SIGNAL_RINGBACK	= 0x01,
	GSM48_SIGNAL_INTERCEPT	= 0x02,
	GSM48_SIGNAL_NET_CONG	= 0x03,
	GSM48_SIGNAL_BUSY	= 0x04,
	GSM48_SIGNAL_CONFIRM	= 0x05,
	GSM48_SIGNAL_ANSWER	= 0x06,
	GSM48_SIGNAL_CALL_WAIT	= 0x07,
	GSM48_SIGNAL_OFF_HOOK	= 0x08,
	GSM48_SIGNAL_OFF	= 0x3f,
	GSM48_SIGNAL_ALERT_OFF	= 0x4f,
};

enum gsm48_cause_loc {
	GSM48_CAUSE_LOC_USER		= 0x00,
	GSM48_CAUSE_LOC_PRN_S_LU	= 0x01,
	GSM48_CAUSE_LOC_PUN_S_LU	= 0x02,
	GSM48_CAUSE_LOC_TRANS_NET	= 0x03,
	GSM48_CAUSE_LOC_PUN_S_RU	= 0x04,
	GSM48_CAUSE_LOC_PRN_S_RU	= 0x05,
	/* not defined */
	GSM48_CAUSE_LOC_INN_NET		= 0x07,
	GSM48_CAUSE_LOC_NET_BEYOND	= 0x0a,
};

/* Section 10.5.2.31 RR Cause / Table 10.5.70 */
enum gsm48_rr_cause {
	GSM48_RR_CAUSE_NORMAL		= 0x00,
	GSM48_RR_CAUSE_ABNORMAL_UNSPEC	= 0x01,
	GSM48_RR_CAUSE_ABNORMAL_UNACCT	= 0x02,
	GSM48_RR_CAUSE_ABNORMAL_TIMER	= 0x03,
	GSM48_RR_CAUSE_ABNORMAL_NOACT	= 0x04,
	GSM48_RR_CAUSE_PREMPTIVE_REL	= 0x05,
	GSM48_RR_CAUSE_HNDOVER_IMP	= 0x08,
	GSM48_RR_CAUSE_CHAN_MODE_UNACCT	= 0x09,
	GSM48_RR_CAUSE_FREQ_NOT_IMPL	= 0x0a,
	GSM48_RR_CAUSE_CALL_CLEARED	= 0x41,
	GSM48_RR_CAUSE_SEMANT_INCORR	= 0x5f,
	GSM48_RR_CAUSE_INVALID_MAND_INF = 0x60,
	GSM48_RR_CAUSE_MSG_TYPE_N	= 0x61,
	GSM48_RR_CAUSE_MSG_TYPE_N_COMPAT= 0x62,
	GSM48_RR_CAUSE_COND_IE_ERROR	= 0x64,
	GSM48_RR_CAUSE_NO_CELL_ALLOC_A	= 0x65,
	GSM48_RR_CAUSE_PROT_ERROR_UNSPC = 0x6f,
};

/* Section 10.5.4.11 CC Cause / Table 10.5.123 */
enum gsm48_cc_cause {
	GSM48_CC_CAUSE_UNASSIGNED_NR	= 1,
	GSM48_CC_CAUSE_NO_ROUTE		= 3,
	GSM48_CC_CAUSE_CHAN_UNACCEPT	= 6,
	GSM48_CC_CAUSE_OP_DET_BARRING	= 8,
	GSM48_CC_CAUSE_NORM_CALL_CLEAR	= 16,
	GSM48_CC_CAUSE_USER_BUSY	= 17,
	GSM48_CC_CAUSE_USER_NOTRESPOND	= 18,
	GSM48_CC_CAUSE_USER_ALERTING_NA	= 19,
	GSM48_CC_CAUSE_CALL_REJECTED	= 21,
	GSM48_CC_CAUSE_NUMBER_CHANGED	= 22,
	GSM48_CC_CAUSE_PRE_EMPTION	= 25,
	GSM48_CC_CAUSE_NONSE_USER_CLR	= 26,
	GSM48_CC_CAUSE_DEST_OOO		= 27,
	GSM48_CC_CAUSE_INV_NR_FORMAT	= 28,
	GSM48_CC_CAUSE_FACILITY_REJ	= 29,
	GSM48_CC_CAUSE_RESP_STATUS_INQ	= 30,
	GSM48_CC_CAUSE_NORMAL_UNSPEC	= 31,
	GSM48_CC_CAUSE_NO_CIRCUIT_CHAN	= 34,
	GSM48_CC_CAUSE_NETWORK_OOO	= 38,
	GSM48_CC_CAUSE_TEMP_FAILURE	= 41,
	GSM48_CC_CAUSE_SWITCH_CONG	= 42,
	GSM48_CC_CAUSE_ACC_INF_DISCARD	= 43,
	GSM48_CC_CAUSE_REQ_CHAN_UNAVAIL	= 44,
	GSM48_CC_CAUSE_RESOURCE_UNAVAIL	= 47,
	GSM48_CC_CAUSE_QOS_UNAVAIL	= 49,
	GSM48_CC_CAUSE_REQ_FAC_NOT_SUBSC= 50,
	GSM48_CC_CAUSE_INC_BARRED_CUG	= 55,
	GSM48_CC_CAUSE_BEARER_CAP_UNAUTH= 57,
	GSM48_CC_CAUSE_BEARER_CA_UNAVAIL= 58,
	GSM48_CC_CAUSE_SERV_OPT_UNAVAIL	= 63,
	GSM48_CC_CAUSE_BEARERSERV_UNIMPL= 65,
	GSM48_CC_CAUSE_ACM_GE_ACM_MAX	= 68,
	GSM48_CC_CAUSE_REQ_FAC_NOTIMPL	= 69,
	GSM48_CC_CAUSE_RESTR_BCAP_AVAIL	= 70,
	GSM48_CC_CAUSE_SERV_OPT_UNIMPL	= 79,
	GSM48_CC_CAUSE_INVAL_TRANS_ID	= 81,
	GSM48_CC_CAUSE_USER_NOT_IN_CUG	= 87,
	GSM48_CC_CAUSE_INCOMPAT_DEST	= 88,
	GSM48_CC_CAUSE_INVAL_TRANS_NET	= 91,
	GSM48_CC_CAUSE_SEMANTIC_INCORR	= 95,
	GSM48_CC_CAUSE_INVAL_MAND_INF	= 96,
	GSM48_CC_CAUSE_MSGTYPE_NOTEXIST	= 97,
	GSM48_CC_CAUSE_MSGTYPE_INCOMPAT	= 98,
	GSM48_CC_CAUSE_IE_NOTEXIST	= 99,
	GSM48_CC_CAUSE_COND_IE_ERR	= 100,
	GSM48_CC_CAUSE_MSG_INCOMP_STATE	= 101,
	GSM48_CC_CAUSE_RECOVERY_TIMER	= 102,
	GSM48_CC_CAUSE_PROTO_ERR	= 111,
	GSM48_CC_CAUSE_INTERWORKING	= 127,
};

/* Annex G, GSM specific cause values for mobility management */
enum gsm48_reject_value {
	GSM48_REJECT_IMSI_UNKNOWN_IN_HLR	= 2,
	GSM48_REJECT_ILLEGAL_MS			= 3,
	GSM48_REJECT_IMSI_UNKNOWN_IN_VLR	= 4,
	GSM48_REJECT_IMEI_NOT_ACCEPTED		= 5,
	GSM48_REJECT_ILLEGAL_ME			= 6,
	GSM48_REJECT_PLMN_NOT_ALLOWED		= 11,
	GSM48_REJECT_LOC_NOT_ALLOWED		= 12,
	GSM48_REJECT_ROAMING_NOT_ALLOWED	= 13,
	GSM48_REJECT_NETWORK_FAILURE		= 17,
	GSM48_REJECT_SYNCH_FAILURE		= 21,
	GSM48_REJECT_CONGESTION			= 22,
	GSM48_REJECT_SRV_OPT_NOT_SUPPORTED	= 32,
	GSM48_REJECT_RQD_SRV_OPT_NOT_SUPPORTED	= 33,
	GSM48_REJECT_SRV_OPT_TMP_OUT_OF_ORDER	= 34,
	GSM48_REJECT_CALL_CAN_NOT_BE_IDENTIFIED	= 38,
	GSM48_REJECT_INCORRECT_MESSAGE		= 95,
	GSM48_REJECT_INVALID_MANDANTORY_INF	= 96,
	GSM48_REJECT_MSG_TYPE_NOT_IMPLEMENTED	= 97,
	GSM48_REJECT_MSG_TYPE_NOT_COMPATIBLE	= 98,
	GSM48_REJECT_INF_ELEME_NOT_IMPLEMENTED	= 99,
	GSM48_REJECT_CONDTIONAL_IE_ERROR	= 100,
	GSM48_REJECT_MSG_NOT_COMPATIBLE		= 101,
	GSM48_REJECT_PROTOCOL_ERROR		= 111,

	/* according to G.6 Additional cause codes for GMM */
	GSM48_REJECT_GPRS_NOT_ALLOWED		= 7,
	GSM48_REJECT_SERVICES_NOT_ALLOWED	= 8,
	GSM48_REJECT_MS_IDENTITY_NOT_DERVIVABLE = 9,
	GSM48_REJECT_IMPLICITLY_DETACHED	= 10,
	GSM48_REJECT_GPRS_NOT_ALLOWED_IN_PLMN	= 14,
	GSM48_REJECT_MSC_TMP_NOT_REACHABLE	= 16,
};

enum chreq_type {
	CHREQ_T_EMERG_CALL,
	CHREQ_T_CALL_REEST_TCH_F,
	CHREQ_T_CALL_REEST_TCH_H,
	CHREQ_T_CALL_REEST_TCH_H_DBL,
	CHREQ_T_SDCCH,
	CHREQ_T_TCH_F,
	CHREQ_T_VOICE_CALL_TCH_H,
	CHREQ_T_DATA_CALL_TCH_H,
	CHREQ_T_LOCATION_UPD,
	CHREQ_T_PAG_R_ANY_NECI0,
	CHREQ_T_PAG_R_ANY_NECI1,
	CHREQ_T_PAG_R_TCH_F,
	CHREQ_T_PAG_R_TCH_FH,
	CHREQ_T_LMU,
	CHREQ_T_RESERVED_SDCCH,
	CHREQ_T_RESERVED_IGNORE,
	CHREQ_T_PDCH_ONE_PHASE,
	CHREQ_T_PDCH_TWO_PHASE,
	_NUM_CHREQ_T,
};

/* Chapter 11.3 */
#define GSM48_T301	180, 0
#define GSM48_T303	30, 0
#define GSM48_T305	30, 0
#define GSM48_T306	30, 0
#define GSM48_T308	10, 0		/* no spec default */
#define GSM48_T310	30, 0		/* no spec default */
#define GSM48_T313	30, 0		/* no spec default */
#define GSM48_T323	30, 0
#define GSM48_T331	30, 0		/* no spec default */
#define GSM48_T333	30, 0		/* no spec default */
#define GSM48_T334	25, 0 /* min 15s */
#define GSM48_T338	30, 0		/* no spec default */
#define GSM48_T303_MS	30, 0
#define GSM48_T305_MS	30, 0
#define GSM48_T308_MS	30, 0
#define GSM48_T310_MS	30, 0
#define GSM48_T313_MS	30, 0
#define GSM48_T323_MS	30, 0
#define GSM48_T332_MS	30, 0
#define GSM48_T335_MS	30, 0

/* Chapter 5.1.2.2 */
#define	GSM_CSTATE_NULL			0
#define	GSM_CSTATE_INITIATED		1
#define	GSM_CSTATE_MM_CONNECTION_PEND	2 /* see 10.5.4.6 */
#define	GSM_CSTATE_MO_CALL_PROC		3
#define	GSM_CSTATE_CALL_DELIVERED	4
#define	GSM_CSTATE_CALL_PRESENT		6
#define	GSM_CSTATE_CALL_RECEIVED	7
#define	GSM_CSTATE_CONNECT_REQUEST	8
#define	GSM_CSTATE_MO_TERM_CALL_CONF	9
#define	GSM_CSTATE_ACTIVE		10
#define	GSM_CSTATE_DISCONNECT_REQ	12
#define	GSM_CSTATE_DISCONNECT_IND	12
#define	GSM_CSTATE_RELEASE_REQ		19
#define	GSM_CSTATE_MO_ORIG_MODIFY	26
#define	GSM_CSTATE_MO_TERM_MODIFY	27
#define	GSM_CSTATE_CONNECT_IND		28

#define SBIT(a) (1 << a)
#define ALL_STATES 0xffffffff

/* Table 10.5.3/3GPP TS 04.08: Location Area Identification information element */
#define GSM_LAC_RESERVED_DETACHED       0x0
#define GSM_LAC_RESERVED_ALL_BTS        0xfffe

/* GSM 04.08 Bearer Capability: Information Transfer Capability */
enum gsm48_bcap_itcap {
	GSM48_BCAP_ITCAP_SPEECH		= 0,
	GSM48_BCAP_ITCAP_UNR_DIG_INF	= 1,
	GSM48_BCAP_ITCAP_3k1_AUDIO	= 2,
	GSM48_BCAP_ITCAP_FAX_G3		= 3,
	GSM48_BCAP_ITCAP_OTHER		= 5,
	GSM48_BCAP_ITCAP_RESERVED	= 7,
};

/* GSM 04.08 Bearer Capability: Transfer Mode */
enum gsm48_bcap_tmod {
	GSM48_BCAP_TMOD_CIRCUIT		= 0,
	GSM48_BCAP_TMOD_PACKET		= 1,
};

/* GSM 04.08 Bearer Capability: Coding Standard */
enum gsm48_bcap_coding {
	GSM48_BCAP_CODING_GSM_STD	= 0,
};

/* GSM 04.08 Bearer Capability: Radio Channel Requirements */
enum gsm48_bcap_rrq {
	GSM48_BCAP_RRQ_FR_ONLY	= 1,
	GSM48_BCAP_RRQ_DUAL_HR	= 2,
	GSM48_BCAP_RRQ_DUAL_FR	= 3,
};

/* GSM 04.08 Bearer Capability: Rate Adaption */
enum gsm48_bcap_ra {
	GSM48_BCAP_RA_NONE	= 0,
	GSM48_BCAP_RA_V110_X30	= 1,
	GSM48_BCAP_RA_X31	= 2,
	GSM48_BCAP_RA_OTHER	= 3,
};

/* GSM 04.08 Bearer Capability: Signalling access protocol */
enum gsm48_bcap_sig_access {
	GSM48_BCAP_SA_I440_I450	= 1,
	GSM48_BCAP_SA_X21	= 2,
	GSM48_BCAP_SA_X28_DP_IN	= 3,
	GSM48_BCAP_SA_X28_DP_UN	= 4,
	GSM48_BCAP_SA_X28_NDP	= 5,
	GSM48_BCAP_SA_X32	= 6,
};

/* GSM 04.08 Bearer Capability: User Rate */
enum gsm48_bcap_user_rate {
	GSM48_BCAP_UR_300	= 1,
	GSM48_BCAP_UR_1200	= 2,
	GSM48_BCAP_UR_2400	= 3,
	GSM48_BCAP_UR_4800	= 4,
	GSM48_BCAP_UR_9600	= 5,
	GSM48_BCAP_UR_12000	= 6,
	GSM48_BCAP_UR_1200_75	= 7,
};

/* GSM 04.08 Bearer Capability: Parity */
enum gsm48_bcap_parity {
	GSM48_BCAP_PAR_ODD	= 0,
	GSM48_BCAP_PAR_EVEN	= 2,
	GSM48_BCAP_PAR_NONE	= 3,
	GSM48_BCAP_PAR_ZERO	= 4,
	GSM48_BCAP_PAR_ONE	= 5,
};

/* GSM 04.08 Bearer Capability: Intermediate Rate */
enum gsm48_bcap_interm_rate {
	GSM48_BCAP_IR_8k	= 2,
	GSM48_BCAP_IR_16k	= 3,
};

/* GSM 04.08 Bearer Capability: Transparency */
enum gsm48_bcap_transp {
	GSM48_BCAP_TR_TRANSP	= 0,
	GSM48_BCAP_TR_RLP	= 1,
	GSM48_BCAP_TR_TR_PREF	= 2,
	GSM48_BCAP_TR_RLP_PREF	= 3,
};

/* GSM 04.08 Bearer Capability: Modem Type */
enum gsm48_bcap_modem_type {
	GSM48_BCAP_MT_NONE	= 0,
	GSM48_BCAP_MT_V21	= 1,
	GSM48_BCAP_MT_V22	= 2,
	GSM48_BCAP_MT_V22bis	= 3,
	GSM48_BCAP_MT_V23	= 4,
	GSM48_BCAP_MT_V26ter	= 5,
	GSM48_BCAP_MT_V32	= 6,
	GSM48_BCAP_MT_UNDEF	= 7,
	GSM48_BCAP_MT_AUTO_1	= 8,
};

/*! GSM 04.08 Bearer Capability: Speech Version Indication
 *  (See also 3GPP TS 24.008, Table 10.5.103) */
enum gsm48_bcap_speech_ver {
	GSM48_BCAP_SV_FR	= 0,	/*!< GSM FR V1 (GSM FR) */
	GSM48_BCAP_SV_HR	= 1,	/*!< GSM HR V1 (GSM HR) */
	GSM48_BCAP_SV_EFR	= 2,	/*!< GSM FR V2 (GSM EFR) */
	GSM48_BCAP_SV_AMR_F	= 4,	/*!< GSM FR V3 (FR AMR) */
	GSM48_BCAP_SV_AMR_H	= 5,	/*!< GSM HR V3 (HR_AMR) */
	GSM48_BCAP_SV_AMR_OFW	= 6,	/*!< GSM FR V4 (OFR AMR-WB) */
	GSM48_BCAP_SV_AMR_OHW	= 7,	/*!< GSM HR V4 (OHR AMR-WB) */
	GSM48_BCAP_SV_AMR_FW	= 8,	/*!< GSM FR V5 (FR AMR-WB) */
	GSM48_BCAP_SV_AMR_OH	= 11,	/*!< GSM HR V6 (OHR AMR) */
};

#define GSM48_TMSI_LEN	5
#define GSM48_MID_TMSI_LEN	(GSM48_TMSI_LEN + 2)
#define GSM48_MI_SIZE 32

/* 3GPP TS 24.008 § 10.5.5.15 Routing area identification */
struct gsm48_ra_id {
	uint8_t digits[3];	/* MCC + MNC BCD digits */
	uint16_t lac;		/* Location Area Code */
	uint8_t rac;		/* Routing Area Code */
} __attribute__ ((packed));

#define GSM48_CELL_CHAN_DESC_SIZE	16

#define GSM_MACBLOCK_LEN	23
#define GSM_MACBLOCK_PADDING	0x2b

/* Table 10.5.118 / 3GPP TS 24.008 Section 10.5.4.7 */
enum gsm48_type_of_number {
	GSM48_TON_UNKNOWN	= 0,
	GSM48_TON_INTERNATIONAL	= 1,
	GSM48_TON_NATIONAL	= 2,
	GSM48_TON_NET_SPEC	= 3,
	GSM48_TON_SHORT_CODE	= 4,
	/* reserved */
};

/* Table 10.5.118 / 3GPP TS 24.008 Section 10.5.4.7 */
enum gsm48_numbering_plan {
	GSM48_NPI_UNKNOWN	= 0,
	GSM48_NPI_ISDN_E164	= 1,
	GSM48_NPI_DATA_X121	= 3,
	GSM48_NPI_TELEX_F69	= 4,
	GSM48_NPI_NATIONAL	= 8,
	GSM48_NPI_PRIVATE	= 9,
	GSM48_NPI_CTS		= 11,
	/* reserved */
};
