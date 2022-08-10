/* -*- c -*- */
/*
 * Copyright 2014 Christopher D. Kilgour techie AT whiterocker.com
 *
 * This file is part of libbtbb
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with libbtbb; see the file COPYING.  If not, write to
 * the Free Software Foundation, Inc., 51 Franklin Street,
 * Boston, MA 02110-1301, USA.
 */
#ifndef PCAPNG_BT_DOT_H
#define PCAPNG_BT_DOT_H

#include "pcap-common.h"
#include "pcapng.h"

typedef struct __attribute__((packed)) {
	uint32_t centre_freq;
	uint32_t analog_bandwidth;
	int32_t  intermediate_freq;
	uint32_t sampling_bandwidth;
} bt_wideband_rf_info;

typedef struct __attribute__((packed)) {
  option_header header;
  bt_wideband_rf_info wideband_rf_info;
} bt_wideband_rf_option;

#define PCAPNG_BT_WIDEBAND_RF_INFO 0xd300

/* --------------------------------- BR/EDR ----------------------------- */

typedef struct __attribute__((packed)) {
  enhanced_packet_block blk_header;
  pcap_bluetooth_bredr_bb_header bredr_bb_header;
} pcapng_bredr_packet;

typedef struct __attribute__((packed)) {
  uint8_t bd_addr[6];
  uint8_t uap_mask;
  uint8_t nap_valid;
} bredr_bd_addr_info;

typedef struct __attribute__((packed)) {
  option_header header;
  bredr_bd_addr_info bd_addr_info;
} bredr_br_addr_option;

typedef struct __attribute__((packed)) {
  uint64_t ts;
  uint32_t lap_uap;
  uint32_t clk;
  uint32_t clk_mask;
} bredr_clk_info;

typedef struct __attribute__((packed)) {
  option_header header;
  bredr_clk_info clock_info;
} bredr_clk_option;

#define PCAPNG_BREDR_OPTION_BD_ADDR           0xd340
#define PCAPNG_BREDR_OPTION_MASTER_CLOCK_INFO 0xd341

/* --------------------------------- Low Energy ---------------------------- */

typedef struct __attribute__((packed)) {
  enhanced_packet_block blk_header;
  pcap_bluetooth_le_ll_header le_ll_header;
  uint8_t le_packet[LE_MAX_PAYLOAD];

  /* Force 32 bit alignment for options and blk_tot_length. */
  uint8_t pad[2];

  /* Add space for OPTIONS and BLOCK_TOTAL_LENGTH at end of
     block. These won't be at this position in the structure unless
     the LE PDU is the full 39 bytes. */
  uint32_t options;
  uint32_t blk_tot_length;
} pcapng_le_packet;

typedef struct __attribute__((packed)) {
  uint64_t ns;
  union {
    struct {
      uint8_t InitA[6];
      uint8_t AdvA[6];
      uint8_t AA[4];
      uint8_t CRCInit[3];
      uint8_t WinSize;
      uint8_t WinOffset[2];
      uint8_t Interval[2];
      uint8_t Latency[2];
      uint8_t Timeout[2];
      uint8_t ChM[5];
      uint8_t HopSCA;
    } fields;
    uint8_t bytes[0];
  } pdu;
} le_ll_connection_info;

typedef struct __attribute__((packed)) {
  option_header header;
  le_ll_connection_info connection_info;
} le_ll_connection_info_option;

#define PCAPNG_LE_LL_CONNECTION_INFO 0xd380

#endif /* PCAPNG_BT_DOT_H */
