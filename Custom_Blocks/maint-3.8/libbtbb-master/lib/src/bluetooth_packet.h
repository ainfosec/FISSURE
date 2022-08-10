/* -*- c -*- */
/*
 * Copyright 2007 - 2013 Dominic Spill, Michael Ossmann, Will Code
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
#ifndef INCLUDED_BLUETOOTH_PACKET_H
#define INCLUDED_BLUETOOTH_PACKET_H
#include "btbb.h"

/* maximum number of symbols */
#define MAX_SYMBOLS 3125

/* maximum number of payload bits */
#define MAX_PAYLOAD_LENGTH 2744

/* minimum header bit errors to indicate that this is an ID packet */
#define ID_THRESHOLD 5

#define PACKET_TYPE_NULL 0
#define PACKET_TYPE_POLL 1
#define PACKET_TYPE_FHS 2
#define PACKET_TYPE_DM1 3
#define PACKET_TYPE_DH1 4
#define PACKET_TYPE_HV1 5
#define PACKET_TYPE_HV2 6
#define PACKET_TYPE_HV3 7
#define PACKET_TYPE_DV 8
#define PACKET_TYPE_AUX1 9
#define PACKET_TYPE_DM3 10
#define PACKET_TYPE_DH3 11
#define PACKET_TYPE_EV4 12
#define PACKET_TYPE_EV5 13
#define PACKET_TYPE_DM5 14
#define PACKET_TYPE_DH5 15

struct btbb_packet {

	uint32_t refcount;

	uint32_t flags;

	uint8_t channel; /* Bluetooth channel (0-79) */
	uint8_t UAP;     /* upper address part */
	uint16_t NAP;    /* non-significant address part */
	uint32_t LAP;    /* lower address part found in access code */

	uint8_t modulation;
	uint8_t transport;
	uint8_t packet_type;
	uint8_t packet_lt_addr; /* LLID field of payload header (2 bits) */
	uint8_t packet_flags; /* Flags - FLOW/ARQN/SQEN */
	uint8_t packet_hec; /* Flags - FLOW/ARQN/SQEN */

	/* packet header, one bit per char */
	char packet_header[18];

	/* number of payload header bytes: 0, 1, 2, or -1 for
	 * unknown. payload is one bit per char. */
	int payload_header_length;
	char payload_header[16];

	/* LLID field of payload header (2 bits) */
	uint8_t payload_llid;

	/* flow field of payload header (1 bit) */
	uint8_t payload_flow;

	/* payload length: the total length of the asynchronous data
	* in bytes.  This does not include the length of synchronous
	* data, such as the voice field of a DV packet.  If there is a
	* payload header, this payload length is payload body length
	* (the length indicated in the payload header's length field)
	* plus payload_header_length plus 2 bytes CRC (if present).
	*/
	int payload_length;

	/* The actual payload data in host format
	* Ready for passing to wireshark
	* 2744 is the maximum length, but most packets are shorter.
	* Dynamic allocation would probably be better in the long run but is
	* problematic in the short run.
	*/
	char payload[MAX_PAYLOAD_LENGTH];

	uint16_t crc;
	uint32_t clkn;     /* CLK1-27 of the packet */
	uint8_t ac_errors; /* Number of bit errors in the AC */

	/* the raw symbol stream (less the preamble), one bit per char */
	//FIXME maybe this should be a vector so we can grow it only
	//to the size needed and later shrink it if we find we have
	//more symbols than necessary
	uint16_t length; /* number of symbols */
	char symbols[MAX_SYMBOLS];

};

/* type-specific CRC checks and decoding */
int fhs(int clock, btbb_packet* p);
int DM(int clock, btbb_packet* p);
int DH(int clock, btbb_packet* p);
int EV3(int clock, btbb_packet* p);
int EV4(int clock, btbb_packet* p);
int EV5(int clock, btbb_packet* p);
int HV(int clock, btbb_packet* p);

/* check if the packet's CRC is correct for a given clock (CLK1-6) */
int crc_check(int clock, btbb_packet* p);

/* format payload for tun interface */
char *tun_format(btbb_packet* p);

/* try a clock value (CLK1-6) to unwhiten packet header,
 * sets resultant d_packet_type and d_UAP, returns UAP.
 */
uint8_t try_clock(int clock, btbb_packet* p);

/* extract LAP from FHS payload */
uint32_t lap_from_fhs(btbb_packet* p);

/* extract UAP from FHS payload */
uint8_t uap_from_fhs(btbb_packet* p);

/* extract NAP from FHS payload */
uint16_t nap_from_fhs(btbb_packet* p);

/* extract clock from FHS payload */
uint32_t clock_from_fhs(btbb_packet* p);

#endif /* INCLUDED_BLUETOOTH_PACKET_H */
