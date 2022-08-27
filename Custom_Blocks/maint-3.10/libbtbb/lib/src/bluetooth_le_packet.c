/* -*- c -*- */
/*
 * Copyright 2007 - 2012 Mike Ryan, Dominic Spill, Michael Ossmann
 * Copyright 2005, 2006 Free Software Foundation, Inc.
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "btbb.h"
#include "bluetooth_le_packet.h"
#include <ctype.h>
#include <string.h>

/* company identifier lookup */
const char *bt_compidtostr(uint16_t compid);

/* string representations of advertising packet type */
static const char *ADV_TYPE_NAMES[] = {
	"ADV_IND", "ADV_DIRECT_IND", "ADV_NONCONN_IND", "SCAN_REQ",
	"SCAN_RSP", "CONNECT_REQ", "ADV_SCAN_IND",
};

/* source clock accuracy in a connect packet */
static const char *CONNECT_SCA[] = {
	"251 ppm to 500 ppm", "151 ppm to 250 ppm", "101 ppm to 150 ppm",
	"76 ppm to 100 ppm", "51 ppm to 75 ppm", "31 ppm to 50 ppm",
	"21 ppm to 30 ppm", "0 ppm to 20 ppm",
};

/* flags */
static const char *FLAGS[] = {
	"LE Limited Discoverable Mode", "LE General Discoverable Mode",
	"BR/EDR Not Supported",
	"Simultaneous LE and BR/EDR to Same Device Capable (Controller)",
	"Simultaneous LE and BR/EDR to Same Device Capable (Host)",
	"Reserved", "Reserved", "Reserved",
};

// count of objects in an array, shamelessly stolen from Chrome
#define COUNT_OF(x) ((sizeof(x)/sizeof(0[x])) / ((size_t)(!(sizeof(x) % sizeof(0[x])))))

static uint8_t count_bits(uint32_t n)
{
	uint8_t i = 0;
	for (i = 0; n != 0; i++)
		n &= n - 1;
	return i;
}

static int aa_access_channel_off_by_one(const uint32_t aa) {
	int retval = 0;
	if(count_bits(aa ^ LE_ADV_AA) == 1) {
		retval = 1;
	}
	return retval;
}

/*
 * A helper function for filtering bogus packets on data channels.
 *
 * If a candidate capture packet is random noise we would expect its
 * Access Address to be a randomly distributed 32-bit number.  An
 * exhaustive software analysis reveals that of 4294967296 possible
 * 32-bit Access Address values, 2900629660 (67.5%) are acceptable and
 * 1394337636 (32.5%) are invalid.  This function will identify which
 * category a candidate Access Address falls into by returning the
 * number of offenses contained.
 *
 * Refer to BT 4.x, Vol 6, Par B, Section 2.1.2.
 *
 * The Access Address in data channel packets meet the
 * following requirements:
 *  - It shall have no more than six consecutive zeros or ones.
 *  - It shall not be the advertising channel packets’ Access Address.
 *  - It shall not be a sequence that differs from the advertising channel packets’
 *    Access Address by only one bit.
 *  - It shall not have all four octets equal.
 *  - It shall have no more than 24 transitions.
 *  - It shall have a minimum of two transitions in the most significant six bits.
 */
static int aa_data_channel_offenses(const uint32_t aa) {
	int retval = 0, transitions = 0;
	unsigned shift, odd = (unsigned) (aa & 1);
	uint8_t aab3, aab2, aab1, aab0 = (uint8_t) (aa & 0xff);

	const uint8_t EIGHT_BIT_TRANSITIONS_EVEN[256] = {
		0, 2, 2, 2, 2, 4, 2, 2, 2, 4, 4, 4, 2, 4, 2, 2,
		2, 4, 4, 4, 4, 6, 4, 4, 2, 4, 4, 4, 2, 4, 2, 2,
		2, 4, 4, 4, 4, 6, 4, 4, 4, 6, 6, 6, 4, 6, 4, 4,
		2, 4, 4, 4, 4, 6, 4, 4, 2, 4, 4, 4, 2, 4, 2, 2,
		2, 4, 4, 4, 4, 6, 4, 4, 4, 6, 6, 6, 4, 6, 4, 4,
		4, 6, 6, 6, 6, 8, 6, 6, 4, 6, 6, 6, 4, 6, 4, 4,
		2, 4, 4, 4, 4, 6, 4, 4, 4, 6, 6, 6, 4, 6, 4, 4,
		2, 4, 4, 4, 4, 6, 4, 4, 2, 4, 4, 4, 2, 4, 2, 2,
		1, 3, 3, 3, 3, 5, 3, 3, 3, 5, 5, 5, 3, 5, 3, 3,
		3, 5, 5, 5, 5, 7, 5, 5, 3, 5, 5, 5, 3, 5, 3, 3,
		3, 5, 5, 5, 5, 7, 5, 5, 5, 7, 7, 7, 5, 7, 5, 5,
		3, 5, 5, 5, 5, 7, 5, 5, 3, 5, 5, 5, 3, 5, 3, 3,
		1, 3, 3, 3, 3, 5, 3, 3, 3, 5, 5, 5, 3, 5, 3, 3,
		3, 5, 5, 5, 5, 7, 5, 5, 3, 5, 5, 5, 3, 5, 3, 3,
		1, 3, 3, 3, 3, 5, 3, 3, 3, 5, 5, 5, 3, 5, 3, 3,
		1, 3, 3, 3, 3, 5, 3, 3, 1, 3, 3, 3, 1, 3, 1, 1
	};

	const uint8_t EIGHT_BIT_TRANSITIONS_ODD[256] = {
		1, 1, 3, 1, 3, 3, 3, 1, 3, 3, 5, 3, 3, 3, 3, 1,
		3, 3, 5, 3, 5, 5, 5, 3, 3, 3, 5, 3, 3, 3, 3, 1,
		3, 3, 5, 3, 5, 5, 5, 3, 5, 5, 7, 5, 5, 5, 5, 3,
		3, 3, 5, 3, 5, 5, 5, 3, 3, 3, 5, 3, 3, 3, 3, 1,
		3, 3, 5, 3, 5, 5, 5, 3, 5, 5, 7, 5, 5, 5, 5, 3,
		5, 5, 7, 5, 7, 7, 7, 5, 5, 5, 7, 5, 5, 5, 5, 3,
		3, 3, 5, 3, 5, 5, 5, 3, 5, 5, 7, 5, 5, 5, 5, 3,
		3, 3, 5, 3, 5, 5, 5, 3, 3, 3, 5, 3, 3, 3, 3, 1,
		2, 2, 4, 2, 4, 4, 4, 2, 4, 4, 6, 4, 4, 4, 4, 2,
		4, 4, 6, 4, 6, 6, 6, 4, 4, 4, 6, 4, 4, 4, 4, 2,
		4, 4, 6, 4, 6, 6, 6, 4, 6, 6, 8, 6, 6, 6, 6, 4,
		4, 4, 6, 4, 6, 6, 6, 4, 4, 4, 6, 4, 4, 4, 4, 2,
		2, 2, 4, 2, 4, 4, 4, 2, 4, 4, 6, 4, 4, 4, 4, 2,
		4, 4, 6, 4, 6, 6, 6, 4, 4, 4, 6, 4, 4, 4, 4, 2,
		2, 2, 4, 2, 4, 4, 4, 2, 4, 4, 6, 4, 4, 4, 4, 2,
		2, 2, 4, 2, 4, 4, 4, 2, 2, 2, 4, 2, 2, 2, 2, 0
	};

	transitions += (odd ? EIGHT_BIT_TRANSITIONS_ODD[aab0] : EIGHT_BIT_TRANSITIONS_EVEN[aab0] );
	odd = (unsigned) (aab0 & 0x80);
	aab1 = (uint8_t) (aa >> 8);
	transitions += (odd ? EIGHT_BIT_TRANSITIONS_ODD[aab1] : EIGHT_BIT_TRANSITIONS_EVEN[aab1] );
	odd = (unsigned) (aab1 & 0x80);
	aab2 = (uint8_t) (aa >> 16);
	transitions += (odd ? EIGHT_BIT_TRANSITIONS_ODD[aab2] : EIGHT_BIT_TRANSITIONS_EVEN[aab2] );
	odd = (unsigned) (aab2 & 0x80);
	aab3 = (uint8_t) (aa >> 24);
	transitions += (odd ? EIGHT_BIT_TRANSITIONS_ODD[aab3] : EIGHT_BIT_TRANSITIONS_EVEN[aab3] );

	/* consider excessive transitions as offenses */
	if (transitions > 24) {
		retval += (transitions - 24);
	}

	const uint8_t AA_MSB6_ALLOWED[64] = {
		0, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 0,
		1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0,
		0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
		0, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 0, 1, 0, 0
	};

	/* consider excessive transitions in the 6 MSBs as an offense */
	retval += (1 - AA_MSB6_ALLOWED[aab3>>2]);

	/* consider all bytes as being equal an offense */
	retval += (((aab0 == aab1) && (aab0 == aab2) && (aab0 == aab3)) ? 1 : 0);

	/* access-channel address and off-by-ones are illegal */
	retval += ((aa == LE_ADV_AA) ? 1 : 0);
	retval += aa_access_channel_off_by_one(aa);

	/* inspect nibble triples for insufficient bit transitions */
	for(shift=0; shift<=20; shift+=4) {
		uint16_t twelvebits = (uint16_t) ((aa >> shift) & 0xfff);
		switch( twelvebits ) {
			/* seven consecutive zeroes */
		case 0x080: case 0x180: case 0x280: case 0x380: case 0x480:
		case 0x580: case 0x680: case 0x780: case 0x880: case 0x980:
		case 0xa80: case 0xb80: case 0xc80: case 0xd80: case 0xe80:
		case 0xf80: case 0x101: case 0x301: case 0x501: case 0x701:
		case 0x901: case 0xb01: case 0xd01: case 0xf01: case 0x202:
		case 0x602: case 0xa02: case 0xe02: case 0x203: case 0x603:
		case 0xa03: case 0xe03: case 0x404: case 0xc04: case 0x405:
		case 0xc05: case 0x406: case 0xc06: case 0x407: case 0xc07:
		case 0x808: case 0x809: case 0x80a: case 0x80b: case 0x80c:
		case 0x80d: case 0x80e: case 0x80f: case 0x010: case 0x011:
		case 0x012: case 0x013: case 0x014: case 0x015: case 0x016:
		case 0x017: case 0x018: case 0x019: case 0x01a: case 0x01b:
		case 0x01c: case 0x01d: case 0x01e: case 0x01f:
			/* eight consecutive zeroes */
		case 0x100: case 0x300: case 0x500: case 0x700: case 0x900:
		case 0xb00: case 0xd00: case 0xf00: case 0x201: case 0x601:
		case 0xa01: case 0xe01: case 0x402: case 0xc02: case 0x403:
		case 0xc03: case 0x804: case 0x805: case 0x806: case 0x807:
		case 0x008: case 0x009: case 0x00a: case 0x00b: case 0x00c:
		case 0x00d: case 0x00e: case 0x00f:
			/* nine consecutive zeroes */
		case 0xe00: case 0xc01: case 0x802: case 0x803: case 0x004:
		case 0x005: case 0x006: case 0x007:
			/* ten consecutive zeroes */
		case 0x400: case 0xc00: case 0x801: case 0x002: case 0x003:
			/* eleven consecutive zeroes */
		case 0x800: case 0x001:
			/* twelve consecutive zeroes */
		case 0x000:
			/* seven consecutive ones */
		case 0x07f: case 0x0fe: case 0x2fe: case 0x4fe: case 0x6fe:
		case 0x8fe: case 0xafe: case 0xcfe: case 0xefe: case 0x1fc:
		case 0x5fc: case 0x9fc: case 0xdfc: case 0x1fd: case 0x5fd:
		case 0x9fd: case 0xdfd: case 0x3f8: case 0xbf8: case 0x3f9:
		case 0xbf9: case 0x3fa: case 0xbfa: case 0x3fb: case 0xbfb:
		case 0x7f4: case 0x7f5: case 0x7f6: case 0x7f7: case 0xfe0:
			/* eight consecutive ones */
		case 0x0ff: case 0x2ff: case 0x4ff: case 0x6ff: case 0x8ff:
		case 0xaff: case 0xcff: case 0xeff: case 0x1fe: case 0x5fe:
		case 0x9fe: case 0xdfe: case 0x3fc: case 0xbfc: case 0x3fd:
		case 0xbfd: case 0x7f8: case 0x7f9: case 0x7fa: case 0x7fb:
		case 0xff0: case 0xff1: case 0xff2: case 0xff3: case 0xff4:
		case 0xff5: case 0xff6: case 0xff7:
			/* nine consecutive ones */
		case 0x1ff: case 0x5ff: case 0x9ff: case 0xdff: case 0x3fe:
		case 0xbfe: case 0x7fc: case 0x7fd: case 0xff8: case 0xff9:
		case 0xffa: case 0xffb:
			/* ten consecutive ones */
		case 0x3ff: case 0xbff: case 0x7fe: case 0xffc: case 0xffd:
			/* eleven consecutive ones */
		case 0x7ff: case 0xffe:
			/* all ones */
		case 0xfff:
			retval++;
			break;
		default:
			break;
		}
	}

	return retval;
}

lell_packet *
lell_packet_new(void)
{
	lell_packet *pkt = (lell_packet *)calloc(1, sizeof(lell_packet));
	pkt->refcount = 1;
	return pkt;
}

void
lell_packet_ref(lell_packet *pkt)
{
	pkt->refcount++;
}

void
lell_packet_unref(lell_packet *pkt)
{
	pkt->refcount--;
	if (pkt->refcount == 0)
		free(pkt);
}

static uint8_t le_channel_index(uint16_t phys_channel) {
	uint8_t ret;
	if (phys_channel == 2402) {
		ret = 37;
	} else if (phys_channel < 2426) { // 0 - 10
		ret = (phys_channel - 2404) / 2;
	} else if (phys_channel == 2426) {
		ret = 38;
	} else if (phys_channel < 2480) { // 11 - 36
		ret = 11 + (phys_channel - 2428) / 2;
	} else {
		ret = 39;
	}
	return ret;
}

void lell_allocate_and_decode(const uint8_t *stream, uint16_t phys_channel, uint32_t clk100ns, lell_packet **pkt)
{
	*pkt = lell_packet_new( );
	memcpy((*pkt)->symbols, stream, MAX_LE_SYMBOLS);

	(*pkt)->channel_idx = le_channel_index(phys_channel);
	(*pkt)->channel_k = (phys_channel-2402)/2;
	(*pkt)->clk100ns = clk100ns;

	(*pkt)->access_address = 0;
	(*pkt)->access_address |= (*pkt)->symbols[0];
	(*pkt)->access_address |= (*pkt)->symbols[1] << 8;
	(*pkt)->access_address |= (*pkt)->symbols[2] << 16;
	(*pkt)->access_address |= (*pkt)->symbols[3] << 24;

	if (lell_packet_is_data(*pkt)) {
		// data PDU
		(*pkt)->length = (*pkt)->symbols[5] & 0x1f;
		(*pkt)->access_address_offenses = aa_data_channel_offenses((*pkt)->access_address);
		(*pkt)->flags.as_bits.access_address_ok = (*pkt)->access_address_offenses ? 0 : 1;
	} else {
		// advertising PDU
		(*pkt)->length = (*pkt)->symbols[5] & 0x3f;
		(*pkt)->adv_type = (*pkt)->symbols[4] & 0xf;
		(*pkt)->adv_tx_add = (*pkt)->symbols[4] & 0x40 ? 1 : 0;
		(*pkt)->adv_rx_add = (*pkt)->symbols[4] & 0x80 ? 1 : 0;
		(*pkt)->flags.as_bits.access_address_ok = ((*pkt)->access_address == 0x8e89bed6);
		(*pkt)->access_address_offenses = (*pkt)->flags.as_bits.access_address_ok ? 0 :
			(aa_access_channel_off_by_one((*pkt)->access_address) ? 1 : 32);
	}
}

unsigned lell_packet_is_data(const lell_packet *pkt)
{
	return (unsigned) (pkt->channel_idx < 37);
}

uint32_t lell_get_access_address(const lell_packet *pkt)
{
	return pkt->access_address;
}

unsigned lell_get_access_address_offenses(const lell_packet *pkt)
{
	return pkt->access_address_offenses;
}

unsigned lell_get_channel_index(const lell_packet *pkt)
{
	return pkt->channel_idx;
}

unsigned lell_get_channel_k(const lell_packet *pkt)
{
	return pkt->channel_k;
}

const char * lell_get_adv_type_str(const lell_packet *pkt)
{
	if (lell_packet_is_data(pkt))
		return NULL;
	if (pkt->adv_type < COUNT_OF(ADV_TYPE_NAMES))
		return ADV_TYPE_NAMES[pkt->adv_type];
	return "UNKNOWN";
}

static void _dump_addr(const char *name, const uint8_t *buf, int offset, int random) {
	int i;
	printf("    %s%02x", name, buf[offset+5]);
	for (i = 4; i >= 0; --i)
		printf(":%02x", buf[offset+i]);
	printf(" (%s)\n", random ? "random" : "public");
}

static void _dump_8(const char *name, const uint8_t *buf, int offset) {
	printf("    %s%02x (%d)\n", name, buf[offset], buf[offset]);
}

static void _dump_16(const char *name, const uint8_t *buf, int offset) {
	uint16_t val = buf[offset+1] << 8 | buf[offset];
	printf("    %s%04x (%d)\n", name, val, val);
}

static void _dump_24(char *name, const uint8_t *buf, int offset) {
	uint32_t val = buf[offset+2] << 16 | buf[offset+1] << 8 | buf[offset];
	printf("    %s%06x\n", name, val);
}

static void _dump_32(const char *name, const uint8_t *buf, int offset) {
	uint32_t val = buf[offset+3] << 24 |
				   buf[offset+2] << 16 |
				   buf[offset+1] << 8 |
				   buf[offset+0];
	printf("    %s%08x\n", name, val);
}

static void _dump_uuid(const uint8_t *uuid) {
	int i;
	for (i = 0; i < 4; ++i)
		printf("%02x", uuid[i]);
	printf("-");
	for (i = 4; i < 6; ++i)
		printf("%02x", uuid[i]);
	printf("-");
	for (i = 6; i < 8; ++i)
		printf("%02x", uuid[i]);
	printf("-");
	for (i = 8; i < 10; ++i)
		printf("%02x", uuid[i]);
	printf("-");
	for (i = 10; i < 16; ++i)
		printf("%02x", uuid[i]);
}

// Refer to pg 1735 of Bluetooth Core Spec 4.0
static void _dump_scan_rsp_data(const uint8_t *buf, int len) {
	int pos = 0;
	int sublen, i;
	uint8_t type;
	uint16_t val;
	char *cval;

	while (pos < len) {
		sublen = buf[pos];
		++pos;
		if (pos + sublen > len) {
			printf("Error: attempt to read past end of buffer (%d + %d > %d)\n", pos, sublen, len);
			return;
		}
		if (sublen == 0) {
			printf("Early return due to 0 length\n");
			return;
		}
		type = buf[pos];
		printf("        Type %02x", type);
		switch (type) {
			case 0x01:
				printf(" (Flags)\n");
				printf("           ");
				for (i = 0; i < 8; ++i)
					printf("%d", buf[pos+1] & (1 << (7-i)) ? 1 : 0);
				printf("\n");
				for (i = 0; i < 8; ++i) {
					if (buf[pos+1] & (1 << i)) {
						printf("               ");
						printf("%s\n", FLAGS[i]);
					}
				}
				printf("\n");
				break;
			case 0x02:
				printf(" (16-bit Service UUIDs, more available)\n");
				goto print16;
			case 0x03:
				printf(" (16-bit Service UUIDs) \n");
print16:
				if ((sublen - 1) % 2 == 0) {
					for (i = 0; i < sublen - 1; i += 2) {
						uint16_t *uuid = (uint16_t *)&buf[pos+1+i];
						printf("           %04x\n", *uuid);
					}
				}
				break;
			case 0x06:
				printf(" (128-bit Service UUIDs, more available)\n");
				goto print128;
			case 0x07:
				printf(" (128-bit Service UUIDs)\n");
print128:
				if ((sublen - 1) % 16 == 0) {
					uint8_t uuid[16];
					for (i = 0; i < sublen - 1; ++i) {
						uuid[15 - (i % 16)] = buf[pos+1+i];
						if ((i & 15) == 15) {
							printf("           ");
							_dump_uuid(uuid);
							printf("\n");
						}
					}
				}
				else {
					printf("Wrong length (%d, must be divisible by 16)\n", sublen-1);
				}
				break;
			case 0x09:
				printf(" (Complete Local Name)\n");
				printf("           ");
				for (i = 1; i < sublen; ++i)
					printf("%c", isprint(buf[pos+i]) ? buf[pos+i] : '.');
				printf("\n");
				break;
			case 0x0a:
				printf(" (Tx Power Level)\n");
				printf("           ");
				if (sublen-1 == 1) {
					cval = (char *)&buf[pos+1];
					printf("%d dBm\n", *cval);
				} else {
					printf("Wrong length (%d, should be 1)\n", sublen-1);
				}
				break;
			case 0x12:
				printf(" (Slave Connection Interval Range)\n");
				printf("           ");
				if (sublen-1 == 4) {
					val = (buf[pos+2] << 8) | buf[pos+1];
					printf("(%0.2f, ", val * 1.25);
					val = (buf[pos+4] << 8) | buf[pos+3];
					printf("%0.2f) ms\n", val * 1.25);
				}
				else {
					printf("Wrong length (%d, should be 4)\n", sublen-1);
				}
				break;
			case 0x16:
				printf(" (Service Data)\n");
				printf("           ");
				if (sublen-1 >= 2) {
					val = (buf[pos+2] << 8) | buf[pos+1];
					printf("UUID: %02x", val);
					if (sublen-1 > 2) {
						printf(", Additional:");
						for (i = 3; i < sublen; ++i)
							printf(" %02x", buf[pos+i]);
					}
					printf("\n");
				}
				else {
					printf("Wrong length (%d, should be >= 2)\n", sublen-1);
				}
				break;
			case 0xff:
				printf(" (Manufacturer Specific Data)\n");
				printf("           ");
				if (sublen - 1 >= 2) {
					uint16_t company = (buf[pos+2] << 8) | buf[pos+1];
					printf("Company: %s\n", bt_compidtostr(company));
					printf("           ");
					printf("Data:");
					for (i = 3; i < sublen; ++i)
						printf(" %02x", buf[pos+i]);
					printf("\n");
				}
				else {
					printf("Wrong length (%d, should be >= 2)\n", sublen-1);
				}
				break;
			default:
				printf("\n");
				printf("           ");
				for (i = 1; i < sublen; ++i)
					printf(" %02x", buf[pos+i]);
				printf("\n");
		}
		pos += sublen;
	}
}

void lell_print(const lell_packet *pkt)
{
	int i, opcode;
	if (lell_packet_is_data(pkt)) {
		int llid = pkt->symbols[4] & 0x3;
		static const char *llid_str[] = {
			"Reserved",
			"LL Data PDU / empty or L2CAP continuation",
			"LL Data PDU / L2CAP start",
			"LL Control PDU",
		};

		printf("Data / AA %08x (%s) / %2d bytes\n", pkt->access_address,
		       pkt->flags.as_bits.access_address_ok ? "valid" : "invalid",
		       pkt->length);
		printf("    Channel Index: %d\n", pkt->channel_idx);
		printf("    LLID: %d / %s\n", llid, llid_str[llid]);
		printf("    NESN: %d  SN: %d  MD: %d\n", (pkt->symbols[4] >> 2) & 1,
												 (pkt->symbols[4] >> 3) & 1,
												 (pkt->symbols[4] >> 4) & 1);
		switch (llid) {
		case 3: // LL Control PDU
			opcode = pkt->symbols[6];
			static const char *opcode_str[] = {
				"LL_CONNECTION_UPDATE_REQ",
				"LL_CHANNEL_MAP_REQ",
				"LL_TERMINATE_IND",
				"LL_ENC_REQ",
				"LL_ENC_RSP",
				"LL_START_ENC_REQ",
				"LL_START_ENC_RSP",
				"LL_UNKNOWN_RSP",
				"LL_FEATURE_REQ",
				"LL_FEATURE_RSP",
				"LL_PAUSE_ENC_REQ",
				"LL_PAUSE_ENC_RSP",
				"LL_VERSION_IND",
				"LL_REJECT_IND",
				"LL_SLAVE_FEATURE_REQ",
				"LL_CONNECTION_PARAM_REQ",
				"LL_CONNECTION_PARAM_RSP",
				"LL_REJECT_IND_EXT",
				"LL_PING_REQ",
				"LL_PING_RSP",
				"Reserved for Future Use",
			};
			printf("    Opcode: %d / %s\n", opcode, opcode_str[(opcode<0x14)?opcode:0x14]);
			break;
		default:
			break;
		}
	} else {
		printf("Advertising / AA %08x (%s)/ %2d bytes\n", pkt->access_address, 
		       pkt->flags.as_bits.access_address_ok ? "valid" : "invalid",
		       pkt->length);
		printf("    Channel Index: %d\n", pkt->channel_idx);
		printf("    Type:  %s\n", lell_get_adv_type_str(pkt));

		switch(pkt->adv_type) {
			case ADV_IND:
			case ADV_NONCONN_IND:
			case ADV_SCAN_IND:
				_dump_addr("AdvA:  ", pkt->symbols, 6, pkt->adv_tx_add);
				if (pkt->length-6 > 0) {
					printf("    AdvData:");
					for (i = 0; i < pkt->length - 6; ++i)
						printf(" %02x", pkt->symbols[12+i]);
					printf("\n");
					_dump_scan_rsp_data(&pkt->symbols[12], pkt->length-6);
				}
				break;
			case ADV_DIRECT_IND:
				_dump_addr("AdvA:  ", pkt->symbols, 6, pkt->adv_tx_add);
				_dump_addr("InitA: ", pkt->symbols, 12, pkt->adv_rx_add);
				break;
			case SCAN_REQ:
				_dump_addr("ScanA: ", pkt->symbols, 6, pkt->adv_tx_add);
				_dump_addr("AdvA:  ", pkt->symbols, 12, pkt->adv_rx_add);
				break;
			case SCAN_RSP:
				_dump_addr("AdvA:  ", pkt->symbols, 6, pkt->adv_tx_add);
				printf("    ScanRspData:");
				for (i = 0; i < pkt->length - 6; ++i)
					printf(" %02x", pkt->symbols[12+i]);
				printf("\n");
				_dump_scan_rsp_data(&pkt->symbols[12], pkt->length-6);
				break;
			case CONNECT_REQ:
				_dump_addr("InitA: ", pkt->symbols, 6, pkt->adv_tx_add);
				_dump_addr("AdvA:  ", pkt->symbols, 12, pkt->adv_rx_add);
				_dump_32("AA:    ", pkt->symbols, 18);
				_dump_24("CRCInit: ", pkt->symbols, 22);
				_dump_8("WinSize: ", pkt->symbols, 25);
				_dump_16("WinOffset: ", pkt->symbols, 26);
				_dump_16("Interval: ", pkt->symbols, 28);
				_dump_16("Latency: ", pkt->symbols, 30);
				_dump_16("Timeout: ", pkt->symbols, 32);

				printf("    ChM:");
				for (i = 0; i < 5; ++i)
					printf(" %02x", pkt->symbols[34+i]);
				printf("\n");

				printf("    Hop: %d\n", pkt->symbols[39] & 0x1f);
				printf("    SCA: %d, %s\n",
						pkt->symbols[39] >> 5,
						CONNECT_SCA[pkt->symbols[39] >> 5]);
				break;
		}
	}

	printf("\n");
	printf("    Data: ");
	for (i = 6; i < 6 + pkt->length; ++i)
		printf(" %02x", pkt->symbols[i]);
	printf("\n");

	printf("    CRC:  ");
	for (i = 0; i < 3; ++i)
		printf(" %02x", pkt->symbols[6 + pkt->length + i]);
	printf("\n");
}
