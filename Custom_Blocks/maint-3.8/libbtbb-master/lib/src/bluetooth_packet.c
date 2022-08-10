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

#include <stdio.h>
#include <stdlib.h>

#include "bluetooth_packet.h"
#include "uthash.h"
#include "sw_check_tables.h"

#define MIN(X, Y) (((X) < (Y)) ? (X) : (Y))

/* Maximum number of AC errors supported by library. Caller may
 * specify any value <= AC_ERROR_LIMIT in btbb_init(). */
#define AC_ERROR_LIMIT 5

/* maximum number of bit errors for known syncwords */
#define MAX_SYNCWORD_ERRS 5

/* maximum number of bit errors in  */
#define MAX_BARKER_ERRORS 1

/* default codeword modified for PN sequence and barker code */
#define DEFAULT_CODEWORD 0xb0000002c7820e7eULL

/* Default access code, used for calculating syndromes */
#define DEFAULT_AC 0xcc7b7268ff614e1bULL

/* index into whitening data array */
static const uint8_t INDICES[] = {99, 85, 17, 50, 102, 58, 108, 45, 92, 62, 32, 118, 88, 11, 80, 2, 37, 69, 55, 8, 20, 40, 74, 114, 15, 106, 30, 78, 53, 72, 28, 26, 68, 7, 39, 113, 105, 77, 71, 25, 84, 49, 57, 44, 61, 117, 10, 1, 123, 124, 22, 125, 111, 23, 42, 126, 6, 112, 76, 24, 48, 43, 116, 0};

/* whitening data */
static const uint8_t WHITENING_DATA[] = {1, 1, 1, 0, 0, 0, 1, 1, 1, 0, 1, 1, 0, 0, 0, 1, 0, 1, 0, 0, 1, 0, 1, 1, 1, 1, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 1, 0, 1, 1, 0, 1, 1, 1, 1, 0, 0, 1, 1, 1, 0, 0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0, 1, 1, 0, 1, 0, 1, 1, 1, 0, 1, 0, 0, 0, 1, 1, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1};

/* lookup table for barker code hamming distance */
static const uint8_t BARKER_DISTANCE[] = {
	3,3,3,2,3,2,2,1,2,3,3,3,3,3,3,2,2,3,3,3,3,3,3,2,1,2,2,3,2,3,3,3,
	3,2,2,1,2,1,1,0,3,3,3,2,3,2,2,1,3,3,3,2,3,2,2,1,2,3,3,3,3,3,3,2,
	2,3,3,3,3,3,3,2,1,2,2,3,2,3,3,3,1,2,2,3,2,3,3,3,0,1,1,2,1,2,2,3,
	3,3,3,2,3,2,2,1,2,3,3,3,3,3,3,2,2,3,3,3,3,3,3,2,1,2,2,3,2,3,3,3};

/* string representations of packet type */
static const char * const TYPE_NAMES[] = {
	"NULL", "POLL", "FHS", "DM1", "DH1/2-DH1", "HV1", "HV2/2-EV3", "HV3/EV3/3-EV3",
	"DV/3-DH1", "AUX1", "DM3/2-DH3", "DH3/3-DH3", "EV4/2-EV5", "EV5/3-EV5", "DM5/2-DH5", "DH5/3-DH5"
};

/*
 * generator matrix for sync word (64,30) linear block code
 * based on polynomial 0260534236651
 * thanks to http://www.ee.unb.ca/cgi-bin/tervo/polygen.pl
 * modified for barker code
 */
static const uint64_t sw_matrix[] = {
	0xfe000002a0d1c014ULL, 0x01000003f0b9201fULL, 0x008000033ae40edbULL, 0x004000035fca99b9ULL,
	0x002000036d5dd208ULL, 0x00100001b6aee904ULL, 0x00080000db577482ULL, 0x000400006dabba41ULL,
	0x00020002f46d43f4ULL, 0x000100017a36a1faULL, 0x00008000bd1b50fdULL, 0x000040029c3536aaULL,
	0x000020014e1a9b55ULL, 0x0000100265b5d37eULL, 0x0000080132dae9bfULL, 0x000004025bd5ea0bULL,
	0x00000203ef526bd1ULL, 0x000001033511ab3cULL, 0x000000819a88d59eULL, 0x00000040cd446acfULL,
	0x00000022a41aabb3ULL, 0x0000001390b5cb0dULL, 0x0000000b0ae27b52ULL, 0x0000000585713da9ULL};

static const uint64_t barker_correct[] = {
	0xb000000000000000ULL, 0x4e00000000000000ULL, 0x4e00000000000000ULL, 0x4e00000000000000ULL,
	0x4e00000000000000ULL, 0x4e00000000000000ULL, 0x4e00000000000000ULL, 0x4e00000000000000ULL,
	0xb000000000000000ULL, 0xb000000000000000ULL, 0xb000000000000000ULL, 0x4e00000000000000ULL,
	0xb000000000000000ULL, 0x4e00000000000000ULL, 0x4e00000000000000ULL, 0x4e00000000000000ULL,
	0xb000000000000000ULL, 0xb000000000000000ULL, 0xb000000000000000ULL, 0x4e00000000000000ULL,
	0xb000000000000000ULL, 0x4e00000000000000ULL, 0x4e00000000000000ULL, 0x4e00000000000000ULL,
	0xb000000000000000ULL, 0xb000000000000000ULL, 0xb000000000000000ULL, 0xb000000000000000ULL,
	0xb000000000000000ULL, 0xb000000000000000ULL, 0xb000000000000000ULL, 0x4e00000000000000ULL,
	0x4e00000000000000ULL, 0x4e00000000000000ULL, 0x4e00000000000000ULL, 0x4e00000000000000ULL,
	0x4e00000000000000ULL, 0x4e00000000000000ULL, 0x4e00000000000000ULL, 0x4e00000000000000ULL,
	0xb000000000000000ULL, 0x4e00000000000000ULL, 0x4e00000000000000ULL, 0x4e00000000000000ULL,
	0x4e00000000000000ULL, 0x4e00000000000000ULL, 0x4e00000000000000ULL, 0x4e00000000000000ULL,
	0xb000000000000000ULL, 0x4e00000000000000ULL, 0x4e00000000000000ULL, 0x4e00000000000000ULL,
	0x4e00000000000000ULL, 0x4e00000000000000ULL, 0x4e00000000000000ULL, 0x4e00000000000000ULL,
	0xb000000000000000ULL, 0xb000000000000000ULL, 0xb000000000000000ULL, 0x4e00000000000000ULL,
	0xb000000000000000ULL, 0x4e00000000000000ULL, 0x4e00000000000000ULL, 0x4e00000000000000ULL,
	0xb000000000000000ULL, 0xb000000000000000ULL, 0xb000000000000000ULL, 0x4e00000000000000ULL,
	0xb000000000000000ULL, 0x4e00000000000000ULL, 0x4e00000000000000ULL, 0x4e00000000000000ULL,
	0xb000000000000000ULL, 0xb000000000000000ULL, 0xb000000000000000ULL, 0xb000000000000000ULL,
	0xb000000000000000ULL, 0xb000000000000000ULL, 0xb000000000000000ULL, 0x4e00000000000000ULL,
	0xb000000000000000ULL, 0xb000000000000000ULL, 0xb000000000000000ULL, 0xb000000000000000ULL,
	0xb000000000000000ULL, 0xb000000000000000ULL, 0xb000000000000000ULL, 0x4e00000000000000ULL,
	0xb000000000000000ULL, 0xb000000000000000ULL, 0xb000000000000000ULL, 0xb000000000000000ULL,
	0xb000000000000000ULL, 0xb000000000000000ULL, 0xb000000000000000ULL, 0xb000000000000000ULL,
	0xb000000000000000ULL, 0x4e00000000000000ULL, 0x4e00000000000000ULL, 0x4e00000000000000ULL,
	0x4e00000000000000ULL, 0x4e00000000000000ULL, 0x4e00000000000000ULL, 0x4e00000000000000ULL,
	0xb000000000000000ULL, 0xb000000000000000ULL, 0xb000000000000000ULL, 0x4e00000000000000ULL,
	0xb000000000000000ULL, 0x4e00000000000000ULL, 0x4e00000000000000ULL, 0x4e00000000000000ULL,
	0xb000000000000000ULL, 0xb000000000000000ULL, 0xb000000000000000ULL, 0x4e00000000000000ULL,
	0xb000000000000000ULL, 0x4e00000000000000ULL, 0x4e00000000000000ULL, 0x4e00000000000000ULL,
	0xb000000000000000ULL, 0xb000000000000000ULL, 0xb000000000000000ULL, 0xb000000000000000ULL,
	0xb000000000000000ULL, 0xb000000000000000ULL, 0xb000000000000000ULL, 0x4e00000000000000ULL};

static const uint64_t pn = 0x83848D96BBCC54FCULL;

static const uint16_t fec23_gen_matrix[] = {
	0x2c01, 0x5802, 0x1c04, 0x3808, 0x7010,
	0x4c20, 0x3440, 0x6880, 0x7d00, 0x5600};

typedef struct {
    uint64_t syndrome; /* key */
    uint64_t error;
    UT_hash_handle hh;
} syndrome_struct;

static syndrome_struct *syndrome_map = NULL;

static void add_syndrome(uint64_t syndrome, uint64_t error)
{
	syndrome_struct *s;
	s = malloc(sizeof(syndrome_struct));
	s->syndrome = syndrome;
	s->error = error;

    HASH_ADD(hh, syndrome_map, syndrome, 8, s);
}

static syndrome_struct *find_syndrome(uint64_t syndrome)
{
    syndrome_struct *s;

    HASH_FIND(hh, syndrome_map, &syndrome, 8, s);
    return s;
}

static uint64_t gen_syndrome(uint64_t codeword)
{
	uint64_t syndrome = codeword & 0xffffffff;
	codeword >>= 32;
	syndrome ^= sw_check_table4[codeword & 0xff];
	codeword >>= 8;
	syndrome ^= sw_check_table5[codeword & 0xff];
	codeword >>= 8;
	syndrome ^= sw_check_table6[codeword & 0xff];
	codeword >>= 8;
	syndrome ^= sw_check_table7[codeword & 0xff];
	return syndrome;
}

static void cycle(uint64_t error, int start, int depth, uint64_t codeword)
{
	uint64_t new_error, syndrome, base;
	int i;
	base = 1;
	depth -= 1;
	for (i = start; i < 58; i++)
	{
		new_error = (base << i);
		new_error |= error;
		if (depth)
			cycle(new_error, i + 1, depth, codeword);
		else {
			syndrome = gen_syndrome(codeword ^ new_error);
			add_syndrome(syndrome, new_error);
		}
	}
}

static void gen_syndrome_map(int bit_errors)
{
	int i;
	for(i = 1; i <= bit_errors; i++)
		cycle(0, 0, i, DEFAULT_AC);
}

/* Generate Sync Word from an LAP */
uint64_t btbb_gen_syncword(const int LAP)
{
	int i;
	uint64_t codeword = DEFAULT_CODEWORD;

	/* the sync word generated is in host order, not air order */
	for (i = 0; i < 24; i++)
		if (LAP & (0x800000 >> i))
			codeword ^= sw_matrix[i];

	return codeword;
}

static void init_packet(btbb_packet *pkt, uint32_t lap, uint8_t ac_errors)
{
	pkt->LAP = lap;
	pkt->ac_errors = ac_errors;

	pkt->flags = 0;
	btbb_packet_set_flag(pkt, BTBB_WHITENED, 1);
}

/* Convert some number of bits of an air order array to a host order integer */
static uint8_t air_to_host8(const char *air_order, const int bits)
{
	int i;
	uint8_t host_order = 0;
	for (i = 0; i < bits; i++)
		host_order |= ((uint8_t)air_order[i] << i);
	return host_order;
}
static uint16_t air_to_host16(const char *air_order, const int bits)
{
	int i;
	uint16_t host_order = 0;
	for (i = 0; i < bits; i++)
		host_order |= ((uint16_t)air_order[i] << i);
	return host_order;
}
static uint32_t air_to_host32(const char *air_order, const int bits)
{
	int i;
	uint32_t host_order = 0;
	for (i = 0; i < bits; i++)
		host_order |= ((uint32_t)air_order[i] << i);
	return host_order;
}
static uint64_t air_to_host64(const char *air_order, const int bits)
{
	int i;
	uint64_t host_order = 0;
	for (i = 0; i < bits; i++)
		host_order |= ((uint64_t)air_order[i] << i);
	return host_order;
}

///* Convert some number of bits in a host order integer to an air order array */
//static void host_to_air(const uint8_t host_order, char *air_order, const int bits)
//{
//    int i;
//    for (i = 0; i < bits; i++)
//        air_order[i] = (host_order >> i) & 0x01;
//}

/* count the number of 1 bits in a uint64_t */
static uint8_t count_bits(uint64_t n)
{
#ifdef __GNUC__
	return (uint8_t) __builtin_popcountll (n);
#else
	uint8_t i = 0;
	for (i = 0; n != 0; i++)
		n &= n - 1;
	return i;
#endif
}

#ifndef RELEASE
#define RELEASE "unknown"
#endif
const char* btbb_get_release(void) {
	return RELEASE;
}

#ifndef VERSION
#define VERSION "unknown"
#endif
const char* btbb_get_version(void) {
	return VERSION;
}

int btbb_init(int max_ac_errors)
{
	/* Sanity check max_ac_errors. */
	if ( (max_ac_errors < 0) || (max_ac_errors > AC_ERROR_LIMIT) ) {
		fprintf(stderr, "%s: max_ac_errors out of range\n",
			__FUNCTION__);
		return -1;
	}

	if ((syndrome_map == NULL) && (max_ac_errors))
		gen_syndrome_map(max_ac_errors);

	return 0;
}

btbb_packet *
btbb_packet_new(void)
{
	btbb_packet *pkt = (btbb_packet *)calloc(1, sizeof(btbb_packet));
	if(pkt)
		pkt->refcount = 1;
	else
		fprintf(stderr, "Unable to allocate packet");
	return pkt;
}

void
btbb_packet_ref(btbb_packet *pkt)
{
	pkt->refcount++;
}

void
btbb_packet_unref(btbb_packet *pkt)
{
	pkt->refcount--;
	if (pkt->refcount == 0)
		free(pkt);
}

uint32_t btbb_packet_get_lap(const btbb_packet *pkt)
{
	return pkt->LAP;
}

void btbb_packet_set_uap(btbb_packet *pkt, uint8_t uap)
{
	pkt->UAP = uap;
	btbb_packet_set_flag(pkt, BTBB_UAP_VALID, 1);
}

uint8_t btbb_packet_get_uap(const btbb_packet *pkt)
{
	return pkt->UAP;
}

uint16_t btbb_packet_get_nap(const btbb_packet *pkt)
{
	return pkt->NAP;
}

uint32_t btbb_packet_get_clkn(const btbb_packet *pkt) {
	return pkt->clkn;
}

uint8_t btbb_packet_get_channel(const btbb_packet *pkt) {
	return pkt->channel;
}

void btbb_packet_set_modulation(btbb_packet *pkt, uint8_t modulation) {
	pkt->modulation = modulation;
}

uint8_t btbb_packet_get_modulation(const btbb_packet *pkt) {
	return pkt->modulation;
}

void btbb_packet_set_transport(btbb_packet *pkt, uint8_t transport) {
	pkt->transport = transport;
}

uint8_t btbb_packet_get_transport(const btbb_packet *pkt) {
	return pkt->transport;
}

uint8_t btbb_packet_get_ac_errors(const btbb_packet *pkt) {
	return pkt->ac_errors;
}

int promiscuous_packet_search(char *stream, int search_length, uint32_t *lap,
							  int max_ac_errors, uint8_t *ac_errors) {
	uint64_t syncword, codeword, syndrome, corrected_barker;
	syndrome_struct *errors;
	char *symbols;
	int count, offset = -1;

	/* Barker code at end of sync word (includes
	 * MSB of LAP) is used as a rough filter.
	 */
	uint8_t barker = air_to_host8(&stream[57], 6);
	barker <<= 1;

	for (count = 0; count < search_length; count++) {
		symbols = &stream[count];
		barker >>= 1;
		barker |= (symbols[63] << 6);
		if (BARKER_DISTANCE[barker] <= MAX_BARKER_ERRORS) {
			// Error correction
			syncword = air_to_host64(symbols, 64);

			/* correct the barker code with a simple comparison */
			corrected_barker = barker_correct[(uint8_t)(syncword >> 57)];
			syncword = (syncword & 0x01ffffffffffffffULL) | corrected_barker;

			codeword = syncword ^ pn;

			/* Zero syndrome -> good codeword. */
			syndrome = gen_syndrome(codeword);
			*ac_errors = 0;

			/* Try to fix errors in bad codeword. */
			if (syndrome) {
				errors = find_syndrome(syndrome);
				if (errors != NULL) {
					syncword ^= errors->error;
					*ac_errors = count_bits(errors->error);
					syndrome = 0;
				}
				else {
					*ac_errors = 0xff;  // fail
				}
			}

			if (*ac_errors <= max_ac_errors) {
				*lap = (syncword >> 34) & 0xffffff;
				offset = count;
				break;
			}
		}
	}
	return offset;
}

/* Matching a specific LAP */
int find_known_lap(char *stream, int search_length, uint32_t lap,
				   int max_ac_errors, uint8_t *ac_errors) {
	uint64_t syncword, ac;
	char *symbols;
	int count, offset = -1;

	ac = btbb_gen_syncword(lap);
	for (count = 0; count < search_length; count++) {
		symbols = &stream[count];
		syncword = air_to_host64(symbols, 64);
		*ac_errors = count_bits(syncword ^ ac);

		if (*ac_errors <= max_ac_errors) {
			offset = count;
			break;
		}
	}
	return offset;
}

/* Looks for an AC in the stream */
int btbb_find_ac(char *stream, int search_length, uint32_t lap,
				 int max_ac_errors, btbb_packet **pkt_ptr) {
	int offset;
	uint8_t ac_errors;

	/* Matching any LAP */
	if (lap == LAP_ANY)
		offset = promiscuous_packet_search(stream, search_length, &lap,
										   max_ac_errors, &ac_errors);
	else
		offset = find_known_lap(stream, search_length, lap,
								max_ac_errors, &ac_errors);

	if (offset >= 0) {
		if (*pkt_ptr == NULL)
			*pkt_ptr = btbb_packet_new();
		init_packet(*pkt_ptr, lap, ac_errors);
	}

	return offset;
}

/* Copy data (symbols) into packet and set rx data. */
void btbb_packet_set_data(btbb_packet *pkt, char *data, int length,
						  uint8_t channel, uint32_t clkn)
{
	int i;

	if (length > MAX_SYMBOLS)
		length = MAX_SYMBOLS;
	for (i = 0; i < length; i++)
		pkt->symbols[i] = data[i];

	pkt->length = length;
	pkt->channel = channel;
	pkt->clkn = clkn >> 1; // really CLK1
}

void btbb_packet_set_flag(btbb_packet *pkt, int flag, int val)
{
	uint32_t mask = 1L << flag;
	pkt->flags &= ~mask;
	if (val)
		pkt->flags |= mask;
}

int btbb_packet_get_flag(const btbb_packet *pkt, int flag)
{
	uint32_t mask = 1L << flag;
	return ((pkt->flags & mask) != 0);
}

const char *btbb_get_symbols(const btbb_packet* pkt)
{
	return (const char*) pkt->symbols;
}

int btbb_packet_get_payload_length(const btbb_packet* pkt)
{
	return pkt->payload_length;
}

const char *btbb_get_payload(const btbb_packet* pkt)
{
	return (const char*) pkt->payload;
}

int btbb_get_payload_packed(const btbb_packet* pkt, char *dst)
{
	int i;
	for(i=0;i<pkt->payload_length;i++)
		dst[i] = (char) air_to_host8(&pkt->payload[i*8], 8);
	return pkt->payload_length;
}

uint8_t btbb_packet_get_type(const btbb_packet* pkt)
{
	return pkt->packet_type;
}

uint8_t btbb_packet_get_lt_addr(const btbb_packet* pkt)
{
	return pkt->packet_lt_addr;
}

uint8_t btbb_packet_get_header_flags(const btbb_packet* pkt)
{
	return pkt->packet_flags;
}

uint8_t btbb_packet_get_hec(const btbb_packet* pkt)
{
	return pkt->packet_hec;
}

uint32_t btbb_packet_get_header_packed(const btbb_packet* pkt)
{
	return air_to_host32(&pkt->packet_header[0], 18);
}

/* Reverse the bits in a byte */
static uint8_t reverse(char byte)
{
	return (byte & 0x80) >> 7 | (byte & 0x40) >> 5 | (byte & 0x20) >> 3 | (byte & 0x10) >> 1 | (byte & 0x08) << 1 | (byte & 0x04) << 3 | (byte & 0x02) << 5 | (byte & 0x01) << 7;
}


/* Decode 1/3 rate FEC, three like symbols in a row */
static int unfec13(char *input, char *output, int length)
{
	int a, b, c, i;
	int be = 0; /* bit errors */

	for (i = 0; i < length; i++) {
		a = 3 * i;
		b = a + 1;
		c = a + 2;
		output[i] = ((input[a] & input[b]) | (input[b] & input[c]) |
				(input[c] & input[a]));
		be += ((input[a] ^ input[b]) | (input[b] ^ input[c]) |
				(input[c] ^ input[a]));
	}

	return (be < (length / 4));
}

/* encode 10 bits with 2/3 rate FEC code, a (15,10) shortened Hamming code */
static uint16_t fec23(uint16_t data)
{
	int i;
	uint16_t codeword = 0;

	/* host order, not air order */
	for (i = 0; i < 10; i++)
		if (data & (1 << i))
			codeword ^= fec23_gen_matrix[i];

	return codeword;
}

/* Decode 2/3 rate FEC, a (15,10) shortened Hamming code */
static char *unfec23(char *input, int length)
{
	/* input points to the input data
	 * length is length in bits of the data
	 * before it was encoded with fec2/3 */
	int iptr, optr, count;
	char* output;
	uint8_t diff, check;
	uint16_t data, codeword;

	diff = length % 10;
	// padding at end of data
	if(0!=diff)
		length += (10 - diff);

	output = (char *) malloc(length);

	for (iptr = 0, optr = 0; optr<length; iptr += 15, optr += 10) {
		// copy data to output
		for(count=0;count<10;count++)
			output[optr+count] = input[iptr+count];

		// grab data and error check in host format
		data = air_to_host16(input+iptr, 10);
		check = air_to_host8(input+iptr+10, 5);

		// call fec23 on data to generate the codeword
		codeword = fec23(data);
		diff = check ^ (codeword >> 10);

		/* no errors or single bit errors (errors in the parity bit):
		 * (a strong hint it's a real packet)
		 * Otherwise we need to corret the output*/
		if (diff & (diff - 1)) {
			switch (diff) {
			/* comments are the bit that's wrong and the value
			* of diff in air order, from the BT spec */
				// 1000000000 11010
				case 0x0b: output[optr] ^= 1; break;
				// 0100000000 01101
				case 0x16: output[optr+1] ^= 1; break;
				// 0010000000 11100
				case 0x07: output[optr+2] ^= 1; break;
				// 0001000000 01110
				case 0x0e: output[optr+3] ^= 1; break;
				// 0000100000 00111
				case 0x1c: output[optr+4] ^= 1; break;
				// 0000010000 11001
				case 0x13: output[optr+5] ^= 1; break;
				// 0000001000 10110
				case 0x0d: output[optr+6] ^= 1; break;
				// 0000000100 01011
				case 0x1a: output[optr+7] ^= 1; break;
				// 0000000010 11111
				case 0x1f: output[optr+8] ^= 1; break;
				// 0000000001 10101
				case 0x15: output[optr+9] ^= 1; break;
				/* not one of these errors, probably multiple bit errors
				* or maybe not a real packet, safe to drop it? */
				default: free(output); return 0;
			}
		}
	}
	return output;
}


/* Remove the whitening from an air order array */
static void unwhiten(char* input, char* output, int clock, int length, int skip, btbb_packet* pkt)
{
	int count, index;
	index = INDICES[clock & 0x3f];
	index += skip;
	index %= 127;

	for(count = 0; count < length; count++)
	{
		/* unwhiten if whitened, otherwise just copy input to output */
		output[count] = btbb_packet_get_flag(pkt, BTBB_WHITENED) ?
			input[count] ^ WHITENING_DATA[index] : input[count];
		index += 1;
		index %= 127;
	}
}

/* Pointer to start of packet, length of packet in bits, UAP */
static uint16_t crcgen(char *payload, int length, int UAP)
{
	char bit;
	uint16_t reg, count;

	reg = (reverse(UAP) << 8) & 0xff00;
	for(count = 0; count < length; count++)
	{
		bit = payload[count];

		reg = (reg >> 1) | (((reg & 0x0001) ^ (bit & 0x01))<<15);

		/*Bit 5*/
		reg ^= ((reg & 0x8000)>>5);

		/*Bit 12*/
		reg ^= ((reg & 0x8000)>>12);
	}
	return reg;
}

/* extract UAP by reversing the HEC computation */
static uint8_t uap_from_hec(uint16_t data, uint8_t hec)
{
        int i;

        for (i = 9; i >= 0; i--) {
                /* 0x65 is xor'd if MSB is 1, else 0x00 (which does nothing) */
                if (hec & 0x80)
                        hec ^= 0x65;

                hec = (hec << 1) | (((hec >> 7) ^ (data >> i)) & 0x01);
        }
        return reverse(hec);
}

/* check if the packet's CRC is correct for a given clock (CLK1-6) */
int crc_check(int clock, btbb_packet* pkt)
{
	/*
	 * return value of 1 represents inconclusive result (default)
	 * return value > 1 represents positive result (e.g. CRC match)
	 * return value of 0 represents negative result (e.g. CRC failure without
	 * the possibility that we have assumed the wrong logical transport)
	 */
	int retval = 1;

	switch(pkt->packet_type)
	{
		case PACKET_TYPE_FHS:
			retval = fhs(clock, pkt);
			break;

		case PACKET_TYPE_DV:
		case PACKET_TYPE_DM1:
		case PACKET_TYPE_DM3:
		case PACKET_TYPE_DM5:
			retval = DM(clock, pkt);
			break;

		case PACKET_TYPE_DH1:
		case PACKET_TYPE_DH3:
		case PACKET_TYPE_DH5:
			retval = DH(clock, pkt);
			break;

		case PACKET_TYPE_HV3: /* EV3 */
			retval = EV3(clock, pkt);
			break;
		case PACKET_TYPE_EV4:
			retval = EV4(clock, pkt);
			break;
		case PACKET_TYPE_EV5:
			retval = EV5(clock, pkt);
			break;

		case PACKET_TYPE_HV1:
			retval = HV(clock, pkt);
			break;

		/* some types can't help us */
		default:
			break;
	}
	/*
	 * never return a zero result unless this is a FHS, DM1, or HV1.  any
	 * other type could have actually been something else (another logical
	 * transport)
	 */
	if (retval == 0 && (pkt->packet_type != 2 && pkt->packet_type != 3 &&
			pkt->packet_type != 5))
		return 1;

	/* EV3 and EV5 have a relatively high false positive rate */
	if (retval > 1 && (pkt->packet_type == 7 || pkt->packet_type == 13))
		return 1;

	return retval;
}

/* verify the payload CRC */
static int payload_crc(btbb_packet* pkt)
{
	uint16_t crc;   /* CRC calculated from payload data */
	uint16_t check; /* CRC supplied by packet */

	crc = crcgen(pkt->payload, (pkt->payload_length - 2) * 8, pkt->UAP);
	check = air_to_host16(&pkt->payload[(pkt->payload_length - 2) * 8], 16);

	return (crc == check);
}

int fhs(int clock, btbb_packet* pkt)
{
	/* skip the access code and packet header */
	char *stream = pkt->symbols + 122;
	/* number of symbols remaining after access code and packet header */
	int size = pkt->length - 122;

	pkt->payload_length = 20;

	if (size < pkt->payload_length * 12)
		return 1; //FIXME should throw exception

	char *corrected = unfec23(stream, pkt->payload_length * 8);
	if (!corrected)
		return 0;

	/* try to unwhiten with known clock bits */
	unwhiten(corrected, pkt->payload, clock, pkt->payload_length * 8, 18, pkt);
	if (payload_crc(pkt)) {
		free(corrected);
		return 1000;
	}

	/* try all 32 possible X-input values instead */
	for (clock = 32; clock < 64; clock++) {
		unwhiten(corrected, pkt->payload, clock, pkt->payload_length * 8, 18, pkt);
		if (payload_crc(pkt)) {
			free(corrected);
			return 1000;
		}
	}

	/* failed to unwhiten */
	free(corrected);
	return 0;
}

/* decode payload header, return value indicates success */
static int decode_payload_header(char *stream, int clock, int header_bytes, int size, int fec, btbb_packet* pkt)
{
	if(header_bytes == 2)
	{
		if(size < 16)
			return 0; //FIXME should throw exception
		if(fec) {
			if(size < 30)
				return 0; //FIXME should throw exception
			char *corrected = unfec23(stream, 16);
			if (!corrected)
				return 0;
			unwhiten(corrected, pkt->payload_header, clock, 16, 18, pkt);
			free(corrected);
		} else {
			unwhiten(stream, pkt->payload_header, clock, 16, 18, pkt);
		}
		/* payload length is payload body length + 2 bytes payload header + 2 bytes CRC */
		pkt->payload_length = air_to_host16(&pkt->payload_header[3], 10) + 4;
	} else {
		if(size < 8)
			return 0; //FIXME should throw exception
		if(fec) {
			if(size < 15)
				return 0; //FIXME should throw exception
			char *corrected = unfec23(stream, 8);
			if (!corrected)
				return 0;
			unwhiten(corrected, pkt->payload_header, clock, 8, 18, pkt);
			free(corrected);
		} else {
			unwhiten(stream, pkt->payload_header, clock, 8, 18, pkt);
		}
		/* payload length is payload body length + 1 byte payload header + 2 bytes CRC */
		pkt->payload_length = air_to_host8(&pkt->payload_header[3], 5) + 3;
	}
	/* Try to set the max payload length to a sensible value,
	 * especially when using strange data
	 */
	int max_length = 0;
	switch(pkt->packet_type) {
		case PACKET_TYPE_DM1:
			max_length = 20;
			break;
		case PACKET_TYPE_DH1:
			/* assuming DH1 but could be 2-DH1 (58) */
			max_length = 30;
			break;
		case PACKET_TYPE_DV:
			/* assuming DV but could be 3-DH1 (87) */
			max_length = 12; /* + 10bytes of voice data */
			break;
		case PACKET_TYPE_DM3:
			/* assuming DM3 but could be 2-DH3 (371) */
			max_length = 125;
			break;
		case PACKET_TYPE_DH3:
			/* assuming DH3 but could be 3-DH3 (556) */
			max_length = 187;
			break;
		case PACKET_TYPE_DM5:
			/* assuming DM5 but could be 2-DH5 (683) */
			max_length = 228;
			break;
		case PACKET_TYPE_DH5:
			/* assuming DH5 but could be 3-DH5 (1025) */
			max_length = 343;
			break;
	}
	pkt->payload_length = MIN(pkt->payload_length, max_length);
	pkt->payload_llid = air_to_host8(&pkt->payload_header[0], 2);
	pkt->payload_flow = air_to_host8(&pkt->payload_header[2], 1);
	pkt->payload_header_length = header_bytes;
	return 1;
}

/* DM 1/3/5 packet (and DV)*/
int DM(int clock, btbb_packet* pkt)
{
	int bitlength;
	/* number of bytes in the payload header */
	int header_bytes = 2;
	/* maximum payload length */
	int max_length;
	/* skip the access code and packet header */
	char *stream = pkt->symbols + 122;
	/* number of symbols remaining after access code and packet header */
	int size = pkt->length - 122;

	switch(pkt->packet_type)
	{
		case PACKET_TYPE_DV:
			/* skip 80 voice bits, then treat the rest like a DM1 */
			stream += 80;
			size -= 80;
			header_bytes = 1;
			/* I don't think the length of the voice field ("synchronous data
			 * field") is included in the length indicated by the payload
			 * header in the data field ("asynchronous data field"), but I
			 * could be wrong.
			 */
			max_length = 12;
			break;
		case PACKET_TYPE_DM1:
			header_bytes = 1;
			max_length = 20;
			break;
		case PACKET_TYPE_DM3:
			max_length = 125;
			break;
		case PACKET_TYPE_DM5:
			max_length = 228;
			break;
		default: /* not a DM1/3/5 or DV */
			return 0;
	}
	if(!decode_payload_header(stream, clock, header_bytes, size, 1, pkt))
		return 0;
	/* check that the length indicated in the payload header is within spec */
	if(pkt->payload_length > max_length)
		/* could be encrypted */
		return 1;
	bitlength = pkt->payload_length*8;
	if(bitlength > size)
		return 1; //FIXME should throw exception

	char *corrected = unfec23(stream, bitlength);
	if (!corrected)
		return 0;
	unwhiten(corrected, pkt->payload, clock, bitlength, 18, pkt);
	free(corrected);

	if (payload_crc(pkt))
		return 10;

	/* could be encrypted */
	return 2;
}

/* DH 1/3/5 packet (and AUX1) */
/* similar to DM 1/3/5 but without FEC */
int DH(int clock, btbb_packet* pkt)
{
	int bitlength;
	/* number of bytes in the payload header */
	int header_bytes = 2;
	/* maximum payload length */
	int max_length;
	/* skip the access code and packet header */
	char *stream = pkt->symbols + 122;
	/* number of symbols remaining after access code and packet header */
	int size = pkt->length - 122;

	switch(pkt->packet_type)
	{
		case PACKET_TYPE_AUX1:
		case PACKET_TYPE_DH1:
			header_bytes = 1;
			max_length = 30;
			break;
		case PACKET_TYPE_DH3:
			max_length = 187;
			break;
		case PACKET_TYPE_DH5:
			max_length = 343;
			break;
		default: /* not a DH1/3/5 */
			return 0;
	}
	if(!decode_payload_header(stream, clock, header_bytes, size, 0, pkt))
		return 0;
	/* check that the length indicated in the payload header is within spec */
	if(pkt->payload_length > max_length)
		/* could be encrypted */
		return 1;
	bitlength = pkt->payload_length*8;
	if(bitlength > size)
		return 1; //FIXME should throw exception

	unwhiten(stream, pkt->payload, clock, bitlength, 18, pkt);

	/* AUX1 has no CRC */
	if (pkt->packet_type == 9)
		return 2;

	if (payload_crc(pkt))
		return 10;

	/* could be encrypted */
	return 2;
}

int EV3(int clock, btbb_packet* pkt)
{
	/* skip the access code and packet header */
	char *stream = pkt->symbols + 122;

	/* number of symbols remaining after access code and packet header */
	int size = pkt->length - 122;

	/* maximum payload length is 30 bytes + 2 bytes CRC */
	int maxlength = 32;

	/* number of bits we have decoded */
	int bits;

	/* check CRC for any integer byte length up to maxlength */
	for (pkt->payload_length = 0;
			pkt->payload_length < maxlength; pkt->payload_length++) {

		bits = pkt->payload_length * 8;

		/* unwhiten next byte */
		if ((bits + 8) > size)
			return 1; //FIXME should throw exception
		unwhiten(stream, pkt->payload + bits, clock, 8, 18 + bits, pkt);

		if ((pkt->payload_length > 2) && (payload_crc(pkt)))
				return 10;
	}
	return 2;
}

int EV4(int clock, btbb_packet* pkt)
{
	char *corrected;

	/* skip the access code and packet header */
	char *stream = pkt->symbols + 122;

	/* number of symbols remaining after access code and packet header */
	int size = pkt->length - 122;

	/*
	 * maximum payload length is 120 bytes + 2 bytes CRC
	 * after FEC2/3, this results in a maximum of 1470 symbols
	 */
	int maxlength = 1470;

	/*
	 * minumum payload length is 1 bytes + 2 bytes CRC
	 * after FEC2/3, this results in a minimum of 45 symbols
	 */
	int minlength = 45;

	int syms = 0; /* number of symbols we have decoded */
	int bits = 0; /* number of payload bits we have decoded */

	pkt->payload_length = 1;

	while (syms < maxlength) {

		/* unfec/unwhiten next block (15 symbols -> 10 bits) */
		if (syms + 15 > size)
			return 1; //FIXME should throw exception
		corrected = unfec23(stream + syms, 10);
		if (!corrected) {
			free(corrected);
			if (syms < minlength)
				return 0;
			else
				return 1;
		}
		unwhiten(corrected, pkt->payload + bits, clock, 10, 18 + bits, pkt);
		free(corrected);

		/* check CRC one byte at a time */
		while (pkt->payload_length * 8 <= bits) {
			if (payload_crc(pkt))
				return 10;
			pkt->payload_length++;
		}
		syms += 15;
		bits += 10;
	}
	return 2;
}

int EV5(int clock, btbb_packet* pkt)
{
	/* skip the access code and packet header */
	char *stream = pkt->symbols + 122;

	/* number of symbols remaining after access code and packet header */
	int size = pkt->length - 122;

	/* maximum payload length is 180 bytes + 2 bytes CRC */
	int maxlength = 182;

	/* number of bits we have decoded */
	int bits;

	/* check CRC for any integer byte length up to maxlength */
	for (pkt->payload_length = 0;
			pkt->payload_length < maxlength; pkt->payload_length++) {

		bits = pkt->payload_length * 8;

		/* unwhiten next byte */
		if ((bits + 8) > size)
			return 1; //FIXME should throw exception
		unwhiten(stream, pkt->payload + bits, clock, 8, 18 + bits, pkt);

		if ((pkt->payload_length > 2) && (payload_crc(pkt)))
				return 10;
	}
	return 2;
}

/* HV packet type payload parser */
int HV(int clock, btbb_packet* pkt)
{
	/* skip the access code and packet header */
	char *stream = pkt->symbols + 122;
	/* number of symbols remaining after access code and packet header */
	int size = pkt->length - 122;

	pkt->payload_header_length = 0;
	if(size < 240) {
		pkt->payload_length = 0;
		return 1; //FIXME should throw exception
	}

	switch (pkt->packet_type) {
		case PACKET_TYPE_HV1:
			{
			char corrected[80];
			if (!unfec13(stream, corrected, 80))
				return 0;
			pkt->payload_length = 10;
			btbb_packet_set_flag(pkt, BTBB_HAS_PAYLOAD, 1);
			unwhiten(corrected, pkt->payload, clock, pkt->payload_length*8, 18, pkt);
			}
			break;
		case PACKET_TYPE_HV2:
			{
			char *corrected = unfec23(stream, 160);
			if (!corrected)
				return 0;
			pkt->payload_length = 20;
			btbb_packet_set_flag(pkt, BTBB_HAS_PAYLOAD, 1);
			unwhiten(corrected, pkt->payload, clock, pkt->payload_length*8, 18, pkt);
			free(corrected);
			}
			break;
		case PACKET_TYPE_HV3:
			pkt->payload_length = 30;
			btbb_packet_set_flag(pkt, BTBB_HAS_PAYLOAD, 1);
			unwhiten(stream, pkt->payload, clock, pkt->payload_length*8, 18, pkt);
			break;
	}

	return 2;
}
/* try a clock value (CLK1-6) to unwhiten packet header,
 * sets resultant p->packet_type and p->UAP, returns UAP.
 */
uint8_t try_clock(int clock, btbb_packet* pkt)
{
	/* skip 72 bit access code */
	char *stream = pkt->symbols + 68;
	/* 18 bit packet header */
	char header[18];
	char unwhitened[18];

	if (!unfec13(stream, header, 18))
		return 0;
	unwhiten(header, unwhitened, clock, 18, 0, pkt);
	uint16_t hdr_data = air_to_host16(unwhitened, 10);
	uint8_t hec = air_to_host8(&unwhitened[10], 8);
	pkt->UAP = uap_from_hec(hdr_data, hec);
	pkt->packet_type = air_to_host8(&unwhitened[3], 4);

	return pkt->UAP;
}

/* decode the packet header */
int btbb_decode_header(btbb_packet* pkt)
{
	/* skip 72 bit access code */
	char *stream = pkt->symbols + 68;
	/* 18 bit packet header */
	char header[18];
	uint8_t UAP;

	if (btbb_packet_get_flag(pkt, BTBB_CLK6_VALID) && unfec13(stream, header, 18)) {
		unwhiten(header, pkt->packet_header, pkt->clkn, 18, 0, pkt);
		uint16_t hdr_data = air_to_host16(pkt->packet_header, 10);
		uint8_t hec = air_to_host8(&pkt->packet_header[10], 8);
		UAP = uap_from_hec(hdr_data, hec);
		if (UAP == pkt->UAP) {
			pkt->packet_lt_addr = air_to_host8(&pkt->packet_header[0], 3);
			pkt->packet_type = air_to_host8(&pkt->packet_header[3], 4);
			pkt->packet_flags = air_to_host8(&pkt->packet_header[7], 3);
			pkt->packet_hec = hec;
			return 1;
		}
	}

	return 0;
}

int btbb_decode_payload(btbb_packet* pkt)
{
	int rv = 0;
	pkt->payload_header_length = 0;

	switch(pkt->packet_type)
	{
		case PACKET_TYPE_NULL:
			/* no payload to decode */
			pkt->payload_length = 0;
			rv = 1;
			break;
		case PACKET_TYPE_POLL:
			/* no payload to decode */
			pkt->payload_length = 0;
			rv = 1;
			break;
		case PACKET_TYPE_FHS:
			rv = fhs(pkt->clkn, pkt);
			break;
		case PACKET_TYPE_DM1:
			rv = DM(pkt->clkn, pkt);
			break;
		case PACKET_TYPE_DH1:
			/* assuming DH1 but could be 2-DH1 */
			rv = DH(pkt->clkn, pkt);
			break;
		case PACKET_TYPE_HV1:
			rv = HV(pkt->clkn, pkt);
			break;
		case PACKET_TYPE_HV2:
			rv = HV(pkt->clkn, pkt);
			break;
		case PACKET_TYPE_HV3: /* HV3/EV3/3-EV3 */
			/* decode as EV3 if CRC checks out */
			if ((rv = EV3(pkt->clkn, pkt)) <= 1)
				/* otherwise assume HV3 */
				rv = HV(pkt->clkn, pkt);
			/* don't know how to decode 3-EV3 */
			break;
		case PACKET_TYPE_DV:
			/* assuming DV but could be 3-DH1 */
			rv = DM(pkt->clkn, pkt);
			break;
		case PACKET_TYPE_AUX1:
			rv = DH(pkt->clkn, pkt);
			break;
		case PACKET_TYPE_DM3:
			/* assuming DM3 but could be 2-DH3 */
			rv = DM(pkt->clkn, pkt);
			break;
		case PACKET_TYPE_DH3:
			/* assuming DH3 but could be 3-DH3 */
			rv = DH(pkt->clkn, pkt);
			break;
		case PACKET_TYPE_EV4:
			/* assuming EV4 but could be 2-EV5 */
			rv = EV4(pkt->clkn, pkt);
			break;
		case PACKET_TYPE_EV5:
			/* assuming EV5 but could be 3-EV5 */
			rv = EV5(pkt->clkn, pkt);
			break;
		case PACKET_TYPE_DM5:
			/* assuming DM5 but could be 2-DH5 */
			rv = DM(pkt->clkn, pkt);
			break;
		case PACKET_TYPE_DH5:
			/* assuming DH5 but could be 3-DH5 */
			rv = DH(pkt->clkn, pkt);
			break;
	}
	btbb_packet_set_flag(pkt, BTBB_HAS_PAYLOAD, 1);
	return rv;
}

/* decode the whole packet */
int btbb_decode(btbb_packet* pkt)
{
	int rv = 0;

	btbb_packet_set_flag(pkt, BTBB_HAS_PAYLOAD, 0);

	if (btbb_decode_header(pkt)) {
		rv =  btbb_decode_payload(pkt);
	}

	/* If we were successful, print the packet */
	if(rv > 0) {
		printf("Packet decoded with clock 0x%02x (rv=%d)\n", pkt->clkn & 0x3f, rv);
		btbb_print_packet(pkt);
	}

	return rv;
}

/* print packet information */
void btbb_print_packet(const btbb_packet* pkt)
{
	if (btbb_packet_get_flag(pkt, BTBB_HAS_PAYLOAD)) {
		printf("  Type: %s\n", TYPE_NAMES[pkt->packet_type]);
		if (pkt->payload_header_length > 0) {
			printf("  LT_ADDR: %d\n", pkt->packet_lt_addr);
			printf("  LLID: %d\n", pkt->payload_llid);
			printf("  flow: %d\n", pkt->payload_flow);
			printf("  payload length: %d\n", pkt->payload_length);
		}
		if (pkt->payload_length) {
			printf("  Data: ");
			int i;
			for(i=0; i<pkt->payload_length; i++)
				printf(" %02x", air_to_host8(pkt->payload + 8*i, 8));
			printf("\n");
		}
	}
}

char *tun_format(btbb_packet* pkt)
{
	/* include 6 bytes for meta data, 3 bytes for packet header */
	int length = 9 + pkt->payload_length;
	char *tun_format = (char *) malloc(length);
	int i;

	/* meta data */
	tun_format[0] = pkt->clkn & 0xff;
	tun_format[1] = (pkt->clkn >> 8) & 0xff;
	tun_format[2] = (pkt->clkn >> 16) & 0xff;
	tun_format[3] = (pkt->clkn >> 24) & 0xff;
	tun_format[4] = pkt->channel;
	tun_format[5] = btbb_packet_get_flag(pkt, BTBB_CLK27_VALID) |
		(btbb_packet_get_flag(pkt, BTBB_NAP_VALID) << 1);

	/* packet header modified to fit byte boundaries */
	/* lt_addr and type */
	tun_format[6] = (char) air_to_host8(&pkt->packet_header[0], 7);
	/* flags */
	tun_format[7] = (char) air_to_host8(&pkt->packet_header[7], 3);
	/* HEC */
	tun_format[8] = (char) air_to_host8(&pkt->packet_header[10], 8);

	for(i=0;i<pkt->payload_length;i++)
		tun_format[i+9] = (char) air_to_host8(&pkt->payload[i*8], 8);

	return tun_format;
}

/* check to see if the packet has a header */
int btbb_header_present(const btbb_packet* pkt)
{
	/* skip to last bit of sync word */
	const char *stream = pkt->symbols + 63;
	int be = 0; /* bit errors */
	char msb;   /* most significant (last) bit of sync word */
	int a, b, c;

	/* check that we have enough symbols */
	if (pkt->length < 122)
		return 0;

	/* check that the AC trailer is correct */
	msb = stream[0];
	be += stream[1] ^ !msb;
	be += stream[2] ^ msb;
	be += stream[3] ^ !msb;
	be += stream[4] ^ msb;

	/*
	 * Each bit of the 18 bit header is repeated three times.  Without
	 * checking the correctness of any particular bit, just count the
	 * number of times three symbols in a row don't all agree.
	 */
	stream += 5;
	for (a = 0; a < 54; a += 3) {
		b = a + 1;
		c = a + 2;
		be += ((stream[a] ^ stream[b]) |
			(stream[b] ^ stream[c]) | (stream[c] ^ stream[a]));
	}

	/*
	 * Few bit errors indicates presence of a header.  Many bit errors
	 * indicates no header is present (i.e. it is an ID packet).
	 */
	return (be < ID_THRESHOLD);
}

/* extract LAP from FHS payload */
uint32_t lap_from_fhs(btbb_packet* pkt)
{
	/* caller should check got_payload() and get_type() */
	return air_to_host32(&pkt->payload[34], 24);
}

/* extract UAP from FHS payload */
uint8_t uap_from_fhs(btbb_packet* pkt)
{
	/* caller should check got_payload() and get_type() */
	return air_to_host8(&pkt->payload[64], 8);
}

/* extract NAP from FHS payload */
uint16_t nap_from_fhs(btbb_packet* pkt)
{
	/* caller should check got_payload() and get_type() */
	return air_to_host16(&pkt->payload[72], 16);
}

/* extract clock from FHS payload */
uint32_t clock_from_fhs(btbb_packet* pkt)
{
	/*
	 * caller should check got_payload() and get_type()
	 *
	 * This is CLK2-27 (units of 1.25 ms).
	 * CLK0 and CLK1 are implicitly zero.
	 */
	return air_to_host32(&pkt->payload[115], 26);
}
