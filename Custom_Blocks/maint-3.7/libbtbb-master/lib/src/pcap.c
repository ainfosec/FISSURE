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
#include "bluetooth_le_packet.h"
#include "bluetooth_packet.h"
#include "btbb.h"
#include "pcap-common.h"

#include <stdlib.h>
#include <string.h>
#include <assert.h>

typedef enum {
	PCAP_OK = 0,
	PCAP_INVALID_HANDLE,
	PCAP_FILE_NOT_ALLOWED,
	PCAP_NO_MEMORY,
} PCAP_RESULT;

typedef struct __attribute__((packed)) pcap_hdr_s {
	uint32_t magic_number;   /* magic number */
	uint16_t version_major;  /* major version number */
	uint16_t version_minor;  /* minor version number */
	int32_t  thiszone;       /* GMT to local correction */
	uint32_t sigfigs;        /* accuracy of timestamps */
	uint32_t snaplen;        /* max length of captured packets, in octets */
	uint32_t network;        /* data link type */
} pcap_hdr_t;

FILE *btbb_pcap_open(const char *filename, uint32_t dlt, uint32_t snaplen) {
	pcap_hdr_t pcap_header = {
		.magic_number = 0xa1b23c4d,
		.version_major = 2,
		.version_minor = 4,
		.thiszone = 0,
		.sigfigs = 0,
		.snaplen = snaplen,
		.network = dlt,
	};

	FILE *pcap_file = fopen(filename, "w");
	if (pcap_file == NULL) return NULL;

	fwrite(&pcap_header, sizeof(pcap_header), 1, pcap_file);

	return pcap_file;
}

/* BT BR/EDR support */

struct btbb_pcap_handle {
	FILE *pcap_file;
};

int 
btbb_pcap_create_file(const char *filename, btbb_pcap_handle ** ph)
{
	int retval = 0;
	btbb_pcap_handle * handle = malloc( sizeof(btbb_pcap_handle) );
	if (handle) {
		memset(handle, 0, sizeof(*handle));
		handle->pcap_file = btbb_pcap_open(filename, DLT_BLUETOOTH_BREDR_BB,
											BREDR_MAX_PAYLOAD);
		if (handle->pcap_file) {
			*ph = handle;
		}
		else {
			perror("PCAP error:");
			retval = -PCAP_FILE_NOT_ALLOWED;
			goto fail;
		}
	}
	else {
		retval = -PCAP_NO_MEMORY;
		goto fail;
	}
	return retval;
fail:
	(void) btbb_pcap_close( handle );
	return retval;
}

typedef struct __attribute__((packed)) pcaprec_hdr_s {
	uint32_t ts_sec;         /* timestamp seconds */
	uint32_t ts_usec;        /* timestamp microseconds */
	uint32_t incl_len;       /* number of octets of packet saved in file */
	uint32_t orig_len;       /* actual length of packet */
} pcaprec_hdr_t;

typedef struct {
	pcaprec_hdr_t pcap_header;
	pcap_bluetooth_bredr_bb_header bredr_bb_header;
} pcap_bredr_packet;

void btbb_pcap_dump(FILE *file, pcaprec_hdr_t *pcap_header, u_char *data) {
	fwrite(pcap_header, sizeof(*pcap_header), 1, file);
	fwrite(data, pcap_header->incl_len, 1, file);
	fflush(file);
}

static void
assemble_pcapng_bredr_packet( pcap_bredr_packet * pkt,
			      const uint32_t interface_id __attribute__((unused)),
			      const uint64_t ns,
			      const uint32_t caplen,
			      const uint8_t rf_channel,
			      const int8_t signal_power,
			      const int8_t noise_power,
			      const uint8_t access_code_offenses,
			      const uint8_t payload_transport,
			      const uint8_t payload_rate,
			      const uint8_t corrected_header_bits,
			      const int16_t corrected_payload_bits,
			      const uint32_t lap,
			      const uint32_t ref_lap,
			      const uint8_t ref_uap,
			      const uint32_t bt_header,
			      const uint16_t flags,
			      const uint8_t * payload )
{
	uint32_t pcap_caplen = sizeof(pcap_bluetooth_bredr_bb_header) -
				sizeof(pkt->bredr_bb_header.bredr_payload) 
				+ caplen;
	uint32_t reflapuap = (ref_lap&0xffffff) | (ref_uap<<24);

	pkt->pcap_header.ts_sec  = ns / 1000000000ull;
	pkt->pcap_header.ts_usec = ns % 1000000000ull;
	pkt->pcap_header.incl_len = pcap_caplen;
	pkt->pcap_header.orig_len = pcap_caplen;

	pkt->bredr_bb_header.rf_channel = rf_channel;
	pkt->bredr_bb_header.signal_power = signal_power;
	pkt->bredr_bb_header.noise_power = noise_power;
	pkt->bredr_bb_header.access_code_offenses = access_code_offenses;
	pkt->bredr_bb_header.payload_transport_rate =
		(payload_transport << 4) | payload_rate;
	pkt->bredr_bb_header.corrected_header_bits = corrected_header_bits; 
	pkt->bredr_bb_header.corrected_payload_bits = htole16( corrected_payload_bits );
	pkt->bredr_bb_header.lap = htole32( lap );
	pkt->bredr_bb_header.ref_lap_uap = htole32( reflapuap );
	pkt->bredr_bb_header.bt_header = htole32( bt_header ); 
	pkt->bredr_bb_header.flags = htole16( flags );
	if (caplen) {
		assert(caplen <= sizeof(pkt->bredr_bb_header.bredr_payload)); // caller ensures this, but to be safe..
		(void) memcpy( &pkt->bredr_bb_header.bredr_payload[0], payload, caplen );
		pkt->bredr_bb_header.flags |= htole16( BREDR_PAYLOAD_PRESENT );
	}
	else {
		pkt->bredr_bb_header.flags &= htole16( ~BREDR_PAYLOAD_PRESENT );
	}
}

int 
btbb_pcap_append_packet(btbb_pcap_handle * h, const uint64_t ns, 
			const int8_t sigdbm, const int8_t noisedbm,
			const uint32_t reflap, const uint8_t refuap, 
			const btbb_packet *pkt)
{
	if (h && h->pcap_file) {
		uint16_t flags = BREDR_DEWHITENED | BREDR_SIGPOWER_VALID |
			((noisedbm < sigdbm) ? BREDR_NOISEPOWER_VALID : 0) |
			((reflap != LAP_ANY) ? BREDR_REFLAP_VALID : 0) |
			((refuap != UAP_ANY) ? BREDR_REFUAP_VALID : 0);
		uint32_t caplen = (uint32_t) btbb_packet_get_payload_length(pkt);
		uint8_t payload_bytes[caplen];
		btbb_get_payload_packed( pkt, (char *) &payload_bytes[0] );
		caplen = MIN(BREDR_MAX_PAYLOAD, caplen);
		pcap_bredr_packet pcap_pkt;
		assemble_pcapng_bredr_packet( &pcap_pkt,
					      0,
					      ns,
					      caplen,
					      btbb_packet_get_channel(pkt),
					      sigdbm,
					      noisedbm,
					      btbb_packet_get_ac_errors(pkt),
						  btbb_packet_get_transport(pkt),
						  btbb_packet_get_modulation(pkt),
					      0, /* TODO: corrected header bits */
					      0, /* TODO: corrected payload bits */
					      btbb_packet_get_lap(pkt),
					      reflap,
					      refuap,
					      btbb_packet_get_header_packed(pkt),
					      flags,
					      payload_bytes );
		btbb_pcap_dump(h->pcap_file, &pcap_pkt.pcap_header, (u_char *)&pcap_pkt.bredr_bb_header);
		return 0;
	}
	return -PCAP_INVALID_HANDLE;
}

int 
btbb_pcap_close(btbb_pcap_handle * h)
{
	if (h && h->pcap_file) {
		fclose(h->pcap_file);
	}
	if (h) {
		free(h);
		return 0;
	}
	return -PCAP_INVALID_HANDLE;
}

/* BTLE support */

struct lell_pcap_handle {
	FILE *pcap_file;
	int dlt;
	uint8_t btle_ppi_version;
};

static int
lell_pcap_create_file_dlt(const char *filename, int dlt, lell_pcap_handle ** ph)
{
	int retval = 0;
	lell_pcap_handle * handle = malloc( sizeof(lell_pcap_handle) );
	if (handle) {
		memset(handle, 0, sizeof(*handle));
		handle->pcap_file = btbb_pcap_open(filename, dlt, BREDR_MAX_PAYLOAD);
		if (handle->pcap_file) {
			handle->dlt = dlt;
			*ph = handle;
		}
		else {
			retval = -PCAP_FILE_NOT_ALLOWED;
			goto fail;
		}
	}
	else {
		retval = -PCAP_NO_MEMORY;
		goto fail;
	}
	return retval;
fail:
	(void) lell_pcap_close( handle );
	return retval;
}

int 
lell_pcap_create_file(const char *filename, lell_pcap_handle ** ph)
{
	return lell_pcap_create_file_dlt(filename, DLT_BLUETOOTH_LE_LL_WITH_PHDR, ph);
}

int 
lell_pcap_ppi_create_file(const char *filename, int btle_ppi_version, 
			  lell_pcap_handle ** ph)
{
	int retval = lell_pcap_create_file_dlt(filename, DLT_PPI, ph);
	if (!retval) {
		(*ph)->btle_ppi_version = btle_ppi_version;
	}
	return retval;
}

typedef struct {
	pcaprec_hdr_t pcap_header;
	pcap_bluetooth_le_ll_header le_ll_header;
	uint8_t le_packet[LE_MAX_PAYLOAD];
} pcap_le_packet;

static void
assemble_pcapng_le_packet( pcap_le_packet * pkt,
			   const uint32_t interface_id __attribute__((unused)),
			   const uint64_t ns,
			   const uint32_t caplen,
			   const uint8_t rf_channel,
			   const int8_t signal_power,
			   const int8_t noise_power,
			   const uint8_t access_address_offenses,
			   const uint32_t ref_access_address,
			   const uint16_t flags,
			   const uint8_t * lepkt )
{
	uint32_t incl_len = MIN(LE_MAX_PAYLOAD, caplen);

	pkt->pcap_header.ts_sec  = ns / 1000000000ull;
	pkt->pcap_header.ts_usec = ns % 1000000000ull;
	pkt->pcap_header.incl_len = sizeof(pcap_bluetooth_le_ll_header)+caplen;
	pkt->pcap_header.orig_len = sizeof(pcap_bluetooth_le_ll_header)+incl_len;

	pkt->le_ll_header.rf_channel = rf_channel;
	pkt->le_ll_header.signal_power = signal_power;
	pkt->le_ll_header.noise_power = noise_power;
	pkt->le_ll_header.access_address_offenses = access_address_offenses;
	pkt->le_ll_header.ref_access_address = htole32( ref_access_address );
	pkt->le_ll_header.flags = htole16( flags );
	(void) memcpy( &pkt->le_packet[0], lepkt, incl_len );
}

int 
lell_pcap_append_packet(lell_pcap_handle * h, const uint64_t ns,
			const int8_t sigdbm, const int8_t noisedbm,
			const uint32_t refAA, const lell_packet *pkt)
{
	if (h && h->pcap_file &&
	    (h->dlt == DLT_BLUETOOTH_LE_LL_WITH_PHDR)) {
		uint16_t flags = LE_DEWHITENED | LE_AA_OFFENSES_VALID |
			LE_SIGPOWER_VALID |
			((noisedbm < sigdbm) ? LE_NOISEPOWER_VALID : 0) |
			(lell_packet_is_data(pkt) ? 0 : LE_REF_AA_VALID);
		pcap_le_packet pcap_pkt;
		assemble_pcapng_le_packet( &pcap_pkt,
					   0,
					   ns,
					   pkt->length + 4 + 2 + 3, // AA + header + CRC
					   pkt->channel_k,
					   sigdbm,
					   noisedbm,
					   pkt->access_address_offenses,
					   refAA,
					   flags,
					   &pkt->symbols[0] );
		btbb_pcap_dump(h->pcap_file, &pcap_pkt.pcap_header, (u_char *)&pcap_pkt.le_ll_header);
		return 0;
	}
	return -PCAP_INVALID_HANDLE;
}

#define PPI_BTLE 30006

typedef struct __attribute__((packed)) {
	uint8_t pph_version;
	uint8_t pph_flags;
	uint16_t pph_len;
	uint32_t pph_dlt;
} ppi_packet_header_t;

typedef struct __attribute__((packed)) {
	uint16_t pfh_type;
	uint16_t pfh_datalen;
} ppi_fieldheader_t;

typedef struct __attribute__((packed)) {
	uint8_t btle_version;
	uint16_t btle_channel;
	uint8_t btle_clkn_high;
	uint32_t btle_clk100ns;
	int8_t rssi_max;
	int8_t rssi_min;
	int8_t rssi_avg;
	uint8_t rssi_count;
} ppi_btle_t;

typedef struct __attribute__((packed)) {
	pcaprec_hdr_t pcap_header;
        ppi_packet_header_t ppi_packet_header;
	ppi_fieldheader_t ppi_fieldheader;
	ppi_btle_t le_ll_ppi_header;
	uint8_t le_packet[LE_MAX_PAYLOAD];
} pcap_ppi_le_packet;

int 
lell_pcap_append_ppi_packet(lell_pcap_handle * h, const uint64_t ns,
			    const uint8_t clkn_high,
			    const int8_t rssi_min, const int8_t rssi_max,
			    const int8_t rssi_avg, const uint8_t rssi_count,
			    const lell_packet *pkt)
{
	if (h && h->pcap_file &&
	    (h->dlt == DLT_PPI)) {
		pcap_ppi_le_packet pcap_pkt;
		const uint16_t pcap_headerlen =
			sizeof(ppi_packet_header_t) +
			sizeof(ppi_fieldheader_t) +
			sizeof(ppi_btle_t);
		uint16_t MHz = 2402 + 2*lell_get_channel_k(pkt);
		unsigned packet_len = pkt->length + 4 + 2 + 3; // AA + header + CRC
		unsigned incl_len   = MIN(LE_MAX_PAYLOAD, packet_len);

		pcap_pkt.pcap_header.ts_sec  = ns / 1000000000ull;
		pcap_pkt.pcap_header.ts_usec = ns % 1000000000ull;
		pcap_pkt.pcap_header.incl_len = pcap_headerlen + incl_len;
		pcap_pkt.pcap_header.orig_len = pcap_headerlen + packet_len;

		pcap_pkt.ppi_packet_header.pph_version = 0;
		pcap_pkt.ppi_packet_header.pph_flags = 0;
		pcap_pkt.ppi_packet_header.pph_len = htole16(pcap_headerlen);
		pcap_pkt.ppi_packet_header.pph_dlt = htole32(DLT_USER0);

		pcap_pkt.ppi_fieldheader.pfh_type = htole16(PPI_BTLE);
		pcap_pkt.ppi_fieldheader.pfh_datalen = htole16(sizeof(ppi_btle_t));
	
		pcap_pkt.le_ll_ppi_header.btle_version = h->btle_ppi_version;
		pcap_pkt.le_ll_ppi_header.btle_channel = htole16(MHz);
		pcap_pkt.le_ll_ppi_header.btle_clkn_high = clkn_high;
		pcap_pkt.le_ll_ppi_header.btle_clk100ns = htole32(pkt->clk100ns);
		pcap_pkt.le_ll_ppi_header.rssi_max = rssi_max;
		pcap_pkt.le_ll_ppi_header.rssi_min = rssi_min;
		pcap_pkt.le_ll_ppi_header.rssi_avg = rssi_avg;
		pcap_pkt.le_ll_ppi_header.rssi_count = rssi_count;
		(void) memcpy( &pcap_pkt.le_packet[0], &pkt->symbols[0], incl_len);
		btbb_pcap_dump(h->pcap_file, &pcap_pkt.pcap_header, (u_char *)&pcap_pkt.ppi_packet_header);
		return 0;
	}
	return -PCAP_INVALID_HANDLE;
}

int 
lell_pcap_close(lell_pcap_handle *h)
{
	if (h && h->pcap_file) {
		fclose(h->pcap_file);
	}
	if (h) {
		free(h);
		return 0;
	}
	return -PCAP_INVALID_HANDLE;
}
