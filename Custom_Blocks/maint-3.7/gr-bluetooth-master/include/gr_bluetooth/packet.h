/* -*- c++ -*- */
/* 
 * Copyright 2013 Christopher D. Kilgour
 * Copyright 2008, 2009 Dominic Spill, Michael Ossmann
 * Copyright 2007 Dominic Spill
 * Copyright 2005, 2006 Free Software Foundation, Inc.
 * 
 * This file is part of gr-bluetooth
 * 
 * This is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 * 
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this software; see the file COPYING.  If not, write to
 * the Free Software Foundation, Inc., 51 Franklin Street,
 * Boston, MA 02110-1301, USA.
 */


#ifndef INCLUDED_GR_BLUETOOTH_PACKET_H
#define INCLUDED_GR_BLUETOOTH_PACKET_H

#include <gr_bluetooth/api.h>
#include <gnuradio/sync_block.h>
#include <string>

namespace gr {
  namespace bluetooth {

    class GR_BLUETOOTH_API packet
    {
      friend class classic_packet;
      friend class classic_packet_impl;
      friend class le_packet;
      friend class le_packet_impl;
      
    public:
      typedef enum {
        UNKNOWN = 0,
        CLASSIC,
        LOW_ENERGY,
        NUM_BTAF
      } air_format;

      typedef boost::shared_ptr<packet> sptr;

    private:
      air_format d_format;
      double     d_freq;
      int        d_length;       /* number of symbols */

      static const int MAX_SYMBOLS = 3125;       /* maximum number of symbols */

      /* the raw symbol stream, one bit per char */
      //FIXME maybe this should be a vector so we can grow it only to the size
      //needed and later shrink it if we find we have more symbols than necessary
      char d_symbols[MAX_SYMBOLS];
      
      /* packet type */
      int d_packet_type;

      /* payload length: the total length of the asynchronous data in bytes.
       * This does not include the length of synchronous data, such as the voice
       * field of a DV packet.
       * If there is a payload header, this payload length is payload body length
       * (the length indicated in the payload header's length field) plus
       * d_payload_header_length plus 2 bytes CRC (if present).
       */
      int d_payload_length;

      /* The actual payload data in host format
       * Ready for passing to wireshark
       * 2744 is the maximum length, but most packets are shorter.
       * Dynamic allocation would probably be better in the long run but is
       * problematic in the short run.
       */
      char d_payload[2744];
      
      /* is the packet whitened? */
      bool d_whitened;

      bool d_have_payload;

    public:
      // -------------------------------------------------------------------

      packet() {}
      packet(char *stream, int length, double freq=0.0);
      virtual ~packet( ) {}

      // -------------------------------------------------------------------

      /* whitening data, both classic and LE use the same whitening LFSR */
      static const uint8_t WHITENING_DATA[127];

      static int sniff_packet(char *stream, int stream_length, double freq, air_format& fmt);

      /* Reverse the bits in a byte */
      static uint8_t reverse(char byte);

      /* Convert from normal bytes to one-LSB-per-byte format */
      static void convert_to_grformat(uint8_t input, uint8_t *output);

      /* Convert some number of bits of an air order array to a host order integer */
      static uint8_t air_to_host8(char *air_order, int bits);
      static uint16_t air_to_host16(char *air_order, int bits);
      static uint32_t air_to_host32(char *air_order, int bits);
      // hmmm, maybe these should have pointer output so they can be overloaded
      
      /* Convert some number of bits in a host order integer to an air order array */
      static void host_to_air(uint8_t host_order, char *air_order, int bits);

      // -------------------------------------------------------------------

      /* is the packet whitened? */
      bool get_whitened();

      /* set the packet's whitened flag */
      void set_whitened(bool whitened);

      /* Retrieve the length of the payload data */
      int get_payload_length();

      /* have we decoded the payload yet? */
      bool got_payload();
      
      int get_type();

      /* decode the whole packet */
      void decode();

      // -------------------------------------------------------------------

      /* decode the packet header */
      virtual bool decode_header() = 0;
      
      /* decode the packet header */
      virtual void decode_payload() = 0;
            
      /* print packet information */
      virtual void print() = 0;
      
      /* format payload for tun interface */
      virtual char *tun_format() = 0;

      /* check to see if the packet has a header */
      virtual bool header_present() = 0;

      virtual int get_channel() = 0;
    };

    /*!
     * \brief <+description of block+>
     * \ingroup gr_bluetooth
     */
    class GR_BLUETOOTH_API classic_packet : virtual public packet
    {
    private:
      int d_channel;

    public:
      typedef boost::shared_ptr<classic_packet> sptr;

      /*!
       * \brief Return a shared_ptr to a new instance of gr::bluetooth::classic_packet.
       *
       * To avoid accidental use of raw pointers, gr::bluetooth::classic_packet's
       * constructor is in a private implementation
       * class. gr::bluetooth::classic_packet::make is the public interface for
       * creating new instances.
       */
      static sptr make(char *stream, int length);

      /* construct with known CLKN and channel */
      static sptr make(char *stream, int length, uint32_t clkn, double freq);

      /* minimum header bit errors to indicate that this is an ID packet */
      static const int ID_THRESHOLD = 5;

      static const int SYMBOLS_PER_BASIC_RATE_ACCESS_CODE = 68;

      /* index into whitening data array */
      static const uint8_t INDICES[64];

      /* lookup table for preamble hamming distance */
      static const uint8_t PREAMBLE_DISTANCE[32];

      /* lookup table for barker hamming distance */
      static const uint8_t BARKER_DISTANCE[128];

      /* string representations of classic packet type */
      static const std::string TYPE_NAMES[16];

      /* native (local) clock */
      uint32_t d_clkn;

      /* search a symbol stream to find a packet, return index */
      static int sniff_ac(char *stream, int stream_length);

      /* Error correction coding for Access Code */
      static uint8_t *lfsr(uint8_t *data, int length, int k, uint8_t *g);

      /* Generate Access Code from an LAP */
      static uint8_t *acgen(int LAP);

      /* Decode 1/3 rate FEC, three like symbols in a row */
      static bool unfec13(char *input, char *output, int length);

      /* Decode 2/3 rate FEC, a (15,10) shortened Hamming code */
      static char *unfec23(char *input, int length);

      /* When passed 10 bits of data this returns a pointer to a 5 bit hamming code */
      //static char *fec23gen(char *data);

      /* Create an Access Code from LAP and check it against stream */
      static bool check_ac(char *stream, int LAP);

      /* Create the 16bit CRC for classic packet payloads - input air order stream */
      static uint16_t crcgen(char *payload, int length, int UAP);

      /* extract UAP by reversing the HEC computation */
      static int UAP_from_hec(uint16_t data, uint8_t hec);

      /* check if the classic_packet's CRC is correct for a given clock (CLK1-6) */
      virtual int crc_check(int clock) = 0;

      /* decode the classic packet header */
      virtual bool decode_header() = 0;
        
      /* decode the classic packet header */
      virtual void decode_payload() = 0;
        
      /* print classic packet information */
      virtual void print() = 0;
        
      /* format payload for tun interface */
      virtual char *tun_format() = 0;

      /* return the classic packet's LAP */
      virtual uint32_t get_LAP() = 0;

      /* return the classic packet's UAP */
      virtual uint8_t get_UAP() = 0;

      /* set the classic packet's UAP */
      virtual void set_UAP(uint8_t UAP) = 0;

      /* set the classic packet's NAP */
      virtual void set_NAP(uint16_t NAP) = 0;

      /* return the classic_packet's clock (CLK1-27) */
      virtual uint32_t get_clock() = 0;

      /* set the classic_packet's clock */
      virtual void set_clock(uint32_t clk6, bool have27) = 0;

      /* try a clock value (CLK1-6) to unwhiten classic_packet header,
       * sets resultant d_packet_type and d_UAP, returns UAP.
       */
      virtual uint8_t try_clock(int clock) = 0;

      /* check to see if the classic packet has a header */
      virtual bool header_present() = 0;

      /* extract LAP from FHS payload */
      virtual uint32_t lap_from_fhs() = 0;

      /* extract UAP from FHS payload */
      virtual uint8_t uap_from_fhs() = 0;

      /* extract NAP from FHS payload */
      virtual uint16_t nap_from_fhs() = 0;

      /* extract clock from FHS payload */
      virtual uint32_t clock_from_fhs() = 0;

      int get_channel( ) { return d_channel; }
    };

#define LE_MAX_PDU_OCTETS 39
#define LE_MAX_OCTETS     (1+4+LE_MAX_PDU_OCTETS+3)
#define LE_MAX_SYMBOLS    (8*LE_MAX_OCTETS)

    class GR_BLUETOOTH_API le_packet : virtual public packet
    {
    public:
      static const unsigned MAX_PDU_OCTETS = LE_MAX_PDU_OCTETS;
      static const unsigned MAX_OCTETS     = LE_MAX_OCTETS;
      static const unsigned MAX_SYMBOLS    = LE_MAX_SYMBOLS;

      typedef boost::shared_ptr<le_packet> sptr;

      static sptr make(char *stream, int length, double freq=0.0);
      static int freq2chan(const double freq);
      static int chan2index(const int chan);
      static int freq2index(const double freq);

      /* whitening sequence indices */
      static const uint8_t INDICES[40];

      /* lookup table for preamble hamming distance */
      static const uint8_t PREAMBLE_DISTANCE[512];

      /* lookup table for access address */
      static const uint8_t ACCESS_ADDRESS_DISTANCE_0[256];
      static const uint8_t ACCESS_ADDRESS_DISTANCE_1[256];
      static const uint8_t ACCESS_ADDRESS_DISTANCE_2[256];
      static const uint8_t ACCESS_ADDRESS_DISTANCE_3[256];

      /* lookup table for header hamming distances */
      static const uint8_t ACCESS_HEADER_DISTANCE_LSB[256];
      static const uint8_t ACCESS_HEADER_DISTANCE_MSB[256];
      static const uint8_t DATA_HEADER_DISTANCE_LSB[256];
      static const uint8_t DATA_HEADER_DISTANCE_MSB[256];

      static int sniff_aa(char *stream, int stream_length, double freq);

      /* decode the packet header */
      virtual bool decode_header() = 0;
       
      /* decode the packet header */
      virtual void decode_payload() = 0;
             
      /* print packet information */
      virtual void print() = 0;
       
      /* format payload for tun interface */
      virtual char *tun_format() = 0;
       
      /* check to see if the packet has a header */
      virtual bool header_present() = 0;

      /* return the low-energy packet's AA */
      virtual uint32_t get_AA() = 0;

      virtual int get_channel( ) = 0;
    };

  } // namespace bluetooth
} // namespace gr

#endif /* INCLUDED_GR_BLUETOOTH_PACKET_H */

