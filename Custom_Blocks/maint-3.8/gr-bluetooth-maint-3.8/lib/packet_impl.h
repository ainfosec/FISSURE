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

#ifndef INCLUDED_BLUETOOTH_GR_BLUETOOTH_PACKET_IMPL_H
#define INCLUDED_BLUETOOTH_GR_BLUETOOTH_PACKET_IMPL_H

#include "gr_bluetooth/packet.h"
#include <string>

namespace gr {
  namespace bluetooth {

    class classic_packet_impl : virtual public classic_packet
    {
    private:
      /* lower address part found in access code */
      uint32_t d_LAP;

      /* upper address part */
      uint8_t d_UAP;

      /* non-significant address part */
      uint8_t d_NAP;
	
      /* packet header, one bit per char */
      char d_packet_header[18];

      /* payload header, one bit per char */
      /* the packet may have a payload header of 0, 1, or 2 bytes, reserving 2 */
      char d_payload_header[16];

      /* number of payload header bytes */
      /* set to 0, 1, 2, or -1 for unknown */
      int d_payload_header_length;

      /* LLID field of payload header (2 bits) */
      uint8_t d_payload_llid;

      /* flow field of payload header (1 bit) */
      uint8_t d_payload_flow;

      /* do we know the UAP/NAP? */
      bool d_have_UAP;
      bool d_have_NAP;

      /* do we know the master clock? */
      bool d_have_clk6;
      bool d_have_clk27;

      /* CLK1-27 of master */
      uint32_t d_clock;

      /* type-specific CRC checks and decoding */
      int fhs(int clock);
      int DM(int clock);
      int DH(int clock);
      int EV3(int clock);
      int EV4(int clock);
      int EV5(int clock);
      int HV(int clock);

      /* decode payload header, return value indicates success */
      bool decode_payload_header(char *stream, int clock, int header_bytes, int size, bool fec);

      /* Remove the whitening from an air order array */
      void unwhiten(char* input, char* output, int clock, int length, int skip);

      /* verify the payload CRC */
      bool payload_crc();

    public:
      classic_packet_impl(char *stream, int length);
      ~classic_packet_impl();

      /* return the classic_packet's LAP */
      uint32_t get_LAP();

      /* return the classic_packet's UAP */
      uint8_t get_UAP();

      /* set the classic_packet's UAP */
      void set_UAP(uint8_t UAP);

      /* set the classic_packet's NAP */
      void set_NAP(uint16_t NAP);

      /* set the classic_packet's clock */
      void set_clock(uint32_t clk6, bool have27);

      /* return the classic_packet's clock (CLK1-27) */
      uint32_t get_clock();

      /* check if the classic_packet's CRC is correct for a given clock (CLK1-6) */
      int crc_check(int clock);

      /* try a clock value (CLK1-6) to unwhiten classic_packet header,
       * sets resultant d_packet_type and d_UAP, returns UAP.
       */
      uint8_t try_clock(int clock);

      /* decode the classic_packet header */
      bool decode_header();

      /* decode the classic_packet header */
      void decode_payload();

      /* print classic_packet information */
      void print();

      /* format payload for tun interface */
      char *tun_format();

      /* check to see if the classic_packet has a header */
      bool header_present();

      /* extract LAP from FHS payload */
      uint32_t lap_from_fhs();

      /* extract UAP from FHS payload */
      uint8_t uap_from_fhs();

      /* extract NAP from FHS payload */
      uint16_t nap_from_fhs();

      /* extract clock from FHS payload */
      uint32_t clock_from_fhs();
    };

    class le_packet_impl : virtual public le_packet
    {
    private:
      int      d_channel;

      int      d_index;
      uint32_t d_AA;

      uint8_t  d_PDU_Type;
      uint8_t  d_TxAdd;
      uint8_t  d_RxAdd;
      uint8_t  d_LLID;
      uint8_t  d_NESN;
      uint8_t  d_SN;
      uint8_t  d_MD;
      unsigned d_PDU_Length;

      char    d_link_symbols[LE_MAX_SYMBOLS];
      uint8_t d_pdu[LE_MAX_PDU_OCTETS];

    public:
      le_packet_impl(char *stream, int length, double freq=0.0);
      ~le_packet_impl();

      /* decode the packet header */
      bool decode_header();
      
      /* decode the packet header */
      void decode_payload();
      
      /* print packet information */
      void print();
      
      /* format payload for tun interface */
      char *tun_format();
      
      /* check to see if the packet has a header */
      bool header_present();

      /* return the low-energy packet's AA */
      uint32_t get_AA() { return d_AA; }

      int get_channel( ) { return d_channel; }
    };

  } // namespace bluetooth
} // namespace gr

#endif /* INCLUDED_BLUETOOTH_GR_BLUETOOTH_PACKET_IMPL_H */

