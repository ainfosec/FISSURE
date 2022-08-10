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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <gnuradio/io_signature.h>
#include "packet_impl.h"
#include <stdio.h>
#include <string.h>
#include <iostream>

namespace gr {
  namespace bluetooth {

    // -------------------------------------------------------------------

    packet::packet(char *stream, int length, double freq) :
      d_format( UNKNOWN ),
      d_freq( freq ),
      d_length( 0 ),
      d_symbols( ),
      d_packet_type( 0 ),
      d_payload_length( 0 ),
      d_payload( ),
      d_whitened( false ),
      d_have_payload( false )
    {
      if(length > MAX_SYMBOLS) {
        length = MAX_SYMBOLS;
      }
      for(int i = 0; i < length; i++) {
        d_symbols[i] = stream[i];
      }
      d_length = length;
    }

    bool packet::get_whitened()
    {
      return d_whitened;
    }

    void packet::set_whitened(bool whitened)
    {
      d_whitened = whitened;
    }

    int packet::get_payload_length()
    {
      return d_payload_length;
    }

    /* Reverse the bits in a byte */
    uint8_t packet::reverse(char byte)
    {
      return (byte & 0x80) >> 7 | (byte & 0x40) >> 5 | (byte & 0x20) >> 3 | 
        (byte & 0x10) >> 1 | (byte & 0x08) << 1 | (byte & 0x04) << 3 | 
        (byte & 0x02) << 5 | (byte & 0x01) << 7;
    }

    const uint8_t packet::WHITENING_DATA[] = {
      1, 1, 1, 0, 0, 0, 1, 1, 1, 0, 1, 1, 0, 0, 0, 1, 0, 1, 0, 0, 1, 0, 1, 1, 1, 1, 1, 0, 
      1, 0, 1, 0, 1, 0, 0, 0, 0, 1, 0, 1, 1, 0, 1, 1, 1, 1, 0, 0, 1, 1, 1, 0, 0, 1, 0, 1, 
      0, 1, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0, 1, 1, 0, 1, 0, 1, 1, 1, 0, 1, 0, 0, 0, 
      1, 1, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1, 
      1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1
    };

    /* Convert from normal bytes to one-LSB-per-byte format */
    void packet::convert_to_grformat(uint8_t input, uint8_t *output)
    {
      int count;
      for(count = 0; count < 8; count++) {
        output[count] = (input & 0x80) >> 7;
        input <<= 1;
      }
    }

    /* Convert some number of bits of an air order array to a host order integer */
    uint8_t packet::air_to_host8(char *air_order, int bits)
    {
      int i;
      uint8_t host_order = 0;
      for (i = 0; i < bits; i++)
        host_order |= (air_order[i] << i);
      return host_order;
    }

    uint16_t packet::air_to_host16(char *air_order, int bits)
    {
      int i;
      uint16_t host_order = 0;
      for (i = 0; i < bits; i++)
        host_order |= (air_order[i] << i);
      return host_order;
    }
    
    uint32_t packet::air_to_host32(char *air_order, int bits)
    {
      int i;
      uint32_t host_order = 0;
      for (i = 0; i < bits; i++)
        host_order |= (air_order[i] << i);
      return host_order;
    }

    /* Convert some number of bits in a host order integer to an air order array */
    void packet::host_to_air(uint8_t host_order, char *air_order, int bits)
    {
      int i;
      for (i = 0; i < bits; i++)
        air_order[i] = (host_order >> i) & 0x01;
    }

    bool packet::got_payload()
    {
      return d_have_payload;
    }

    int packet::get_type()
    {
      return d_packet_type;
    }

    int packet::sniff_packet(char *stream, int stream_length, double freq, air_format& fmt)
    {
      int retval = -1;

      if ((retval == -1) && ((fmt == UNKNOWN) || (fmt == CLASSIC))) {
        retval = classic_packet::sniff_ac(stream, stream_length);
        if (retval >= 0) {
          fmt = CLASSIC;
        }
      }
      if ((retval == -1) && ((fmt == UNKNOWN) || (fmt == LOW_ENERGY))) {
        retval = le_packet::sniff_aa(stream, stream_length, freq);
        if (retval >= 0) {
          fmt = LOW_ENERGY;
        }
      }
      
      return retval;
    }

    /* decode the whole packet */
    void packet::decode()
    {
      d_have_payload = false;
      if (decode_header( )) {
        decode_payload( );
      }
    }

    // -------------------------------------------------------------------
    

    /* initialize constant class member arrays */
    /* isn't it silly that this can't be done in the class declaration? */
    const uint8_t classic_packet::INDICES[] = {
      99,85,17,50,102,58,108,45,92,62,32,118,88,11,80,2,37,69,55,8,20,40,
      74,114,15,106,30,78,53,72,28,26,68,7,39,113,105,77,71,25,84,49,57,
      44,61,117,10,1,123,124,22,125,111,23,42,126,6,112,76,24,48,43,116,0
    };

    const uint8_t classic_packet::PREAMBLE_DISTANCE[] = {
      2,2,1,2,2,1,2,2,1,2,0,1,2,2,1,2,2,1,2,2,1,0,2,1,2,2,1,2,2,1,2,2
    };

    const uint8_t classic_packet::BARKER_DISTANCE[] = {
      3,3,3,2,3,2,2,1,2,3,3,3,3,3,3,2,2,3,3,3,3,3,3,2,1,2,2,3,2,3,3,3,3,2,2,
      1,2,1,1,0,3,3,3,2,3,2,2,1,3,3,3,2,3,2,2,1,2,3,3,3,3,3,3,2,2,3,3,3,3,3,
      3,2,1,2,2,3,2,3,3,3,1,2,2,3,2,3,3,3,0,1,1,2,1,2,2,3,3,3,3,2,3,2,2,1,2,
      3,3,3,3,3,3,2,2,3,3,3,3,3,3,2,1,2,2,3,2,3,3,3
    };

    const std::string classic_packet::TYPE_NAMES[] = {
      "NULL", "POLL", "FHS", "DM1", "DH1/2-DH1", "HV1", "HV2/2-EV3", "HV3/EV3/3-EV3",
      "DV/3-DH1", "AUX1", "DM3/2-DH3", "DH3/3-DH3", "EV4/2-EV5", "EV5/3-EV5", 
      "DM5/2-DH5", "DH5/3-DH5"
    };

    classic_packet::sptr
    classic_packet::make(char *stream, int length)
    {
      return classic_packet::sptr(new classic_packet_impl(stream, length));
    }

    classic_packet::sptr
    classic_packet::make(char *stream, int length, uint32_t clkn, double freq)
    {
      classic_packet::sptr pkt = classic_packet::sptr(new classic_packet_impl(stream, length));

      pkt->d_clkn = clkn;
      pkt->d_freq = freq;

      if ((freq >= 2402000000.0) && (freq <= 2480000000.0)) {
        pkt->d_channel = (int) ((freq-2402000000.0)/1000000.0);
      }
      else {
        pkt->d_channel = -1;
      }

      return pkt;
    }

    /*
     * The private constructor
     */
    classic_packet_impl::classic_packet_impl(char *stream, int length)
      : packet(stream, length)
    {
      //FIXME maybe should verify LAP
      d_LAP            = air_to_host32(&d_symbols[38], 24);
      d_whitened       = true;
      d_have_UAP       = false;
      d_have_NAP       = false;
      d_have_clk6      = false;
      d_have_clk27     = false;
      d_have_payload   = false;
      d_payload_length = 0;
    }

    /* search a symbol stream to find a classic_packet, return index */
    int classic_packet::sniff_ac(char *stream, int stream_length)
    {
      /* Looks for an AC in the stream */
      int count;
      int max_distance = 2; // maximum number of bit errors to tolerate in preamble + trailer

      for( count=0; count<stream_length; count++ ) {
        char * symbols = &stream[count];
        // start of sync word (includes LSB of sync word)
        uint8_t preamble = air_to_host8( &symbols[0], 5 );
        // MSB of LAP and 6-bit barker in 7 symbols
        uint16_t barker = air_to_host16( &symbols[61], 7 );
        if ((PREAMBLE_DISTANCE[preamble] + BARKER_DISTANCE[barker]) 
            <= max_distance) {
          uint32_t LAP = air_to_host32( &symbols[38], 24 );
          if (check_ac( symbols, LAP )) {
            return count;
          }
        }
      }
      return -1;
    }

    /*
     * Our virtual destructor.
     */
    classic_packet_impl::~classic_packet_impl()
    {
    }

    /* A linear feedback shift register */
    uint8_t *classic_packet::lfsr(uint8_t *data, int length, int k, uint8_t *g)
    /*
     * A linear feedback shift register
     * used for the syncword in the access code
     * and the fec2/3 encoding (could also be used for the HEC/CRC)
     * Although I'm not sure how to run it backwards for HEC->UAP
     */
    {
      int    i, j;
      uint8_t *cw, feedback;
      cw = (uint8_t *) calloc(length - k, 1);

      for (i = k - 1; i >= 0; i--) {
        feedback = data[i] ^ cw[length - k - 1];
        if (feedback != 0) {
          for (j = length - k - 1; j > 0; j--)
            if (g[j] != 0)
              cw[j] = cw[j - 1] ^ feedback;
            else
              cw[j] = cw[j - 1];
          cw[0] = g[0] && feedback;
        } else {
          for (j = length - k - 1; j > 0; j--)
            cw[j] = cw[j - 1];
          cw[0] = 0;
        }
      }
      return cw;
    }

    /* Generate Access Code from an LAP */
    uint8_t *classic_packet::acgen(int LAP)
    {
      /* Endianness - Assume LAP is MSB first, rest done LSB first */
      uint8_t *retval, count, *cw, *data;
      retval = (uint8_t *) calloc(9,1);
      data = (uint8_t *) malloc(30);
      // pseudo-random sequence to XOR with LAP and syncword
      uint8_t pn[] = {0x03,0xF2,0xA3,0x3D,0xD6,0x9B,0x12,0x1C,0x10};
      // generator polynomial for the access code
      uint8_t g[] = {1,0,0,1,0,1,0,1,1,0,1,1,1,1,0,0,1,0,0,0,1,1,1,0,1,0,1,0,0,0,0,1,1,0,1};

      LAP = reverse((LAP & 0xff0000)>>16) | (reverse((LAP & 0x00ff00)>>8)<<8) | (reverse(LAP & 0x0000ff)<<16);

      retval[4] = (LAP & 0xc00000)>>22;
      retval[5] = (LAP & 0x3fc000)>>14;
      retval[6] = (LAP & 0x003fc0)>>6;
      retval[7] = (LAP & 0x00003f)<<2;

      /* Trailer */
      if(LAP & 0x1)
	{	retval[7] |= 0x03;
          retval[8] = 0x2a;
	} else
        retval[8] = 0xd5;

      for(count = 4; count < 9; count++)
        retval[count] ^= pn[count];

      data[0] = (retval[4] & 0x02) >> 1;
      data[1] = (retval[4] & 0x01);
      host_to_air(reverse(retval[5]), (char *) data+2, 8);
      host_to_air(reverse(retval[6]), (char *) data+10, 8);
      host_to_air(reverse(retval[7]), (char *) data+18, 8);
      host_to_air(reverse(retval[8]), (char *) data+26, 4);

      cw = lfsr(data, 64, 30, g);
      free(data);

      retval[0] = cw[0] << 3 | cw[1] << 2 | cw[2] << 1 | cw[3];
      retval[1] = cw[4] << 7 | cw[5] << 6 | cw[6] << 5 | cw[7] << 4 | cw[8] << 3 | cw[9] << 2 | cw[10] << 1 | cw[11];
      retval[2] = cw[12] << 7 | cw[13] << 6 | cw[14] << 5 | cw[15] << 4 | cw[16] << 3 | cw[17] << 2 | cw[18] << 1 | cw[19];
      retval[3] = cw[20] << 7 | cw[21] << 6 | cw[22] << 5 | cw[23] << 4 | cw[24] << 3 | cw[25] << 2 | cw[26] << 1 | cw[27];
      retval[4] = cw[28] << 7 | cw[29] << 6 | cw[30] << 5 | cw[31] << 4 | cw[32] << 3 | cw[33] << 2 | (retval[4] & 0x3);
      free(cw);

      for(count = 0; count < 9; count++)
        retval[count] ^= pn[count];

      /* Preamble */
      if(retval[0] & 0x08)
        retval[0] |= 0xa0;
      else
        retval[0] |= 0x50;

      return retval;
    }

    /* Decode 1/3 rate FEC, three like symbols in a row */
    bool classic_packet::unfec13(char *input, char *output, int length)
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

    /* Decode 2/3 rate FEC, a (15,10) shortened Hamming code */
    char *classic_packet::unfec23(char *input, int length)
    {
      /* input points to the input data
       * length is length in bits of the data
       * before it was encoded with fec2/3 */
      int iptr, optr, blocks;
      char* output;
      uint8_t difference, count, *codeword;
      uint8_t fecgen[] = {1,1,0,1,0,1};

      iptr = -15;
      optr = -10;
      difference = length % 10;
      // padding at end of data
      if(0!=difference)
        length += (10 - difference);

      blocks = length/10;
      output = (char *) malloc(length);

      while(blocks) {
        iptr += 15;
        optr += 10;
        blocks--;

        // copy data to output
        for(count=0;count<10;count++)
          output[optr+count] = input[iptr+count];

        // call fec23gen on data to generate the codeword
        //codeword = fec23gen(input+iptr);
        codeword = lfsr((uint8_t *) input+iptr, 15, 10, fecgen);

        // compare codeword to the 5 received bits
        difference = 0;
        for(count=0;count<5;count++)
          if(codeword[count]!=input[iptr+10+count])
            difference++;

        /* no errors or single bit errors (errors in the parity bit):
         * (a strong hint it's a real packet) */
        if((0==difference) || (1==difference)) {
          free(codeword);
          continue;
        }

        // multiple different bits in the codeword
        for(count=0;count<5;count++) {
          difference |= codeword[count] ^ input[iptr+10+count];
          difference <<= 1;
        }
        free(codeword);

        switch (difference) {
          /* comments are the bit that's wrong and the value
           * of difference in binary, from the BT spec */
          // 1000000000 11010
        case 26: output[optr] ^= 1; break;
          // 0100000000 01101
        case 13: output[optr+1] ^= 1; break;
          // 0010000000 11100
        case 28: output[optr+2] ^= 1; break;
          // 0001000000 01110
        case 14: output[optr+3] ^= 1; break;
          // 0000100000 00111
        case 7: output[optr+4] ^= 1; break;
          // 0000010000 11001
        case 25: output[optr+5] ^= 1; break;
          // 0000001000 10110
        case 22: output[optr+6] ^= 1; break;
          // 0000000100 01011
        case 11: output[optr+7] ^= 1; break;
          // 0000000010 11111
        case 31: output[optr+8] ^= 1; break;
          // 0000000001 10101
        case 21: output[optr+9] ^= 1; break;
          /* not one of these errors, probably multiple bit errors
           * or maybe not a real packet, safe to drop it? */
        default: free(output); return NULL;
        }
      }
      return output;
    }

    /* Create an Access Code from LAP and check it against stream */
    bool classic_packet::check_ac(char *stream, int LAP)
    {
      int count, aclength, biterrors;
      uint8_t *ac, *grdata;
      aclength = 72;
      biterrors = 0;

      /* Generate AC */
      ac = acgen(LAP);

      /* Check AC */
      /* Convert it to grformat, 1 bit per byte, in the LSB */
      grdata = (uint8_t *) malloc(aclength);

      for(count = 0; count < 9; count++)
        convert_to_grformat(ac[count], &grdata[count*8]);
      free(ac);

      for(count = 0; count < SYMBOLS_PER_BASIC_RATE_ACCESS_CODE; count++)
	{
          if(grdata[count] != stream[count])
            biterrors++;
          //FIXME do error correction instead of detection
          if(biterrors>=7)
            {
              free(grdata);
              return false;
            }
	}
      if(biterrors)
	{
          //printf("POSSIBLE PACKET, LAP = %06x with %d errors\n", LAP, biterrors);
          free(grdata);
          //return false;
          return true;
	}

      free(grdata);
      return true;
    }

    /* Remove the whitening from an air order array */
    void classic_packet_impl::unwhiten(char* input, char* output, int clock, int length, int skip)
    {
      int count, index;
      index = INDICES[clock & 0x3f];
      index += skip;
      index %= 127;

      for(count = 0; count < length; count++) {
        /* unwhiten if d_whitened, otherwise just copy input to output */
        output[count] = (d_whitened) ? input[count] ^ WHITENING_DATA[index] : input[count];
        index += 1;
        index %= 127;
      }
    }

    /* Pointer to start of packet, length of packet in bits, UAP */
    uint16_t classic_packet::crcgen(char *payload, int length, int UAP)
    {
      char byte;
      uint16_t reg, count;

      reg = (reverse(UAP) << 8) & 0xff00;
      for(count = 0; count < length; count++)
	{
          byte = payload[count];

          reg = (reg >> 1) | (((reg & 0x0001) ^ (byte & 0x01))<<15);

          /*Bit 5*/
          reg ^= ((reg & 0x8000)>>5);

          /*Bit 12*/
          reg ^= ((reg & 0x8000)>>12);
	}
      return reg;
    }

    /* return the packet's LAP */
    uint32_t classic_packet_impl::get_LAP()
    {
      return d_LAP;
    }

    /* return the packet's UAP */
    uint8_t classic_packet_impl::get_UAP()
    {
      //FIXME throw exception if !d_have_UAP
      return d_UAP;
    }

    /* set the packet's UAP */
    void classic_packet_impl::set_UAP(uint8_t UAP)
    {
      d_UAP = UAP;
      d_have_UAP = true;
    }

    void classic_packet_impl::set_NAP(uint16_t NAP)
    {
      d_NAP = NAP;
      d_have_NAP = true;
    }

    /* return the packet's clock (CLK1-27) */
    uint32_t classic_packet_impl::get_clock()
    {
      //FIXME throw exception if !d_have_clk6
      return d_clock;
    }

    /* set the classic_packet's clock (CLK1-27) */
    void classic_packet_impl::set_clock(uint32_t clock, bool have27)
    {
      /* we expect to be called with either 6 or 27 clock bits */
      if (have27)
        d_clock = clock & 0x7ffffff;
      else
        d_clock = clock & 0x3f;

      d_have_clk6 = true;
      d_have_clk27 = have27;
    }

    /* extract UAP by reversing the HEC computation */
    int classic_packet::UAP_from_hec(uint16_t data, uint8_t hec)
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

    /* check if the classic_packet's CRC is correct for a given clock (CLK1-6) */
    int classic_packet_impl::crc_check(int clock)
    {
      /*
       * return value of 1 represents inconclusive result (default)
       * return value > 1 represents positive result (e.g. CRC match)
       * return value of 0 represents negative result (e.g. CRC failure without
       * the possibility that we have assumed the wrong logical transport)
       */
      int retval = 1;

      switch(d_packet_type)
	{
        case 2:/* FHS */
          retval = fhs(clock);
          break;

        case 8:/* DV */
        case 3:/* DM1 */
        case 10:/* DM3 */
        case 14:/* DM5 */
          retval = DM(clock);
          break;

        case 4:/* DH1 */
        case 11:/* DH3 */
        case 15:/* DH5 */
          retval = DH(clock);
          break;

        case 7:/* EV3 */
          retval = EV3(clock);
          break;
        case 12:/* EV4 */
          retval = EV4(clock);
          break;
        case 13:/* EV5 */
          retval = EV5(clock);
          break;
		
        case 5:/* HV1 */
          retval = HV(clock);
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
      if (retval == 0 && (d_packet_type != 2 && d_packet_type != 3 &&
                          d_packet_type != 5))
        return 1;

      /* EV3 and EV5 have a relatively high false positive rate */
      if (retval > 1 && (d_packet_type == 7 || d_packet_type == 13))
        return 1;

      return retval;
    }
    
    
    /* verify the payload CRC */
    bool classic_packet_impl::payload_crc()
    {
      uint16_t crc;   /* CRC calculated from payload data */
      uint16_t check; /* CRC supplied by packet */

      crc = crcgen(d_payload, (d_payload_length - 2) * 8, d_UAP);
      check = air_to_host16(&d_payload[(d_payload_length - 2) * 8], 16);

      return (crc == check);
    }

    int classic_packet_impl::fhs(int clock)
    {
      /* skip the access code and packet header */
      char *stream = d_symbols + 126;
      /* number of symbols remaining after access code and packet header */
      int size = d_length - 126;

      d_payload_length = 20;

      if (size < d_payload_length * 12)
        return 1; //FIXME should throw exception

      char *corrected = unfec23(stream, d_payload_length * 8);
      if (!corrected)
        return 0;

      /* try to unwhiten with known clock bits */
      unwhiten(corrected, d_payload, clock, d_payload_length * 8, 18);
      if (payload_crc()) {
        free(corrected);
        return 1000;
      }

      /* try all 32 possible X-input values instead */
      for (clock = 32; clock < 64; clock++) {
        unwhiten(corrected, d_payload, clock, d_payload_length * 8, 18);
        if (payload_crc()) {
          free(corrected);
          return 1000;
        }
      }

      /* failed to unwhiten */
      free(corrected);
      return 0;
    }

    /* decode payload header, return value indicates success */
    bool classic_packet_impl::decode_payload_header(char *stream, int clock, int header_bytes, int size, bool fec)
    {
      if(header_bytes == 2)
	{
          if(size < 16)
            return false; //FIXME should throw exception
          if(fec) {
            if(size < 30)
              return false; //FIXME should throw exception
            char *corrected = unfec23(stream, 16);
            if (!corrected)
              return false;
            unwhiten(corrected, d_payload_header, clock, 16, 18);
            free(corrected);
          } else {
            unwhiten(stream, d_payload_header, clock, 16, 18);
          }
          /* payload length is payload body length + 2 bytes payload header + 2 bytes CRC */
          d_payload_length = air_to_host16(&d_payload_header[3], 10) + 4;
	} else {
        if(size < 8)
          return false; //FIXME should throw exception
        if(fec) {
          if(size < 15)
            return false; //FIXME should throw exception
          char *corrected = unfec23(stream, 8);
          if (!corrected)
            return false;
          unwhiten(corrected, d_payload_header, clock, 8, 18);
          free(corrected);
        } else {
          unwhiten(stream, d_payload_header, clock, 8, 18);
        }
        /* payload length is payload body length + 1 byte payload header + 2 bytes CRC */
        d_payload_length = air_to_host8(&d_payload_header[3], 5) + 3;
      }
      d_payload_llid = air_to_host8(&d_payload_header[0], 2);
      d_payload_flow = air_to_host8(&d_payload_header[2], 1);
      d_payload_header_length = header_bytes;
      return true;
    }
   
    /* DM 1/3/5 packet (and DV)*/
    int classic_packet_impl::DM(int clock)
    {
      int bitlength;
      /* number of bytes in the payload header */
      int header_bytes = 2;
      /* maximum payload length */
      int max_length;
      /* skip the access code and packet header */
      char *stream = d_symbols + 126;
      /* number of symbols remaining after access code and packet header */
      int size = d_length - 126;

      switch(d_packet_type)
	{
        case(8): /* DV */
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
        case(3): /* DM1 */
          header_bytes = 1;
          max_length = 20;
          break;
        case(10): /* DM3 */
          max_length = 125;
          break;
        case(14): /* DM5 */
          max_length = 228;
          break;
        default: /* not a DM1/3/5 or DV */
          return 0;
	}
      if(!decode_payload_header(stream, clock, header_bytes, size, true))
        return 0;
      /* check that the length indicated in the payload header is within spec */
      if(d_payload_length > max_length)
        /* could be encrypted */
        return 1;
      bitlength = d_payload_length*8;
      if(bitlength > size)
        return 1; //FIXME should throw exception

      char *corrected = unfec23(stream, bitlength);
      if (!corrected)
        return 0;
      unwhiten(corrected, d_payload, clock, bitlength, 18);
      free(corrected);

      if (payload_crc())
        return 10;

      /* could be encrypted */
      return 1;
    }

    /* DH 1/3/5 packet (and AUX1) */
    /* similar to DM 1/3/5 but without FEC */
    int classic_packet_impl::DH(int clock)
    {
      int bitlength;
      /* number of bytes in the payload header */
      int header_bytes = 2;
      /* maximum payload length */
      int max_length;
      /* skip the access code and packet header */
      char *stream = d_symbols + 126;
      /* number of symbols remaining after access code and packet header */
      int size = d_length - 126;
	
      switch(d_packet_type)
	{
        case(9): /* AUX1 */
        case(4): /* DH1 */
          header_bytes = 1;
        max_length = 30;
        break;
        case(11): /* DH3 */
          max_length = 187;
          break;
        case(15): /* DH5 */
          max_length = 343;
          break;
        default: /* not a DH1/3/5 */
          return 0;
	}
      if(!decode_payload_header(stream, clock, header_bytes, size, false))
        return 0;
      /* check that the length indicated in the payload header is within spec */
      if(d_payload_length > max_length)
        /* could be encrypted */
        return 1;
      bitlength = d_payload_length*8;
      if(bitlength > size)
        return 1; //FIXME should throw exception

      unwhiten(stream, d_payload, clock, bitlength, 18);
	
      /* AUX1 has no CRC */
      if (d_packet_type == 9)
        return 1;

      if (payload_crc())
        return 10;

      /* could be encrypted */
      return 1;
    }

    int classic_packet_impl::EV3(int clock)
    {
      /* skip the access code and packet header */
      char *stream = d_symbols + 126;

      /* number of symbols remaining after access code and packet header */
      int size = d_length - 126;

      /* maximum payload length is 30 bytes + 2 bytes CRC */
      int maxlength = 32;

      /* number of bits we have decoded */
      int bits;

      /* check CRC for any integer byte length up to maxlength */
      for (d_payload_length = 0;
           d_payload_length < maxlength; d_payload_length++) {

        bits = d_payload_length * 8;

        /* unwhiten next byte */
        if ((bits + 8) > size)
          return 1; //FIXME should throw exception
        unwhiten(stream, d_payload + bits, clock, 8, 18 + bits);

        if ((d_payload_length > 2) && (payload_crc()))
          return 10;
      }
      return 1;
    }

    int classic_packet_impl::EV4(int clock)
    {
      char *corrected;

      /* skip the access code and packet header */
      char *stream = d_symbols + 126;

      /* number of symbols remaining after access code and packet header */
      int size = d_length - 126;

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

      d_payload_length = 1;

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
        unwhiten(corrected, d_payload + bits, clock, 10, 18 + bits);
        free(corrected);

        /* check CRC one byte at a time */
        while (d_payload_length * 8 <= bits) {
          if (payload_crc())
            return 10;
          d_payload_length++;
        }
        syms += 15;
        bits += 10;
      }
      return 1;
    }

    int classic_packet_impl::EV5(int clock)
    {
      /* skip the access code and packet header */
      char *stream = d_symbols + 126;

      /* number of symbols remaining after access code and packet header */
      int size = d_length - 126;

      /* maximum payload length is 180 bytes + 2 bytes CRC */
      int maxlength = 182;

      /* number of bits we have decoded */
      int bits;

      /* check CRC for any integer byte length up to maxlength */
      for (d_payload_length = 0;
           d_payload_length < maxlength; d_payload_length++) {

        bits = d_payload_length * 8;

        /* unwhiten next byte */
        if ((bits + 8) > size)
          return 1; //FIXME should throw exception
        unwhiten(stream, d_payload + bits, clock, 8, 18 + bits);

        if ((d_payload_length > 2) && (payload_crc()))
          return 10;
      }
      return 1;
    }

    /* HV packet type payload parser */
    int classic_packet_impl::HV(int clock)
    {
      /* skip the access code and packet header */
      char *stream = d_symbols + 126;
      /* number of symbols remaining after access code and packet header */
      int size = d_length - 126;

      if(size < 240) {
        d_payload_length = 0;
        return 1; //FIXME should throw exception
      }

      switch (d_packet_type) {
      case 5:/* HV1 */
        {
          char corrected[80];
          if (!unfec13(stream, corrected, 80))
            return 0;
          d_payload_length = 10;
          unwhiten(corrected, d_payload, clock, d_payload_length*8, 18);
        }
        break;
      case 6:/* HV2 */
        {
          char *corrected = unfec23(stream, 160);
          if (!corrected)
            return 0;
          d_payload_length = 20;
          unwhiten(corrected, d_payload, clock, d_payload_length*8, 18);
          free(corrected);
        }
        break;
      case 7:/* HV3 */
        d_payload_length = 30;
        unwhiten(stream, d_payload, clock, d_payload_length*8, 18);
        break;
      }

      return 1;
    }

    /* try a clock value (CLK1-6) to unwhiten packet header,
     * sets resultant d_packet_type and d_UAP, returns UAP.
     */
    uint8_t classic_packet_impl::try_clock(int clock)
    {
      /* skip 72 bit access code */
      char *stream = d_symbols + 72;
      /* 18 bit packet header */
      char header[18];
      char unwhitened[18];

      if (!unfec13(stream, header, 18))
        return 0;
      unwhiten(header, unwhitened, clock, 18, 0);
      uint16_t hdr_data = air_to_host16(unwhitened, 10);
      uint8_t hec = air_to_host8(&unwhitened[10], 8);
      d_UAP = classic_packet::UAP_from_hec(hdr_data, hec);
      d_packet_type = air_to_host8(&unwhitened[3], 4);

      return d_UAP;
    }

    /* decode the packet header */
    bool classic_packet_impl::decode_header()
    {
      /* skip 72 bit access code */
      char *stream = d_symbols + 72;
      /* 18 bit packet header */
      char header[18];
      uint8_t UAP;

      if (d_have_clk6 && unfec13(stream, header, 18)) {
        unwhiten(header, d_packet_header, d_clock, 18, 0);
        uint16_t hdr_data = air_to_host16(d_packet_header, 10);
        uint8_t hec = air_to_host8(&d_packet_header[10], 8);
        UAP = classic_packet::UAP_from_hec(hdr_data, hec);
        if (UAP == d_UAP) {
          d_packet_type = air_to_host8(&d_packet_header[3], 4);
          return true;
        } else {
          printf("bad HEC! %02x %02x %i ", UAP, d_UAP, air_to_host8(&d_packet_header[3], 4));
        }
      }
	
      printf("failed to decode header\n");
      return false;
    }

    void classic_packet_impl::decode_payload()
    {
      d_payload_header_length = 0;

      switch(d_packet_type)
	{
        case 0: /* NULL */
          /* no payload to decode */
          d_payload_length = 0;
          break;
        case 1: /* POLL */
          /* no payload to decode */
          d_payload_length = 0;
          break;
        case 2: /* FHS */
          fhs(d_clock);
          break;
        case 3: /* DM1 */
          DM(d_clock);
          break;
        case 4: /* DH1 */
          /* assuming DH1 but could be 2-DH1 */
          DH(d_clock);
          break;
        case 5: /* HV1 */
          HV(d_clock);
          break;
        case 6: /* HV2 */
          HV(d_clock);
          break;
        case 7: /* HV3/EV3/3-EV3 */
          /* decode as EV3 if CRC checks out */
          if (EV3(d_clock) <= 1)
            /* otherwise assume HV3 */
            HV(d_clock);
          /* don't know how to decode 3-EV3 */
          break;
        case 8: /* DV */
          /* assuming DV but could be 3-DH1 */
          DM(d_clock);
          break;
        case 9: /* AUX1 */
          DH(d_clock);
          break;
        case 10: /* DM3 */
          /* assuming DM3 but could be 2-DH3 */
          DM(d_clock);
          break;
        case 11: /* DH3 */
          /* assuming DH3 but could be 3-DH3 */
          DH(d_clock);
          break;
        case 12: /* EV4 */
          /* assuming EV4 but could be 2-EV5 */
          EV4(d_clock);
          break;
        case 13: /* EV5 */
          /* assuming EV5 but could be 3-EV5 */
          EV5(d_clock);
        case 14: /* DM5 */
          /* assuming DM5 but could be 2-DH5 */
          DM(d_clock);
          break;
        case 15: /* DH5 */
          /* assuming DH5 but could be 3-DH5 */
          DH(d_clock);
          break;
	}
      d_have_payload = true;
    }

    /* print packet information */
    void classic_packet_impl::print()
    {
      if (d_have_payload) {
        std::cout << TYPE_NAMES[d_packet_type] << std::endl;
        if (d_payload_header_length > 0) {
          printf("  LLID: %d\n", d_payload_llid);
          printf("  flow: %d\n", d_payload_flow);
          printf("  payload length: %d\n", d_payload_length);
        }
      }
    }

    char *classic_packet_impl::tun_format()
    {
      /* include 6 bytes for meta data, 3 bytes for packet header */
      int length = 9 + d_payload_length;
      char *tun_format = (char *) malloc(length);
      int i;

      /* meta data */
      tun_format[0] = d_clock & 0xff;
      tun_format[1] = (d_clock >> 8) & 0xff;
      tun_format[2] = (d_clock >> 16) & 0xff;
      tun_format[3] = (d_clock >> 24) & 0xff;
      tun_format[4] = get_channel( );
      tun_format[5] = d_have_clk27 | (d_have_NAP << 1);

      /* packet header modified to fit byte boundaries */
      /* lt_addr and type */
      tun_format[6] = (char) air_to_host8(&d_packet_header[0], 7);
      /* flags */
      tun_format[7] = (char) air_to_host8(&d_packet_header[7], 3);
      /* HEC */
      tun_format[8] = (char) air_to_host8(&d_packet_header[10], 8);

      for(i=0;i<d_payload_length;i++)
        tun_format[i+9] = (char) air_to_host8(&d_payload[i*8], 8);

      return tun_format;
    }

    /* check to see if the packet has a header */
    bool classic_packet_impl::header_present()
    {
      /* skip to last bit of sync word */
      char *stream = d_symbols + 67;
      int be = 0; /* bit errors */
      char msb;   /* most significant (last) bit of sync word */
      int a, b, c;

      /* check that we have enough symbols */
      if (d_length < 126)
        return false;

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
    uint32_t classic_packet_impl::lap_from_fhs()
    {
      /* caller should check got_payload() and get_type() */
      return air_to_host32(&d_payload[34], 24);
    }

    /* extract UAP from FHS payload */
    uint8_t classic_packet_impl::uap_from_fhs()
    {
      /* caller should check got_payload() and get_type() */
      return air_to_host8(&d_payload[64], 8);
    }

    /* extract NAP from FHS payload */
    uint16_t classic_packet_impl::nap_from_fhs()
    {
      /* caller should check got_payload() and get_type() */
      return air_to_host8(&d_payload[72], 16);
    }

    /* extract clock from FHS payload */
    uint32_t classic_packet_impl::clock_from_fhs()
    {
      /*
       * caller should check got_payload() and get_type()
       *
       * This is CLK2-27 (units of 1.25 ms).
       * CLK0 and CLK1 are implicitly zero.
       */
      return air_to_host32(&d_payload[115], 26);
    }

    // -------------------------------------------------------------------

    le_packet::sptr 
    le_packet::make(char *stream, int length, double freq) 
    {
      return le_packet::sptr(new le_packet_impl(stream, length, freq));
    }

    int le_packet::freq2chan(const double freq) {
      int retval = -1;
      if ((freq >= 2402000000.0) && (freq <= 2480000000.0)) {
        if (::fmod(freq, 2000000.0) < 5000.0) {
          retval = (int) ((freq - 2402000000.0) / 2000000.0);
        }
      }
      return retval;
    }

    int le_packet::chan2index(const int chan) {
      int retval = -1;
      if ((chan >= 0) && (chan <= 39)) {
        const int indices[40] = {
          37,
          0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
          38,
          11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 
          27, 28, 29, 30, 31, 32, 33, 34, 35, 36,
          39
        };
        retval = indices[chan];
      }
      return retval;
    }

    int le_packet::freq2index(const double freq) {
      int chan = freq2chan( freq );
      return chan2index( chan );
    }

    const uint8_t le_packet::PREAMBLE_DISTANCE[] = {
      4,4,3,4,4,3,4,4,3,4,2,3,4,4,3,4,4,3,4,4,3,2,4,3,4,4,3,4,4,3,4,4,3,4,2,
      3,4,4,3,4,2,3,1,2,3,4,2,3,4,4,3,4,4,3,4,4,3,4,2,3,4,4,3,4,4,3,4,4,3,2,
      4,3,4,4,3,4,4,3,4,4,3,2,4,3,2,1,3,2,4,3,4,4,3,2,4,3,4,4,3,4,4,3,4,4,3,
      4,2,3,4,4,3,4,4,3,4,4,3,2,4,3,4,4,3,4,4,3,4,4,3,4,2,3,4,4,3,4,2,3,1,2,
      3,4,2,3,4,4,3,4,4,3,4,4,3,4,2,3,4,4,3,4,2,3,1,2,3,4,2,3,1,2,0,1,2,3,1,
      2,3,4,2,3,4,4,3,4,2,3,1,2,3,4,2,3,4,4,3,4,4,3,4,4,3,4,2,3,4,4,3,4,4,3,
      4,4,3,2,4,3,4,4,3,4,4,3,4,4,3,4,2,3,4,4,3,4,2,3,1,2,3,4,2,3,4,4,3,4,4,
      3,4,4,3,4,2,3,4,4,3,4,4,3,4,4,3,2,4,3,4,4,3,4,4,3,4,4,3,2,4,3,2,1,3,2,
      4,3,4,4,3,2,4,3,4,4,3,4,4,3,4,4,3,4,2,3,4,4,3,4,4,3,4,4,3,2,4,3,4,4,3,
      4,4,3,4,4,3,2,4,3,2,1,3,2,4,3,4,4,3,2,4,3,2,1,3,2,1,0,2,1,3,2,4,3,2,1,
      3,2,4,3,4,4,3,2,4,3,4,4,3,4,4,3,4,4,3,2,4,3,2,1,3,2,4,3,4,4,3,2,4,3,4,
      4,3,4,4,3,4,4,3,4,2,3,4,4,3,4,4,3,4,4,3,2,4,3,4,4,3,4,4,3,4,4,3,4,2,3,
      4,4,3,4,2,3,1,2,3,4,2,3,4,4,3,4,4,3,4,4,3,4,2,3,4,4,3,4,4,3,4,4,3,2,4,
      3,4,4,3,4,4,3,4,4,3,2,4,3,2,1,3,2,4,3,4,4,3,2,4,3,4,4,3,4,4,3,4,4,3,4,
      2,3,4,4,3,4,4,3,4,4,3,2,4,3,4,4,3,4,4,3,4,4
    };

    const uint8_t le_packet::ACCESS_ADDRESS_DISTANCE_0[] = {
      5, 6, 4, 5, 4, 5, 3, 4, 6, 7, 5, 6, 5, 6, 4, 5, 4, 5, 3, 4, 3, 4, 2, 3, 
      5, 6, 4, 5, 4, 5, 3, 4, 6, 7, 5, 6, 5, 6, 4, 5, 7, 8, 6, 7, 6, 7, 5, 6, 
      5, 6, 4, 5, 4, 5, 3, 4, 6, 7, 5, 6, 5, 6, 4, 5, 4, 5, 3, 4, 3, 4, 2, 3, 
      5, 6, 4, 5, 4, 5, 3, 4, 3, 4, 2, 3, 2, 3, 1, 2, 4, 5, 3, 4, 3, 4, 2, 3, 
      5, 6, 4, 5, 4, 5, 3, 4, 6, 7, 5, 6, 5, 6, 4, 5, 4, 5, 3, 4, 3, 4, 2, 3, 
      5, 6, 4, 5, 4, 5, 3, 4, 4, 5, 3, 4, 3, 4, 2, 3, 5, 6, 4, 5, 4, 5, 3, 4, 
      3, 4, 2, 3, 2, 3, 1, 2, 4, 5, 3, 4, 3, 4, 2, 3, 5, 6, 4, 5, 4, 5, 3, 4, 
      6, 7, 5, 6, 5, 6, 4, 5, 4, 5, 3, 4, 3, 4, 2, 3, 5, 6, 4, 5, 4, 5, 3, 4, 
      3, 4, 2, 3, 2, 3, 1, 2, 4, 5, 3, 4, 3, 4, 2, 3, 2, 3, 1, 2, 1, 2, 0, 1, 
      3, 4, 2, 3, 2, 3, 1, 2, 4, 5, 3, 4, 3, 4, 2, 3, 5, 6, 4, 5, 4, 5, 3, 4, 
      3, 4, 2, 3, 2, 3, 1, 2, 4, 5, 3, 4, 3, 4, 2, 3
    };

    const uint8_t le_packet::ACCESS_ADDRESS_DISTANCE_1[] = {
      6, 7, 5, 6, 5, 6, 4, 5, 5, 6, 4, 5, 4, 5, 3, 4, 5, 6, 4, 5, 4, 5, 3, 4, 
      4, 5, 3, 4, 3, 4, 2, 3, 5, 6, 4, 5, 4, 5, 3, 4, 4, 5, 3, 4, 3, 4, 2, 3, 
      4, 5, 3, 4, 3, 4, 2, 3, 3, 4, 2, 3, 2, 3, 1, 2, 7, 8, 6, 7, 6, 7, 5, 6, 
      6, 7, 5, 6, 5, 6, 4, 5, 6, 7, 5, 6, 5, 6, 4, 5, 5, 6, 4, 5, 4, 5, 3, 4, 
      6, 7, 5, 6, 5, 6, 4, 5, 5, 6, 4, 5, 4, 5, 3, 4, 5, 6, 4, 5, 4, 5, 3, 4, 
      4, 5, 3, 4, 3, 4, 2, 3, 5, 6, 4, 5, 4, 5, 3, 4, 4, 5, 3, 4, 3, 4, 2, 3, 
      4, 5, 3, 4, 3, 4, 2, 3, 3, 4, 2, 3, 2, 3, 1, 2, 4, 5, 3, 4, 3, 4, 2, 3, 
      3, 4, 2, 3, 2, 3, 1, 2, 3, 4, 2, 3, 2, 3, 1, 2, 2, 3, 1, 2, 1, 2, 0, 1, 
      6, 7, 5, 6, 5, 6, 4, 5, 5, 6, 4, 5, 4, 5, 3, 4, 5, 6, 4, 5, 4, 5, 3, 4, 
      4, 5, 3, 4, 3, 4, 2, 3, 5, 6, 4, 5, 4, 5, 3, 4, 4, 5, 3, 4, 3, 4, 2, 3, 
      4, 5, 3, 4, 3, 4, 2, 3, 3, 4, 2, 3, 2, 3, 1, 2
    };

    const uint8_t le_packet::ACCESS_ADDRESS_DISTANCE_2[] = {
      3, 2, 4, 3, 4, 3, 5, 4, 2, 1, 3, 2, 3, 2, 4, 3, 4, 3, 5, 4, 5, 4, 6, 5, 
      3, 2, 4, 3, 4, 3, 5, 4, 4, 3, 5, 4, 5, 4, 6, 5, 3, 2, 4, 3, 4, 3, 5, 4, 
      5, 4, 6, 5, 6, 5, 7, 6, 4, 3, 5, 4, 5, 4, 6, 5, 4, 3, 5, 4, 5, 4, 6, 5, 
      3, 2, 4, 3, 4, 3, 5, 4, 5, 4, 6, 5, 6, 5, 7, 6, 4, 3, 5, 4, 5, 4, 6, 5, 
      5, 4, 6, 5, 6, 5, 7, 6, 4, 3, 5, 4, 5, 4, 6, 5, 6, 5, 7, 6, 7, 6, 8, 7, 
      5, 4, 6, 5, 6, 5, 7, 6, 2, 1, 3, 2, 3, 2, 4, 3, 1, 0, 2, 1, 2, 1, 3, 2, 
      3, 2, 4, 3, 4, 3, 5, 4, 2, 1, 3, 2, 3, 2, 4, 3, 3, 2, 4, 3, 4, 3, 5, 4, 
      2, 1, 3, 2, 3, 2, 4, 3, 4, 3, 5, 4, 5, 4, 6, 5, 3, 2, 4, 3, 4, 3, 5, 4, 
      3, 2, 4, 3, 4, 3, 5, 4, 2, 1, 3, 2, 3, 2, 4, 3, 4, 3, 5, 4, 5, 4, 6, 5, 
      3, 2, 4, 3, 4, 3, 5, 4, 4, 3, 5, 4, 5, 4, 6, 5, 3, 2, 4, 3, 4, 3, 5, 4, 
      5, 4, 6, 5, 6, 5, 7, 6, 4, 3, 5, 4, 5, 4, 6, 5
    };

    const uint8_t le_packet::ACCESS_ADDRESS_DISTANCE_3[] = {
      4, 5, 3, 4, 3, 4, 2, 3, 3, 4, 2, 3, 2, 3, 1, 2, 5, 6, 4, 5, 4, 5, 3, 4, 
      4, 5, 3, 4, 3, 4, 2, 3, 5, 6, 4, 5, 4, 5, 3, 4, 4, 5, 3, 4, 3, 4, 2, 3, 
      6, 7, 5, 6, 5, 6, 4, 5, 5, 6, 4, 5, 4, 5, 3, 4, 5, 6, 4, 5, 4, 5, 3, 4, 
      4, 5, 3, 4, 3, 4, 2, 3, 6, 7, 5, 6, 5, 6, 4, 5, 5, 6, 4, 5, 4, 5, 3, 4, 
      6, 7, 5, 6, 5, 6, 4, 5, 5, 6, 4, 5, 4, 5, 3, 4, 7, 8, 6, 7, 6, 7, 5, 6, 
      6, 7, 5, 6, 5, 6, 4, 5, 3, 4, 2, 3, 2, 3, 1, 2, 2, 3, 1, 2, 1, 2, 0, 1, 
      4, 5, 3, 4, 3, 4, 2, 3, 3, 4, 2, 3, 2, 3, 1, 2, 4, 5, 3, 4, 3, 4, 2, 3, 
      3, 4, 2, 3, 2, 3, 1, 2, 5, 6, 4, 5, 4, 5, 3, 4, 4, 5, 3, 4, 3, 4, 2, 3, 
      4, 5, 3, 4, 3, 4, 2, 3, 3, 4, 2, 3, 2, 3, 1, 2, 5, 6, 4, 5, 4, 5, 3, 4, 
      4, 5, 3, 4, 3, 4, 2, 3, 5, 6, 4, 5, 4, 5, 3, 4, 4, 5, 3, 4, 3, 4, 2, 3, 
      6, 7, 5, 6, 5, 6, 4, 5, 5, 6, 4, 5, 4, 5, 3, 4
    };

    const uint8_t le_packet::ACCESS_HEADER_DISTANCE_LSB[] = {
      0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 2, 1, 1, 1, 1, 1, 1, 1, 2, 
      2, 2, 2, 2, 2, 2, 2, 3, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 3, 
      2, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 3, 3, 3, 3, 4, 1, 1, 1, 1, 1, 1, 1, 2, 
      2, 2, 2, 2, 2, 2, 2, 3, 2, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 3, 3, 3, 3, 4, 
      2, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 3, 3, 3, 3, 4, 3, 3, 3, 3, 3, 3, 3, 4, 
      4, 4, 4, 4, 4, 4, 4, 5, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 3, 
      2, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 3, 3, 3, 3, 4, 2, 2, 2, 2, 2, 2, 2, 3, 
      3, 3, 3, 3, 3, 3, 3, 4, 3, 3, 3, 3, 3, 3, 3, 4, 4, 4, 4, 4, 4, 4, 4, 5, 
      0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 2, 1, 1, 1, 1, 1, 1, 1, 2, 
      2, 2, 2, 2, 2, 2, 2, 3, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 3, 
      2, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 3, 3, 3, 3, 4
    };

    const uint8_t le_packet::ACCESS_HEADER_DISTANCE_MSB[] = {
      1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 
      1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 1, 1, 
      1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 
      1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 
      2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 
      1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 
      2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 
      3, 3, 3, 3, 3, 3, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 
      2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 
      3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3
    };

    const uint8_t le_packet::DATA_HEADER_DISTANCE_LSB[] = {
      1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 
      1, 0, 0, 0, 1, 0, 0, 0, 2, 1, 1, 1, 2, 1, 1, 1, 2, 1, 1, 1, 2, 1, 1, 1, 
      2, 1, 1, 1, 2, 1, 1, 1, 2, 1, 1, 1, 2, 1, 1, 1, 2, 1, 1, 1, 2, 1, 1, 1, 
      2, 1, 1, 1, 2, 1, 1, 1, 2, 1, 1, 1, 2, 1, 1, 1, 2, 1, 1, 1, 2, 1, 1, 1, 
      3, 2, 2, 2, 3, 2, 2, 2, 3, 2, 2, 2, 3, 2, 2, 2, 3, 2, 2, 2, 3, 2, 2, 2, 
      3, 2, 2, 2, 3, 2, 2, 2, 2, 1, 1, 1, 2, 1, 1, 1, 2, 1, 1, 1, 2, 1, 1, 1, 
      2, 1, 1, 1, 2, 1, 1, 1, 2, 1, 1, 1, 2, 1, 1, 1, 3, 2, 2, 2, 3, 2, 2, 2, 
      3, 2, 2, 2, 3, 2, 2, 2, 3, 2, 2, 2, 3, 2, 2, 2, 3, 2, 2, 2, 3, 2, 2, 2, 
      3, 2, 2, 2, 3, 2, 2, 2, 3, 2, 2, 2, 3, 2, 2, 2, 3, 2, 2, 2, 3, 2, 2, 2, 
      3, 2, 2, 2, 3, 2, 2, 2, 4, 3, 3, 3, 4, 3, 3, 3, 4, 3, 3, 3, 4, 3, 3, 3, 
      4, 3, 3, 3, 4, 3, 3, 3, 4, 3, 3, 3, 4, 3, 3, 3
    };

    const uint8_t le_packet::DATA_HEADER_DISTANCE_MSB[] = {
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 
      0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 
      1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 
      1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 
      2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 
      2, 2, 2, 2, 2, 2, 2, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 
      1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 
      2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 
      2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 
      2, 2, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 
      3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3
    };

    const uint8_t le_packet::INDICES[] = {
      93, 85, 16, 7, 100, 69, 38, 124, 89, 62, 54, 49, 103, 106, 21, 112, 33, 
      58, 31, 77, 18, 40, 56, 23, 81, 11, 29, 117, 109, 72, 75, 43, 63, 50, 
      107, 113, 86, 8, 70, 125
    };

    int
    le_packet::sniff_aa(char *stream, int stream_length, double freq)
    {
      /* Looks for AA */
      int count;
      int index = freq2index( freq );
      int distance = 0;
      const uint8_t *phlsb, *phmsb;

      if (index >= 37) {
        // access channel
        phlsb = ACCESS_HEADER_DISTANCE_LSB;
        phmsb = ACCESS_HEADER_DISTANCE_MSB;
      }
      else if (index < 0) {
        return -1;
      }
      else {
        phlsb = DATA_HEADER_DISTANCE_LSB;
        phmsb = DATA_HEADER_DISTANCE_MSB;
      }

      for( count=0; count<stream_length; count++ ) {
        char *   symbols    = &stream[count];
        uint16_t preamble   = air_to_host16(&symbols[0], 9);
        char hbuf[16];
        unsigned hi, wi;

        // de-whiten 
        for( hi=0, wi=INDICES[index]; hi<16; hi++, wi=(wi+1)%127 ) {
          hbuf[hi] = symbols[hi+40] ^ WHITENING_DATA[wi];
        }

        uint8_t  header_lsb = air_to_host8(&hbuf[0], 8);
        uint8_t  header_msb = air_to_host8(&hbuf[8], 8);

        int preamble_distance = PREAMBLE_DISTANCE[preamble];
        int header_distance   = phlsb[header_lsb] + phmsb[header_msb];       
        int distance          = preamble_distance + header_distance;

        int max_distance = 0;

        if (index >= 37) {
          // access channel
          uint8_t aabyte = air_to_host8(&symbols[8], 8);
          int aa_distance = ACCESS_ADDRESS_DISTANCE_0[aabyte];
          aabyte = air_to_host8(&symbols[16], 8);
          aa_distance += ACCESS_ADDRESS_DISTANCE_1[aabyte];
          aabyte = air_to_host8(&symbols[24], 8);
          aa_distance += ACCESS_ADDRESS_DISTANCE_2[aabyte];
          aabyte = air_to_host8(&symbols[32], 8);
          aa_distance += ACCESS_ADDRESS_DISTANCE_3[aabyte];
          if (!aa_distance && distance) {
            printf( "preamble_distance=%d, header_distance=%d, aa_distance=%d\n", 
                    preamble_distance, header_distance, aa_distance );
            if (preamble_distance) {
              printf( "preamble=0x%03x\n", preamble );
            }
            if (header_distance) {
              printf( "de_whitened: header_lsb=0x%02x, header_msb=0x%02x\n", header_lsb, header_msb );
              uint8_t  raw_lsb = air_to_host8(&stream[40], 8);
              uint8_t  raw_msb = air_to_host8(&stream[48], 8);
              printf( "raw:         header_lsb=0x%02x, header_msb=0x%02x\n", raw_lsb, raw_msb );
            }
          }
          distance += aa_distance;
          max_distance += 2;
        }

        if (distance <= max_distance) {
          return count;
        }
      }

      return -1;
    }

    le_packet_impl::le_packet_impl(char *stream, int length, double freq)
      : packet(stream, length, freq)
    {
      d_index = freq2index( freq );

      (void) ::memcpy( &d_link_symbols[0], stream, LE_MAX_SYMBOLS );

      unsigned i, wi = INDICES[d_index];
      for( i=40; i<LE_MAX_SYMBOLS; i++, wi=(wi+1)%127 ) {
        d_link_symbols[i] ^= WHITENING_DATA[wi];
      }

      d_AA             = air_to_host32(&d_link_symbols[8], 32);
      d_whitened       = true;
      d_have_payload   = false;
      d_payload_length = 0;

      uint16_t header = air_to_host16(&d_link_symbols[40], 16);
      if (d_index >= 37) {
        d_PDU_Type   = (header >> 0) & 0xf;
        d_TxAdd      = (header >> 6) & 1;
        d_RxAdd      = (header >> 7) & 1;
        d_PDU_Length = (header >> 8) & 0x3f;
      }
      else {
        d_LLID       = (header >> 0) & 3;
        d_NESN       = (header >> 2) & 1;
        d_SN         = (header >> 3) & 1;
        d_MD         = (header >> 4) & 1;
        d_PDU_Length = (header >> 8) & 0x1f;
      }

      unsigned pi;
      for( pi=0, i=56; i+8<LE_MAX_SYMBOLS; pi++, i+=8 ) {
        d_pdu[pi] = air_to_host8(&d_link_symbols[i], 8);
      }
    }

    le_packet_impl::~le_packet_impl( )
    {
    }

    bool le_packet_impl::decode_header()
    {
      return false; // FIXME: TODO
    }
    
    void le_packet_impl::decode_payload()
    {
      // FIXME: TODO
    }
           
    void le_packet_impl::print()
    {
      unsigned i;

      if (d_index >= 37) {
        printf( "BTLE index=%02d, AA=%08x, PDUType=%d, TxAdd=%d, RxAdd=%d, Length=%d\n", 
                d_index, d_AA, d_PDU_Type, d_TxAdd, d_RxAdd, d_PDU_Length );
        switch(d_PDU_Type) {
        case 0:
        case 2:
        case 4:
        case 6:
          printf( "  AdvA=%02x%02x%02x%02x%02x%02x\n", 
                  d_pdu[0], d_pdu[1], d_pdu[2], d_pdu[3], d_pdu[4], d_pdu[5] );
          if (d_PDU_Type == 4) {
            printf( "\n  (char) ScanRspData=" );
          }
          else {
            printf( "\n  (char) AdvData=" );
          }
          for( i=6; i<d_PDU_Length; i++ ) {
            char c = (char) d_pdu[i];
            if ((c < ' ') || (c > '~')) {
              c = '.';
            }
            printf( " %c", c );
          }
          if (d_PDU_Type == 4) {
            printf( "\n  (byte) ScanRspData=" );
          }
          else {
            printf( "\n  (byte) AdvData=" );
          }
          for( i=6; i<d_PDU_Length; i++ ) {
            printf( "%02x", d_pdu[i] );
          }
          printf( "\n" );
          break;
        case 1:
          printf( "  AdvA=%02x%02x%02x%02x%02x%02x\n"
                  "  InitA=%02x%02x%02x%02x%02x%02x\n",
                  d_pdu[0], d_pdu[1], d_pdu[2], d_pdu[3], d_pdu[4], d_pdu[5],
                  d_pdu[6], d_pdu[7], d_pdu[8], d_pdu[9], d_pdu[10], d_pdu[11] );
          break;
        case 3:
          printf( "  ScanA=%02x%02x%02x%02x%02x%02x\n"
                  "  AdvA=%02x%02x%02x%02x%02x%02x\n",
                  d_pdu[0], d_pdu[1], d_pdu[2], d_pdu[3], d_pdu[4], d_pdu[5],
                  d_pdu[6], d_pdu[7], d_pdu[8], d_pdu[9], d_pdu[10], d_pdu[11] );
          break;
        case 5:
          printf( "  InitA=%02x%02x%02x%02x%02x%02x\n"
                  "  AdvA=%02x%02x%02x%02x%02x%02x\n",
                  d_pdu[0], d_pdu[1], d_pdu[2], d_pdu[3], d_pdu[4], d_pdu[5],
                  d_pdu[6], d_pdu[7], d_pdu[8], d_pdu[9], d_pdu[10], d_pdu[11] );
          {
            uint32_t AA        = d_pdu[12] | (((uint32_t) d_pdu[13]) << 8) |
              (((uint32_t) d_pdu[14]) << 16) | (((uint32_t) d_pdu[15]) << 24);
            uint32_t CRCInit   = d_pdu[16] | (((uint32_t) d_pdu[17]) << 8) |
              (((uint32_t) d_pdu[18]) << 16);
            uint8_t  WinSize   = d_pdu[19];
            uint16_t WinOffset = d_pdu[20] | (((uint16_t) d_pdu[21]) << 8);
            uint16_t Interval  = d_pdu[22] | (((uint16_t) d_pdu[23]) << 8);
            uint16_t Latency   = d_pdu[24] | (((uint16_t) d_pdu[25]) << 8);
            uint16_t Timeout   = d_pdu[26] | (((uint16_t) d_pdu[27]) << 8);
            uint64_t ChM       = d_pdu[28] | (((uint64_t) d_pdu[29]) << 8) |
              (((uint64_t) d_pdu[30]) << 16) | (((uint64_t) d_pdu[31]) << 24) |
              (((uint64_t) d_pdu[32]) << 32);
            uint8_t  Hop       = d_pdu[33] & 0x1f;
            uint8_t  SCA       = (d_pdu[33] >> 5) & 7;
            printf( "  AA=%08x, CRCInit=%06x, WinSize=%d, WinOffset=%d\n",
                    AA, CRCInit, WinSize, WinOffset );
            printf( "  Interval=%d, Latency=%d, Timeout=%d, ChM=%010lx, Hop=%d, SCA=%d\n",
                    Interval, Latency, Timeout, ChM, Hop, SCA );
          }
          break;
        default:
          break;
        }
      }
      else {
        printf( "BTLE index=%02d, AA=%08x, LLID=%d, NESN=%d, SN=%d, MD=%d, Length=%d\n", 
                d_index, d_AA, d_LLID, d_NESN, d_SN, d_MD, d_PDU_Length );
      }
    }
      
    char *le_packet_impl::tun_format()
    {
      return (char*)calloc(256,1); // FIXME: TODO
    }
      
    bool le_packet_impl::header_present()
    {
      return false; // FIXME: TODO
    }

  } /* namespace bluetooth */
} /* namespace gr */

