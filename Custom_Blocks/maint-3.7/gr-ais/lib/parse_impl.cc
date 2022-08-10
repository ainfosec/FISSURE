/* -*- c++ -*- */
/* 
 * Copyright 2013 <+YOU OR YOUR COMPANY+>.
 * 
 * This is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3, or (at your option)
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
#include "parse_impl.h"
#include <gnuradio/tags.h>
#include <iostream>
#include <sstream>
#include <iomanip>

#define VERBOSE 0

namespace gr {
  namespace ais {

    parse::sptr
    parse::make(gr::msg_queue::sptr queue, char designator)
    {
      return gnuradio::get_initial_sptr
        (new parse_impl(queue, designator));
    }

    /*
     * The private constructor
     */
    parse_impl::parse_impl(gr::msg_queue::sptr queue, char designator)
      : gr::sync_block("parse",
              gr::io_signature::make(1, 1, sizeof(char)),
              gr::io_signature::make(0, 0, 0)),
              d_queue(queue),
              d_designator(designator)
    {
        set_output_multiple(1000);
    }

    /*
     * Our virtual destructor.
     */
    parse_impl::~parse_impl()
    {
    }

    int
    parse_impl::work(int noutput_items,
                    gr_vector_const_void_star &input_items,
                    gr_vector_void_star &output_items)
    {
        const char *in = (const char *) input_items[0];

        int size = noutput_items - 500; //we need to be able to look at least this far forward
        if(size <= 0) return 0;

        //look ma, no state machine
        //instead of iterating through in[] looking for things, we'll just pull up all the start/stop tags and use those to look for packets
        std::vector<gr::tag_t> preamble_tags, start_tags, end_tags;
        uint64_t abs_sample_cnt = nitems_read(0);
        get_tags_in_range(preamble_tags, 0, abs_sample_cnt, abs_sample_cnt + size, pmt::string_to_symbol("ais_preamble"));
        if(preamble_tags.size() == 0) return size; //sad trombone

        //look for start & end tags within a reasonable range
        uint64_t preamble_mark = preamble_tags[0].offset;
        if(VERBOSE) std::cout << "Found a preamble at " << preamble_mark << std::endl;

        //now look for a start tag within reasonable range of the preamble
        get_tags_in_range(start_tags, 0, preamble_mark, preamble_mark + 30, pmt::string_to_symbol("ais_frame"));
        if(start_tags.size() == 0) return preamble_mark + 30 - abs_sample_cnt; //nothing here, move on (should update d_num_startlost)
        uint64_t start_mark = start_tags[0].offset;
        if(VERBOSE) std::cout << "Found a start tag at " << start_mark << std::endl;

        //now look for an end tag within reasonable range of the preamble
        get_tags_in_range(end_tags, 0, start_mark + 184, start_mark + 450, pmt::string_to_symbol("ais_frame"));
        if(end_tags.size() == 0) return preamble_mark + 450 - abs_sample_cnt; //should update d_num_stoplost
        uint64_t end_mark = end_tags[0].offset;
        if(VERBOSE) std::cout << "Found an end tag at " << end_mark << std::endl;

        //now we've got a valid, framed packet
        uint64_t datalen = end_mark - start_mark - 8; //includes CRC, discounts end of frame marker
        if(VERBOSE) std::cout << "Found packet with length " << datalen << std::endl;
        char *pkt = new char[datalen];

        memcpy(pkt, &in[start_mark-abs_sample_cnt], datalen);
        parse_data(pkt, datalen);
        delete(pkt);
        return end_mark - abs_sample_cnt;
    }

    unsigned long unpack(char *buffer, int start, int length)
    {
        unsigned long ret = 0;
        for(int i = start; i < (start+length); i++) {
            ret <<= 1;
            ret |= (buffer[i] & 0x01);
        }
        return ret;
    }

    void reverse_bit_order(char *data, int length)
    {
        int tmp = 0;
        for(int i = 0; i < length/8; i++) {
            for(int j = 0; j < 4; j++) {
                tmp = data[i*8 + j];
                data[i*8 + j] = data[i*8 + 7-j];
                data[i*8 + 7-j] = tmp;
            }
        }
    }

    char nmea_checksum(std::string buffer)
    {
        unsigned int i = 0;
        char sum = 0x00;
        if(buffer[0] == '!') i++;
        for(; i < buffer.length(); i++) sum ^= buffer[i];
        return sum;
    }

    unsigned short crc(char *buffer, unsigned int len) // Calculates CRC-checksum from unpacked data
    {
        static const uint16_t crc_itu16_table[] =
        {
        0x0000, 0x1189, 0x2312, 0x329B, 0x4624, 0x57AD, 0x6536, 0x74BF,
        0x8C48, 0x9DC1, 0xAF5A, 0xBED3, 0xCA6C, 0xDBE5, 0xE97E, 0xF8F7,
        0x1081, 0x0108, 0x3393, 0x221A, 0x56A5, 0x472C, 0x75B7, 0x643E,
        0x9CC9, 0x8D40, 0xBFDB, 0xAE52, 0xDAED, 0xCB64, 0xF9FF, 0xE876,
        0x2102, 0x308B, 0x0210, 0x1399, 0x6726, 0x76AF, 0x4434, 0x55BD,
        0xAD4A, 0xBCC3, 0x8E58, 0x9FD1, 0xEB6E, 0xFAE7, 0xC87C, 0xD9F5,
        0x3183, 0x200A, 0x1291, 0x0318, 0x77A7, 0x662E, 0x54B5, 0x453C,
        0xBDCB, 0xAC42, 0x9ED9, 0x8F50, 0xFBEF, 0xEA66, 0xD8FD, 0xC974,
        0x4204, 0x538D, 0x6116, 0x709F, 0x0420, 0x15A9, 0x2732, 0x36BB,
        0xCE4C, 0xDFC5, 0xED5E, 0xFCD7, 0x8868, 0x99E1, 0xAB7A, 0xBAF3,
        0x5285, 0x430C, 0x7197, 0x601E, 0x14A1, 0x0528, 0x37B3, 0x263A,
        0xDECD, 0xCF44, 0xFDDF, 0xEC56, 0x98E9, 0x8960, 0xBBFB, 0xAA72,
        0x6306, 0x728F, 0x4014, 0x519D, 0x2522, 0x34AB, 0x0630, 0x17B9,
        0xEF4E, 0xFEC7, 0xCC5C, 0xDDD5, 0xA96A, 0xB8E3, 0x8A78, 0x9BF1,
        0x7387, 0x620E, 0x5095, 0x411C, 0x35A3, 0x242A, 0x16B1, 0x0738,
        0xFFCF, 0xEE46, 0xDCDD, 0xCD54, 0xB9EB, 0xA862, 0x9AF9, 0x8B70,
        0x8408, 0x9581, 0xA71A, 0xB693, 0xC22C, 0xD3A5, 0xE13E, 0xF0B7,
        0x0840, 0x19C9, 0x2B52, 0x3ADB, 0x4E64, 0x5FED, 0x6D76, 0x7CFF,
        0x9489, 0x8500, 0xB79B, 0xA612, 0xD2AD, 0xC324, 0xF1BF, 0xE036,
        0x18C1, 0x0948, 0x3BD3, 0x2A5A, 0x5EE5, 0x4F6C, 0x7DF7, 0x6C7E,
        0xA50A, 0xB483, 0x8618, 0x9791, 0xE32E, 0xF2A7, 0xC03C, 0xD1B5,
        0x2942, 0x38CB, 0x0A50, 0x1BD9, 0x6F66, 0x7EEF, 0x4C74, 0x5DFD,
        0xB58B, 0xA402, 0x9699, 0x8710, 0xF3AF, 0xE226, 0xD0BD, 0xC134,
        0x39C3, 0x284A, 0x1AD1, 0x0B58, 0x7FE7, 0x6E6E, 0x5CF5, 0x4D7C,
        0xC60C, 0xD785, 0xE51E, 0xF497, 0x8028, 0x91A1, 0xA33A, 0xB2B3,
        0x4A44, 0x5BCD, 0x6956, 0x78DF, 0x0C60, 0x1DE9, 0x2F72, 0x3EFB,
        0xD68D, 0xC704, 0xF59F, 0xE416, 0x90A9, 0x8120, 0xB3BB, 0xA232,
        0x5AC5, 0x4B4C, 0x79D7, 0x685E, 0x1CE1, 0x0D68, 0x3FF3, 0x2E7A,
        0xE70E, 0xF687, 0xC41C, 0xD595, 0xA12A, 0xB0A3, 0x8238, 0x93B1,
        0x6B46, 0x7ACF, 0x4854, 0x59DD, 0x2D62, 0x3CEB, 0x0E70, 0x1FF9,
        0xF78F, 0xE606, 0xD49D, 0xC514, 0xB1AB, 0xA022, 0x92B9, 0x8330,
        0x7BC7, 0x6A4E, 0x58D5, 0x495C, 0x3DE3, 0x2C6A, 0x1EF1, 0x0F78
        };

        unsigned short crc=0xffff;
        int i = 0;

        int datalen = len/8;

        char data[256];
        for(int j=0;j<datalen;j++) //this unpacks the data in preparation for calculating CRC
        {
            data[j] = unpack(buffer, j*8, 8);
        }

        for (i = 0;  i < datalen;  i++)
            crc = (crc >> 8) ^ crc_itu16_table[(crc ^ data[i]) & 0xFF];

        return (crc & 0xFFFF) != 0xF0B8;
    }

    void parse_impl::parse_data(char *data, int len)
    {
        d_payload.str("");

        char asciidata[255]; //168/6 bits per ascii char
        reverse_bit_order(data, len); //the AIS standard has bits come in backwards for some inexplicable reason
        if(crc(data, len)) {
            if(VERBOSE) std::cout << "Failed CRC!" << std::endl;
            return; //don't make a message if crc fails
        }

        len -= 16; //strip off CRC

        for(int i = 0; i < len/6; i++) {
            asciidata[i] = unpack(data, i*6, 6);
            if(asciidata[i] > 39) asciidata[i] += 8;
            asciidata[i] += 48;
        }

        //hey just a note, NMEA sentences are limited to 82 characters. the 448-bit long AIS messages end up longer than 82 encoded chars.
        //so technically, the below is not valid as it does not split long sentences for you. the upside is that ESR's GPSD (recommended for this use)
        //ignores this length restriction and parses them anyway. but this might bite you if you use this program with other parsers.
        //you should probably write something to split the sentences here. shouldn't be hard at all.
        //if(debug) d_payload << "BAD PACKET: ";
        d_payload << "!AIVDM,1,1,," << d_designator << ",";
        for(int i = 0; i < len/6; i++) d_payload << asciidata[i];
        d_payload << ",0"; //number of bits to fill out 6-bit boundary

        char checksum = nmea_checksum(std::string(d_payload.str()));
        d_payload << "*" << std::setw(2) << std::setfill('0') << std::hex << std::uppercase << int(checksum);

        //ptooie
        gr::message::sptr msg = gr::message::make_from_string(std::string(d_payload.str()));
        d_queue->handle(msg);
    }


  } /* namespace ais */
} /* namespace gr */

