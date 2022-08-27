/* -*- c++ -*- */
/* 
 * Copyright 2015 Nick Foster
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

#include <cstdio>
#include <functional>
#include <gnuradio/io_signature.h>
#include "pdu_to_nmea_impl.h"

namespace gr {
  namespace ais {

    pdu_to_nmea::sptr
    pdu_to_nmea::make(std::string designator)
    {
      return gnuradio::get_initial_sptr
        (new pdu_to_nmea_impl(designator));
    }

    /*
     * The private constructor
     */
    pdu_to_nmea_impl::pdu_to_nmea_impl(std::string designator)
      : block("pdu_to_nmea",
              io_signature::make(0,0,0),
              io_signature::make(0,0,0)),
        d_designator(designator)
    {
        message_port_register_in(pmt::mp("print"));
        set_msg_handler(pmt::mp("print"), std::bind(&pdu_to_nmea_impl::print, this, std::placeholders::_1));
        message_port_register_in(pmt::mp("to_nmea"));
        set_msg_handler(pmt::mp("to_nmea"), std::bind(&pdu_to_nmea_impl::to_nmea, this, std::placeholders::_1));
        message_port_register_out(pmt::mp("out"));
    }

    /*
     * Our virtual destructor.
     */
    pdu_to_nmea_impl::~pdu_to_nmea_impl()
    {
    }

    //TODO: test with padding more thoroughly
    std::vector<uint8_t> pdu_to_nmea_impl::unpack_bits(pmt::pmt_t msg, uint8_t *npad) {
        const uint8_t *p = (const uint8_t *) pmt::blob_data(pmt::cdr(msg));
        int len = pmt::blob_length(pmt::cdr(msg));
        int nbits = len*8;
        *npad = (6-(nbits % 6)) % 6;
        int padded_len = nbits+*npad;
        std::vector<uint8_t> up(padded_len/6, 0);
        for(int i=0; i<nbits; i++) {
            uint8_t bit = (p[i/8] >> (7-(i%8))) & 1;
            up[i/6] |= (bit << (5-(i%6)));
        }
        for(int i=0;i<*npad; i++) {
            up[nbits/6] <<= 1;
        }

        return up;
    }

    std::string pdu_to_nmea_impl::to_ascii(std::vector<uint8_t> msg) {
        std::string ret(msg.begin(), msg.end());
        for(int i=0; i<ret.size(); i++) {
            if(ret[i] > 39) ret[i] += 8;
            ret[i] += char(48);
        }
        return ret;
    }

    uint8_t pdu_to_nmea_impl::get_checksum(std::string &msg) {
        unsigned int i = 0;
        uint8_t sum = 0x00;
        if(msg[0] == '!') i++;
        for(; i < msg.length(); i++) sum ^= msg[i];
        return sum;
    }


    std::string pdu_to_nmea_impl::to_sentence(std::string ascii, uint8_t npad) {
        int frag_id = 1;
        int frag_offset = 0;
        std::string ret;
        const int nmea_max=56; //minus overhead from sentence structure
        const int num_frags = 1+((ascii.length()-1) / nmea_max);
        while(frag_id <= num_frags) {
            if(frag_id > 1) ret += "\n";
            std::string this_sentence =  "!AIVDM,"
                                         + std::to_string(num_frags)
                                         + ","
                                         + std::to_string(frag_id++)
                                         + ",,"
                                         + d_designator
                                         + ",";

            std::string this_frag = ascii.substr(frag_offset, nmea_max);
            frag_offset += this_frag.length();
            this_sentence += this_frag + "," + std::to_string(int(npad));
            char wat[3];
            uint8_t checksum = get_checksum(this_sentence);
            snprintf(wat, 3, "%02X", checksum); //NMEA 0183 checksum
            this_sentence += "*" + std::string(wat);
            ret += this_sentence;
        }
        return ret;
    }

    std::string pdu_to_nmea_impl::msg_to_sentence(pmt::pmt_t msg) {
        uint8_t npad;
        std::vector<uint8_t> unpacked = unpack_bits(msg, &npad);
        return to_sentence(to_ascii(unpacked), npad);
    }

    void pdu_to_nmea_impl::print(pmt::pmt_t msg) {
        std::cout << msg_to_sentence(msg) << std::endl;
    }

    void pdu_to_nmea_impl::to_nmea(pmt::pmt_t msg) {
        std::string aivdm = msg_to_sentence(msg);
        //make PDU
        pmt::pmt_t pdu(pmt::cons(pmt::PMT_NIL,
                                 pmt::init_u8vector(aivdm.length(), (uint8_t *)aivdm.c_str())));
        //post to output port
        message_port_pub(pmt::mp("out"), pdu);
    }
  } /* namespace ais */
} /* namespace gr */

