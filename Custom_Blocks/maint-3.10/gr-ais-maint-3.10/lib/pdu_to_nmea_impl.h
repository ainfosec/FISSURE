/* -*- c++ -*- */
/* 
 * Copyright 2014 <+YOU OR YOUR COMPANY+>.
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

#ifndef INCLUDED_AIS_PDU_TO_NMEA_IMPL_H
#define INCLUDED_AIS_PDU_TO_NMEA_IMPL_H

#include <gnuradio/ais/pdu_to_nmea.h>
#include <pmt/pmt.h>
#include <string>

namespace gr {
  namespace ais {

    class pdu_to_nmea_impl : public pdu_to_nmea
    {
     private:
         void print(pmt::pmt_t msg);
         void to_nmea(pmt::pmt_t msg);
         std::vector<uint8_t> unpack_bits(pmt::pmt_t msg, uint8_t *npad);
         std::string to_ascii(std::vector<uint8_t> msg);
         uint8_t get_checksum(std::string &msg);
         std::string to_sentence(std::string ascii, uint8_t npad);
         std::string msg_to_sentence(pmt::pmt_t msg);

         std::string d_designator;

     public:
      pdu_to_nmea_impl(std::string designator);
      ~pdu_to_nmea_impl();
    };

  } // namespace ais
} // namespace gr

#endif /* INCLUDED_AIS_PDU_TO_NMEA_IMPL_H */

