/* -*- c++ -*- */
/* 
 * Copyright 2015 Felix Wunsch, Communications Engineering Lab (CEL) / Karlsruhe Institute of Technology (KIT) <wunsch.felix@googlemail.com>.
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
#include "phr_removal_impl.h"

namespace gr {
  namespace ieee802_15_4 {

    phr_removal::sptr
    phr_removal::make(std::vector<unsigned char> phr)
    {
      return gnuradio::get_initial_sptr
        (new phr_removal_impl(phr));
    }

    /*
     * The private constructor
     */
    phr_removal_impl::phr_removal_impl(std::vector<unsigned char> phr)
      : gr::block("phr_removal",
              gr::io_signature::make(0,0,0),
              gr::io_signature::make(0,0,0))
    {
      if(phr.size() != PHR_LEN)
        throw std::runtime_error("PHR size must be 12 (unpacked)");

      // define message ports
      message_port_register_out(pmt::mp("out"));
      message_port_register_in(pmt::mp("in"));
      set_msg_handler(pmt::mp("in"), boost::bind(&phr_removal_impl::remove_phr, this, _1));
    }

    /*
     * Our virtual destructor.
     */
    phr_removal_impl::~phr_removal_impl()
    {
    }

    void
    phr_removal_impl::remove_phr(pmt::pmt_t msg)
    {
      if(!pmt::is_pair(msg))
        throw std::runtime_error("Input PMT is not of type pair");

      unsigned char dest[1];
      unsigned char src[8] = {0,0,0,0,0,1,1,1};
      pack(dest, src, 1);
      // std::cout << int(*dest) << std::endl;

      pmt::pmt_t blob = pmt::cdr(msg);
      size_t data_len = pmt::blob_length(blob);
      int payload_len = data_len - PHR_LEN;
      if(payload_len > MAX_PHY_SIZE*8)
        throw std::runtime_error("Payload length exceeds the maximum 127 bytes"); 
      if(payload_len % 8 != 0)
        throw std::runtime_error("Number of payload bits must be an integer multiple of 8");
      unsigned char* blob_ptr = (unsigned char*) pmt::blob_data(blob);      
      pack(d_buf, blob_ptr+PHR_LEN, payload_len/8);
      pmt::pmt_t packet = pmt::make_blob(d_buf, payload_len/8);
      message_port_pub(pmt::mp("out"), pmt::cons(pmt::PMT_NIL, packet));
    }

    void
    phr_removal_impl::pack(unsigned char* dest_packed, unsigned char* src_unpacked, int nbytes)
    {
      unsigned char tmp;
      for(int i=0; i<nbytes; i++)
      {
        tmp = 0;
        for(int k=0; k<8; k++)
        {
          // std::cout << int(src_unpacked[(i+1)*8-k-1]) << " shifted by " << k << " is " <<  (src_unpacked[(i+1)*8-1-k] << k) << std::endl;
          tmp += src_unpacked[(i+1)*8-k-1] << k;
        }
        // std::cout << std::endl;
        dest_packed[i] = tmp;
      }
    }
  } /* namespace ieee802_15_4 */
} /* namespace gr */

