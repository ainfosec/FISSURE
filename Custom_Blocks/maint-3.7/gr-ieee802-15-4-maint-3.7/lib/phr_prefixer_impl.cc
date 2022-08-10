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
#include <gnuradio/block_detail.h>
#include "phr_prefixer_impl.h"

namespace gr {
  namespace ieee802_15_4 {

    phr_prefixer::sptr
    phr_prefixer::make(std::vector<unsigned char> phr)
    {
      return gnuradio::get_initial_sptr
        (new phr_prefixer_impl(phr));
    }

    /*
     * The private constructor
     */
    phr_prefixer_impl::phr_prefixer_impl(std::vector<unsigned char> phr)
      : gr::block("phr_prefixer",
              gr::io_signature::make(0,0,0),
              gr::io_signature::make(0,0,0))
    {
      // check input dimensions and prepare the buffer with the (static) PHR
      if(phr.size() != PHR_LEN)
        throw std::runtime_error("PHR size must be 12 (unpacked)");
      d_buf = new unsigned char[127*8+PHR_LEN]; // maximum length
      memcpy(d_buf, &phr[0], sizeof(unsigned char)*PHR_LEN);

      // define message ports
      message_port_register_out(pmt::mp("out"));
      message_port_register_in(pmt::mp("in"));
      set_msg_handler(pmt::mp("in"), boost::bind(&phr_prefixer_impl::prefix_phr, this, _1));
    }

    /*
     * Our virtual destructor.
     */
    phr_prefixer_impl::~phr_prefixer_impl()
    {
      delete[] d_buf;
    }

    void
    phr_prefixer_impl::prefix_phr(pmt::pmt_t msg)
    {
      if(pmt::is_eof_object(msg)) 
      {
        message_port_pub(pmt::mp("out"), pmt::PMT_EOF);
        detail().get()->set_done(true);
        return;
      }      

      if(!pmt::is_pair(msg))
        throw std::runtime_error("Input PMT is not of type pair");

      pmt::pmt_t blob = pmt::cdr(msg);
      size_t data_len = pmt::blob_length(blob);
      if(data_len > 127)
        throw std::runtime_error("Payload length exceeds the maximum 127 bytes"); 
      unsigned char* blob_ptr = (unsigned char*) pmt::blob_data(blob);
      unpack(d_buf+PHR_LEN, blob_ptr, data_len);
      pmt::pmt_t packet = pmt::make_blob(&d_buf[0], data_len*8+PHR_LEN);
      message_port_pub(pmt::mp("out"), pmt::cons(pmt::PMT_NIL, packet));
    }

    void
    phr_prefixer_impl::unpack(unsigned char* dest_unpacked, unsigned char* src_packed, int nbytes)
    {
      // extract bits from left to right (to preserve the order at byte boundaries) and copy them into the buffer   
      for(int i=0; i<nbytes; i++)
      {
        // std::cout << "\ninput byte: " << unsigned(src_packed[i]) << ", bits:";
        for(int k=0; k<8; k++)
        {
          dest_unpacked[(i+1)*8-k-1] = ((src_packed[i] >> k) & 0x01);
        }
        // for(int k=0;k<8; k++)
        //   std::cout << " " << unsigned(dest_unpacked[i*8+k]);
      }  
    }
  } /* namespace ieee802_15_4 */
} /* namespace gr */

