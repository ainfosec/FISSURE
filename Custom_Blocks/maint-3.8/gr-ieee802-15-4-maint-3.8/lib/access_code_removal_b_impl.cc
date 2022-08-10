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
#include "access_code_removal_b_impl.h"

namespace gr {
  namespace ieee802_15_4 {

    access_code_removal_b::sptr
    access_code_removal_b::make(int len_payload)
    {
      return gnuradio::get_initial_sptr
        (new access_code_removal_b_impl(len_payload));
    }

    /*
     * The private constructor
     */
    access_code_removal_b_impl::access_code_removal_b_impl(int len_payload)
      : gr::sync_block("access_code_removal_b",
              gr::io_signature::make(1,1, sizeof(unsigned char)),
              gr::io_signature::make(0, 0, 0))
    {
      d_len_payload = len_payload;
      if(d_len_payload >= 0)
        d_fixed_payload_len = true;
      else
        d_fixed_payload_len = false;

      d_byte_ctr = 0;

      message_port_register_out(pmt::mp("out"));
    }

    /*
     * Our virtual destructor.
     */
    access_code_removal_b_impl::~access_code_removal_b_impl()
    {
    }

    void
    access_code_removal_b_impl::extract_payload()
    {
      pmt::pmt_t packet = pmt::make_blob(d_buf+d_len_SHR+d_len_PHR, d_len_payload);
      message_port_pub(pmt::mp("out"), pmt::cons(pmt::PMT_NIL, packet));
      // std::cout << "access_code_removal_b sent a message" << std::endl;
    }

    int
    access_code_removal_b_impl::work(int noutput_items,
			  gr_vector_const_void_star &input_items,
			  gr_vector_void_star &output_items)
    {
        const unsigned char *in = (const unsigned char *) input_items[0];

        for(int i=0; i<noutput_items; i++)
        {
          d_buf[d_byte_ctr] = in[i];
          d_byte_ctr++;
          if(d_byte_ctr == d_len_SHR + d_len_PHR) // PHR byte
          {
            if(!d_fixed_payload_len)
            {
              d_len_payload = int(d_buf[d_len_SHR]);
              if(d_len_payload > 127)
                throw std::runtime_error("Payload length must not exceed 127 bytes");
            // std::cout << "payload length: " << d_len_payload << std::endl;
            }
          }
          else if(d_byte_ctr == d_len_payload + d_len_SHR + d_len_PHR && d_len_payload >= 0)
          {
            extract_payload();
            d_byte_ctr = 0;
          }
        }

        return noutput_items;
    }

  } /* namespace ieee802_15_4 */
} /* namespace gr */

