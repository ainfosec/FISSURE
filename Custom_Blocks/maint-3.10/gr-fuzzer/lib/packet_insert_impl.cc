/* -*- c++ -*- */
/*
 * Copyright 2022 gr-fuzzer author.
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

#include "packet_insert_impl.h"
#include <algorithm>
#include <gnuradio/io_signature.h>
#include <stdexcept>
#include <stdio.h>

namespace gr {
  namespace fuzzer {

    packet_insert::sptr
    packet_insert::make(const std::vector<unsigned char> &data, int periodicity, int offset)
    {
      return gnuradio::get_initial_sptr
        (new packet_insert_impl(data, periodicity, offset));
    }


    /*
     * The private constructor
     */
    packet_insert_impl::packet_insert_impl(const std::vector<unsigned char> &data,
                             int periodicity, int offset)
      : gr::block("packet_insert",
               gr::io_signature::make(1, 1, sizeof(unsigned char)),
               gr::io_signature::make(1, 1, sizeof(unsigned char))),
      d_data(data),
      d_offset(offset),
      d_periodicity(periodicity)
    {

      d_length = 0;
      message_port_register_in(pmt::mp("packet_in"));
      message_port_register_out(pmt::mp("set_mute"));
      
      set_msg_handler(pmt::mp("packet_in"), [this](pmt::pmt_t msg) { this->read_message(msg); });
        
      // some sanity checks
      assert(offset < periodicity);
      assert(offset >= 0);
      assert((size_t)periodicity > data.size());        
        
    }

    /*
     * Our virtual destructor.
     */
    packet_insert_impl::~packet_insert_impl()
    {
    }

    int packet_insert_impl::general_work (int noutput_items,
                       gr_vector_int &ninput_items,
                       gr_vector_const_void_star &input_items,
                       gr_vector_void_star &output_items)
    {
      unsigned char *out = (unsigned char *)output_items[0];
      const unsigned char *in = (const unsigned char *)input_items[0];
      
      int ii(0), oo(0);

      while((oo < noutput_items) && (ii < ninput_items[0])) {
        if((d_offset >= ((int)d_data.size())) || ((int)d_length == 0)) { // if we are in the copy region
          int max_copy = std::min(std::min(noutput_items - oo, ninput_items[0] - ii),
                                  d_periodicity - d_offset);
          memcpy( &out[oo], &in[ii], sizeof(unsigned char)*max_copy );
          ii += max_copy;
          oo += max_copy;
          d_offset = (d_offset + max_copy)%(d_periodicity);
          
        }
        else { // if we are in the insertion region
          int max_copy = std::min(noutput_items - oo, ((int)d_length) - d_offset);
          memcpy(&out[oo], &d_data1[d_offset], sizeof(unsigned char)*max_copy);
          oo += max_copy;
          d_offset = (d_offset + max_copy)%(d_periodicity);
        }
      }
      
      consume_each(ii);
      return oo;
    }
    
    
    void packet_insert_impl::read_message(pmt::pmt_t msg)
    {    
      d_length = pmt::length(msg);
      long temp_byte = 0;
      unsigned char temp_byte_char = 0;
      
      for (int i = 0; i < d_length; ++i)
      {
          pmt::pmt_t element = pmt::nth(i,msg);
          temp_byte = pmt::to_long(element);
          temp_byte_char = (unsigned char) temp_byte;
          d_data1[i] = temp_byte_char;
      }
    }    

  } /* namespace fuzzer */
} /* namespace gr */

