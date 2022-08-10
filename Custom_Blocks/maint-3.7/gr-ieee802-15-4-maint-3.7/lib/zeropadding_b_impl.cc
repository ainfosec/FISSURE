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
#include "zeropadding_b_impl.h"

namespace gr {
  namespace ieee802_15_4 {

    zeropadding_b::sptr
    zeropadding_b::make(int nzeros)
    {
      return gnuradio::get_initial_sptr
        (new zeropadding_b_impl(nzeros));
    }

    /*
     * The private constructor
     */
    zeropadding_b_impl::zeropadding_b_impl(int nzeros)
      : gr::block("zeropadding_b",
              gr::io_signature::make(0,0,0),
              gr::io_signature::make(1,1,sizeof(unsigned char))),
      d_nzeros(nzeros)
    {
      d_buf.clear();

      // define message port
      message_port_register_in(pmt::mp("in"));
      set_msg_handler(pmt::mp("in"), boost::bind(&zeropadding_b_impl::pad_zeros, this, _1));      
    }

    /*
     * Our virtual destructor.
     */
    zeropadding_b_impl::~zeropadding_b_impl()
    {
    }

    void
    zeropadding_b_impl::pad_zeros(pmt::pmt_t msg)
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
      unsigned char* blob_ptr = (unsigned char*) pmt::blob_data(blob);
      // push blob content into buffer
      for(int i=0; i<data_len; i++)
        d_buf.push_back(blob_ptr[i]);
      // pad zeros
      for(int i=0; i<d_nzeros; i++)
        d_buf.push_back(0);
    }

    int
    zeropadding_b_impl::general_work (int noutput_items,
                       gr_vector_int &ninput_items,
                       gr_vector_const_void_star &input_items,
                       gr_vector_void_star &output_items)
    {
        unsigned char *out = (unsigned char *) output_items[0];

        noutput_items = std::min(noutput_items, int(d_buf.size()));
        memcpy(out, &d_buf[0], sizeof(unsigned char)*noutput_items);       
        d_buf.erase(d_buf.begin(), d_buf.begin()+noutput_items);

        return noutput_items;
    }

  } /* namespace ieee802_15_4 */
} /* namespace gr */

