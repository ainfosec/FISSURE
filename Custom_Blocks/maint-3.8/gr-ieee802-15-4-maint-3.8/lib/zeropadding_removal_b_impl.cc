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
#include "zeropadding_removal_b_impl.h"

namespace gr {
  namespace ieee802_15_4 {

    zeropadding_removal_b::sptr
    zeropadding_removal_b::make(int phr_payload_len, int nzeros)
    {
      return gnuradio::get_initial_sptr
        (new zeropadding_removal_b_impl(phr_payload_len, nzeros));
    }

    /*
     * The private constructor
     */
    zeropadding_removal_b_impl::zeropadding_removal_b_impl(int phr_payload_len, int nzeros)
      : gr::sync_block("zeropadding_removal_b",
              gr::io_signature::make(1,1, sizeof(unsigned char)),
              gr::io_signature::make(0, 0, 0)),
      d_phr_payload_len(phr_payload_len),
      d_nzeros(nzeros),
      d_buf_pos(0)
    {
      d_buf.resize(phr_payload_len+nzeros, 0);

      // define message port
      message_port_register_out(pmt::mp("out"));
    }

    /*
     * Our virtual destructor.
     */
    zeropadding_removal_b_impl::~zeropadding_removal_b_impl()
    {
    }

    void
    zeropadding_removal_b_impl::remove_zeros()
    {
      pmt::pmt_t packet = pmt::make_blob(&d_buf[0], d_buf.size()-d_nzeros);
      // std::cout << "zeropadding_removal_b published a packet of size " << d_buf.size()-d_nzeros << std::endl;
      message_port_pub(pmt::mp("out"), pmt::cons(pmt::PMT_NIL, packet));
      d_buf_pos = 0;
    }

    int
    zeropadding_removal_b_impl::work(int noutput_items,
			  gr_vector_const_void_star &input_items,
			  gr_vector_void_star &output_items)
    {
      const unsigned char *in = (const unsigned char *) input_items[0];

      int nitems_consumed = 0;
      while(nitems_consumed < noutput_items)
      {
        d_buf[d_buf_pos] = in[nitems_consumed];
        d_buf_pos++;
        nitems_consumed++;
        if(d_buf_pos == d_buf.size())
          remove_zeros();
      }

      return noutput_items;
    }

  } /* namespace ieee802_15_4 */
} /* namespace gr */

