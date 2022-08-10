/* -*- c++ -*- */
/*
 * Copyright 2020 Free Software Foundation, Inc.
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
#include "pdu_round_robin_impl.h"

namespace gr {
  namespace iridium {

    pdu_round_robin::sptr
    pdu_round_robin::make(int output_count)
    {
      return gnuradio::get_initial_sptr
        (new pdu_round_robin_impl(output_count));
    }


    /*
     * The private constructor
     */
    pdu_round_robin_impl::pdu_round_robin_impl(int output_count)
      : gr::sync_block("pdu_round_robin",
              gr::io_signature::make(0, 0, 0),
              gr::io_signature::make(0, 0, 0)),
        d_next_port(0)
    {
      message_port_register_in(pmt::mp("in"));
      message_port_register_out(pmt::mp("out_0"));
      message_port_register_out(pmt::mp("out_1"));

      set_msg_handler(pmt::mp("in"), [this](pmt::pmt_t msg) { this->handler(msg); });
    }

    /*
     * Our virtual destructor.
     */
    pdu_round_robin_impl::~pdu_round_robin_impl()
    {
    }

    void pdu_round_robin_impl::handler(pmt::pmt_t msg)
    {
      if(d_next_port == 0) {
        d_next_port = 1;
        message_port_pub(pmt::mp("out_0"), msg);
      } else {
        d_next_port = 0;
        message_port_pub(pmt::mp("out_1"), msg);
      }
    }

    int
    pdu_round_robin_impl::work(int noutput_items,
        gr_vector_const_void_star &input_items,
        gr_vector_void_star &output_items)
    {
      return noutput_items;
    }

  } /* namespace iridium */
} /* namespace gr */

