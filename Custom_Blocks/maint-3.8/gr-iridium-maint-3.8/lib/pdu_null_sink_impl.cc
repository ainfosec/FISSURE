/* -*- c++ -*- */
/*
 * Copyright 2020 gr-iridium author.
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
#include "pdu_null_sink_impl.h"

namespace gr {
  namespace iridium {

    pdu_null_sink::sptr
    pdu_null_sink::make()
    {
      return gnuradio::get_initial_sptr
        (new pdu_null_sink_impl());
    }


    /*
     * The private constructor
     */
    pdu_null_sink_impl::pdu_null_sink_impl()
      : gr::sync_block("pdu_null_sink",
              gr::io_signature::make(0, 0, 0),
              gr::io_signature::make(0, 0, 0))
    {
      message_port_register_in(pmt::mp("pdus"));
      set_msg_handler(pmt::mp("pdus"), [this](pmt::pmt_t msg) { this->handler(msg); });
    }

    /*
     * Our virtual destructor.
     */
    pdu_null_sink_impl::~pdu_null_sink_impl()
    {
    }

    void pdu_null_sink_impl::handler(pmt::pmt_t msg)
    {
    }

    int
    pdu_null_sink_impl::work(int noutput_items,
        gr_vector_const_void_star &input_items,
        gr_vector_void_star &output_items)
    {
      // Tell runtime system how many output items we produced.
      return noutput_items;
    }

  } /* namespace iridium */
} /* namespace gr */

