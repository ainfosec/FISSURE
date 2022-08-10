/* -*- c++ -*- */
/* @file
 * @author (C) 2015 by Roman Khassraf <rkhassraf@gmail.com>
 * @section LICENSE
 *
 * Gr-gsm is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3, or (at your option)
 * any later version.
 *
 * Gr-gsm is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with gr-gsm; see the file COPYING.  If not, write to
 * the Free Software Foundation, Inc., 51 Franklin Street,
 * Boston, MA 02110-1301, USA.
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <gnuradio/io_signature.h>
#include "burst_fnr_filter_impl.h"
#include <stdio.h>
#include <grgsm/endian.h>
#include <grgsm/gsmtap.h>


namespace gr {
  namespace gsm {

    burst_fnr_filter::sptr
    burst_fnr_filter::make(filter_mode mode, unsigned int fnr)
    {
      return gnuradio::get_initial_sptr
        (new burst_fnr_filter_impl(mode, fnr));
    }

    /*
     * The private constructor
     */
    burst_fnr_filter_impl::burst_fnr_filter_impl(filter_mode mode, unsigned int fnr)
      : gr::block("burst_fnr_filter",
              gr::io_signature::make(0, 0, 0),
              gr::io_signature::make(0, 0, 0)),
      d_mode(mode),
      d_framenr(fnr),
      d_filter_policy(FILTER_POLICY_DEFAULT)
    {
        message_port_register_in(pmt::mp("in"));       
        message_port_register_out(pmt::mp("out"));

        set_msg_handler(pmt::mp("in"), boost::bind(&burst_fnr_filter_impl::process_burst, this, _1));
    }

    /*
     * Our virtual destructor.
     */
    burst_fnr_filter_impl::~burst_fnr_filter_impl() {}

    void burst_fnr_filter_impl::process_burst(pmt::pmt_t msg)
    {
        if (d_filter_policy == FILTER_POLICY_DROP_ALL)
          return;

        if (d_filter_policy == FILTER_POLICY_PASS_ALL) {
          message_port_pub(pmt::mp("out"), msg);
          return;
        }

        pmt::pmt_t header_plus_burst = pmt::cdr(msg);
        gsmtap_hdr * header = (gsmtap_hdr *)pmt::blob_data(header_plus_burst);
        
        unsigned int frame_nr = be32toh(header->frame_number);
        
        if ((d_mode == FILTER_LESS_OR_EQUAL && frame_nr <= d_framenr)
            || (d_mode == FILTER_GREATER_OR_EQUAL && frame_nr >= d_framenr))
        {
            message_port_pub(pmt::mp("out"), msg);
        }
    }

    /* External API */
    unsigned int
    burst_fnr_filter_impl::get_fn(void)
    {
      return d_framenr;
    }

    unsigned int
    burst_fnr_filter_impl::set_fn(unsigned int fn)
    {
      if (fn <= GSM_HYPERFRAME)
        d_framenr = fn;

      return d_framenr;
    }


    filter_mode
    burst_fnr_filter_impl::get_mode(void)
    {
      return d_mode;
    }

    filter_mode
    burst_fnr_filter_impl::set_mode(filter_mode mode)
    {
      d_mode = mode;
      return d_mode;
    }

    /* Filtering policy */
    filter_policy
    burst_fnr_filter_impl::get_policy(void)
    {
      return d_filter_policy;
    }

    filter_policy
    burst_fnr_filter_impl::set_policy(filter_policy policy)
    {
      d_filter_policy = policy;
      return d_filter_policy;
    }

  } /* namespace gsm */
} /* namespace gr */
