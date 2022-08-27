/* -*- c++ -*- */
/* @file
 * @author (C) 2017 by Piotr Krysik <ptrkrysik@gmail.com>
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
#include "burst_type_filter_impl.h"
#include <stdio.h>
#include <gsm/endian.h>
#include <gsm/gsmtap.h>


namespace gr {
  namespace gsm {
      
    burst_type_filter::sptr
    burst_type_filter::make(const std::vector<uint8_t> & selected_burst_types)
    {
      return gnuradio::get_initial_sptr
        (new burst_type_filter_impl(selected_burst_types));
    }

    /*
     * The private constructor
     */
    burst_type_filter_impl::burst_type_filter_impl(const std::vector<uint8_t> & selected_burst_types)
      : gr::block("burst_type_filter",
              gr::io_signature::make(0, 0, 0),
              gr::io_signature::make(0, 0, 0)),
        d_filter_policy(FILTER_POLICY_DEFAULT)
    {
        set_selected_burst_types(selected_burst_types);
    
        message_port_register_in(pmt::mp("bursts_in"));
        message_port_register_out(pmt::mp("bursts_out"));
        
        set_msg_handler(pmt::mp("bursts_in"), boost::bind(&burst_type_filter_impl::process_burst, this, boost::placeholders::_1));
    }

    /*
     * Our virtual destructor.
     */
    burst_type_filter_impl::~burst_type_filter_impl() {}

    void burst_type_filter_impl::process_burst(pmt::pmt_t msg)
    {
        if (d_filter_policy == FILTER_POLICY_DROP_ALL)
          return;

        if (d_filter_policy == FILTER_POLICY_PASS_ALL) {
          message_port_pub(pmt::mp("bursts_out"), msg);
          return;
        }

        gsmtap_hdr * header = (gsmtap_hdr *)pmt::blob_data(pmt::cdr(msg));
        if (std::find(d_selected_burst_types.begin(), d_selected_burst_types.end(), header->sub_type) != d_selected_burst_types.end()) //check if burst type is listed in burst types to pass
        {
            message_port_pub(pmt::mp("bursts_out"), msg);
        }
    }
    
    /* Filtering policy */
    filter_policy
    burst_type_filter_impl::get_policy(void)
    {
      return d_filter_policy;
    }

    filter_policy
    burst_type_filter_impl::set_policy(filter_policy policy)
    {
      d_filter_policy = policy;
      return d_filter_policy;
    }
    
    void
    burst_type_filter_impl::set_selected_burst_types(const std::vector<uint8_t> & selected_burst_types)
    {
      d_selected_burst_types.assign(selected_burst_types.begin(), selected_burst_types.end());
    }
  } /* namespace gsm */
} /* namespace gr */
