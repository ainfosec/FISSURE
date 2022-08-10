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
#include "dummy_burst_filter_impl.h"
#include <stdio.h>
#include <grgsm/endian.h>
#include <grgsm/gsmtap.h>


namespace gr {
  namespace gsm {
      
    // dummy burst defined in gsm 05.02, section 5.2.6
    const int8_t dummy_burst_filter_impl::d_dummy_burst[] = {0,0,0,
        1,1,1,1,1,0,1,1,0,1,1,1,0,1,1,0,
        0,0,0,0,1,0,1,0,0,1,0,0,1,1,1,0,
        0,0,0,0,1,0,0,1,0,0,0,1,0,0,0,0,
        0,0,0,1,1,1,1,1,0,0,0,1,1,1,0,0,
        0,1,0,1,1,1,0,0,0,1,0,1,1,1,0,0,
        0,1,0,1,0,1,1,1,0,1,0,0,1,0,1,0,
        0,0,1,1,0,0,1,1,0,0,1,1,1,0,0,1,
        1,1,1,0,1,0,0,1,1,1,1,1,0,0,0,1,
        0,0,1,0,1,1,1,1,1,0,1,0,1,0,
        0,0,0 };

    dummy_burst_filter::sptr
    dummy_burst_filter::make()
    {
      return gnuradio::get_initial_sptr
        (new dummy_burst_filter_impl());
    }

    /*
     * The private constructor
     */
    dummy_burst_filter_impl::dummy_burst_filter_impl()
      : gr::block("dummy_burst_filter",
              gr::io_signature::make(0, 0, 0),
              gr::io_signature::make(0, 0, 0)),
        d_filter_policy(FILTER_POLICY_DEFAULT)
    {
        message_port_register_in(pmt::mp("in"));        
        message_port_register_out(pmt::mp("out"));
        
        set_msg_handler(pmt::mp("in"), boost::bind(&dummy_burst_filter_impl::process_burst, this, _1));
    }

    /*
     * Our virtual destructor.
     */
    dummy_burst_filter_impl::~dummy_burst_filter_impl() {}

    void dummy_burst_filter_impl::process_burst(pmt::pmt_t msg)
    {
        if (d_filter_policy == FILTER_POLICY_DROP_ALL)
          return;

        if (d_filter_policy == FILTER_POLICY_PASS_ALL) {
          message_port_pub(pmt::mp("out"), msg);
          return;
        }

        pmt::pmt_t header_plus_burst = pmt::cdr(msg);
        int8_t * burst = (int8_t *)(pmt::blob_data(header_plus_burst)) + sizeof(gsmtap_hdr);
        size_t burst_len = pmt::blob_length(header_plus_burst) - sizeof(gsmtap_hdr);
        
        if (!is_dummy_burst(burst, burst_len))
        {
            message_port_pub(pmt::mp("out"), msg);
        }
    }
    
    bool dummy_burst_filter_impl::is_dummy_burst(int8_t *burst, size_t burst_len)
    {
        if (burst_len != DUMMY_BURST_LEN)
        {
            return false;
        }
        for (int i=0; i<DUMMY_BURST_LEN; i++)
        {
            if (burst[i] != d_dummy_burst[i])
            {
                return false;
            }
        }
        return true;
    }

    /* Filtering policy */
    filter_policy
    dummy_burst_filter_impl::get_policy(void)
    {
      return d_filter_policy;
    }

    filter_policy
    dummy_burst_filter_impl::set_policy(filter_policy policy)
    {
      d_filter_policy = policy;
      return d_filter_policy;
    }
    
  } /* namespace gsm */
} /* namespace gr */
