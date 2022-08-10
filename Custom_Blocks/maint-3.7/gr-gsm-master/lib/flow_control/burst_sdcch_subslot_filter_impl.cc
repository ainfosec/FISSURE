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
#include "burst_sdcch_subslot_filter_impl.h"
#include <stdio.h>
#include <grgsm/endian.h>
#include <grgsm/gsmtap.h>

namespace gr {
  namespace gsm {

    burst_sdcch_subslot_filter::sptr
    burst_sdcch_subslot_filter::make(subslot_filter_mode mode, unsigned int subslot)
    {
      return gnuradio::get_initial_sptr
        (new burst_sdcch_subslot_filter_impl(mode, subslot));
    }

    /*
     * The private constructor
     */
    burst_sdcch_subslot_filter_impl::burst_sdcch_subslot_filter_impl(subslot_filter_mode mode, unsigned int subslot)
      : gr::block("burst_sdcch_subslot_filter",
              gr::io_signature::make(0, 0, 0),
              gr::io_signature::make(0, 0, 0)),
      d_mode(mode),
      d_subslot(subslot),
      d_filter_policy(FILTER_POLICY_DEFAULT)
    {     
        message_port_register_in(pmt::mp("in"));
        message_port_register_out(pmt::mp("out"));
        
        set_msg_handler(pmt::mp("in"), boost::bind(&burst_sdcch_subslot_filter_impl::process_burst, this, _1));
    }

    /*
     * Our virtual destructor.
     */
    burst_sdcch_subslot_filter_impl::~burst_sdcch_subslot_filter_impl() {}

    void burst_sdcch_subslot_filter_impl::process_burst(pmt::pmt_t msg)
    {    
        // hardcoded subslots of the channels, both SDCCH and the associated SACCH
        // -1 means that the particular position in the frame is not SDCCH
        static const int8_t subslots_sdcch4[102] = {
          -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1, 0, 0, 0, 0, 1, 1, 1, 1,-1,-1, 2, 2, 2, 2, 3, 3, 3, 3,-1,-1, 0, 0, 0, 0, 1, 1, 1, 1,-1,
          -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1, 0, 0, 0, 0, 1, 1, 1, 1,-1,-1, 2, 2, 2, 2, 3, 3, 3, 3,-1,-1, 2, 2, 2, 2, 3, 3, 3, 3,-1
        };
        static const int8_t subslots_sdcch8[102] = {
          0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 6, 6, 6, 6, 7, 7, 7, 7, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3,-1,-1,-1,
          0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 6, 6, 6, 6, 7, 7, 7, 7, 4, 4, 4, 4, 5, 5, 5, 5, 6, 6, 6, 6, 7, 7, 7, 7,-1,-1,-1
        };

        if (d_filter_policy == FILTER_POLICY_DROP_ALL)
          return;

        if (d_filter_policy == FILTER_POLICY_PASS_ALL) {
          message_port_pub(pmt::mp("out"), msg);
          return;
        }
    
        pmt::pmt_t header_plus_burst = pmt::cdr(msg);
        gsmtap_hdr * header = (gsmtap_hdr *)pmt::blob_data(header_plus_burst);
        
        uint32_t frame_nr = be32toh(header->frame_number);
        uint32_t fn_mod102 = frame_nr % 102;
        
        int8_t subslot;
        
        if (d_mode == SS_FILTER_SDCCH8)
        {
            subslot = subslots_sdcch8[fn_mod102];
        }
        else if (d_mode == SS_FILTER_SDCCH4)
        {
            subslot = subslots_sdcch4[fn_mod102];
        }
        
        if ((subslot == -1) || (d_mode == SS_FILTER_SDCCH4 && subslot > 3))
        {
            return;
        }
        
        if (subslot == d_subslot)
        {
            message_port_pub(pmt::mp("out"), msg);
        }
    }

    /* External API */
    unsigned int
    burst_sdcch_subslot_filter_impl::get_ss(void)
    {
      return d_subslot;
    }

    unsigned int
    burst_sdcch_subslot_filter_impl::set_ss(unsigned int ss)
    {
      if ((d_mode == SS_FILTER_SDCCH8 && ss < 8)
      || (d_mode == SS_FILTER_SDCCH4 && ss < 4))
        d_subslot = ss;

      return d_subslot;
    }


    subslot_filter_mode
    burst_sdcch_subslot_filter_impl::get_mode(void)
    {
      return d_mode;
    }

    subslot_filter_mode
    burst_sdcch_subslot_filter_impl::set_mode(subslot_filter_mode mode)
    {
      d_mode = mode;
      return d_mode;
    }

    /* Filtering policy */
    filter_policy
    burst_sdcch_subslot_filter_impl::get_policy(void)
    {
      return d_filter_policy;
    }

    filter_policy
    burst_sdcch_subslot_filter_impl::set_policy(filter_policy policy)
    {
      d_filter_policy = policy;
      return d_filter_policy;
    }

  } /* namespace gsm */
} /* namespace gr */
