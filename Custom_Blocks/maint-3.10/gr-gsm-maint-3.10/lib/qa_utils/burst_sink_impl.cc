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
#include "burst_sink_impl.h"
#include <stdio.h>
#include <sstream>
#include <gsm/endian.h>
#include <gsm/gsmtap.h>

namespace gr {
  namespace gsm {

    burst_sink::sptr
    burst_sink::make()
    {
      return gnuradio::get_initial_sptr
        (new burst_sink_impl());
    }

    /*
     * The private constructor
     */
    burst_sink_impl::burst_sink_impl()
      : gr::block("burst_sink",
              gr::io_signature::make(0, 0, 0),
              gr::io_signature::make(0, 0, 0)),
        d_bursts(pmt::PMT_NIL)
    {
        message_port_register_in(pmt::mp("in"));
        set_msg_handler(pmt::mp("in"), boost::bind(&burst_sink_impl::process_burst, this, boost::placeholders::_1));
    }

    /*
     * Our virtual destructor.
     */
    burst_sink_impl::~burst_sink_impl()
    {
//         for (int i=0; i<d_burst_data.size(); i++)
//         {
//             std::cout << d_framenumbers[i] << " " << d_timeslots[i] << " " << d_burst_data[i] << std::endl;
//         }
    }

    void burst_sink_impl::process_burst(pmt::pmt_t msg)
    {
        pmt::pmt_t header_plus_burst = pmt::cdr(msg);

        gsmtap_hdr * header = (gsmtap_hdr *)pmt::blob_data(header_plus_burst);
        int8_t * burst = (int8_t *)(pmt::blob_data(header_plus_burst))+sizeof(gsmtap_hdr);
        size_t burst_len=pmt::blob_length(header_plus_burst)-sizeof(gsmtap_hdr);
        uint32_t frame_nr = be32toh(header->frame_number);

        std::stringstream burst_str;
        for(int i=0; i<burst_len; i++)
        {
            if (static_cast<int>(burst[i]) == 0)
            {
                burst_str << "0";
            }
            else
            {
                burst_str << "1";
            }
        }

        d_framenumbers.push_back(frame_nr);
        d_timeslots.push_back(header->timeslot);
        d_burst_data.push_back(burst_str.str());
        d_sub_types.push_back(header->sub_type);
        d_sub_slots.push_back(header->sub_slot);
    }

    std::vector<int> burst_sink_impl::get_framenumbers()
    {
        return d_framenumbers;
    }

    std::vector<int> burst_sink_impl::get_timeslots()
    {
        return d_timeslots;
    }

    std::vector<std::string> burst_sink_impl::get_burst_data()
    {
        return d_burst_data;
    }
    pmt::pmt_t burst_sink_impl::get_bursts()
    {
        return d_bursts;
    }
    std::vector<uint8_t> burst_sink_impl::get_sub_types()
    {
        return d_sub_types;
    }
    std::vector<uint8_t> burst_sink_impl::get_sub_slots()
    {
        return d_sub_slots;
    }
  } /* namespace gsm */
} /* namespace gr */

