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
#include "message_sink_impl.h"
#include <stdio.h>
#include <sstream>

namespace gr {
  namespace gsm {

    message_sink::sptr
    message_sink::make()
    {
      return gnuradio::get_initial_sptr
        (new message_sink_impl());
    }

    /*
     * The private constructor
     */
    message_sink_impl::message_sink_impl()
      : gr::block("message_sink",
              gr::io_signature::make(0, 0, 0),
              gr::io_signature::make(0, 0, 0))
    {
        message_port_register_in(pmt::mp("in"));
        set_msg_handler(pmt::mp("in"), boost::bind(&message_sink_impl::process_message, this, _1));
    }

    /*
     * Our virtual destructor.
     */
    message_sink_impl::~message_sink_impl()
    {
        for (int i=0; i<d_messages.size(); i++)
        {
            std::cout << d_messages[i].c_str() << std::endl;
        }
    }

    void message_sink_impl::process_message(pmt::pmt_t msg)
    {
        pmt::pmt_t message_plus_header_blob = pmt::cdr(msg);
        uint8_t * message_plus_header = (uint8_t *)pmt::blob_data(message_plus_header_blob);
        size_t message_plus_header_len = pmt::blob_length(message_plus_header_blob);

        std::stringstream s_msg_stream;
        for (int i=0; i<message_plus_header_len; i++)
        {
            if (i>0)
            {
                s_msg_stream << (" ");
            }
            s_msg_stream << std::hex << std::setw(2) << std::setfill('0') << (unsigned)message_plus_header[i];
        }
        d_messages.push_back(s_msg_stream.str());
    }

    std::vector<std::string> message_sink_impl::get_messages()
    {
        return d_messages;
    }

  } /* namespace gsm */
} /* namespace gr */

