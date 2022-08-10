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
#include "message_file_sink_impl.h"
#include <stdio.h>

namespace gr {
  namespace gsm {

    message_file_sink::sptr
    message_file_sink::make(const std::string &filename)
    {
      return gnuradio::get_initial_sptr
        (new message_file_sink_impl(filename));
    }

    /*
     * The private constructor
     */
    message_file_sink_impl::message_file_sink_impl(const std::string &filename)
      : gr::block("message_file_sink",
              gr::io_signature::make(0, 0, 0),
              gr::io_signature::make(0, 0, 0)),
              d_output_file(filename.c_str(), std::ofstream::binary)
    {
        message_port_register_in(pmt::mp("in"));
        set_msg_handler(pmt::mp("in"), boost::bind(&message_file_sink_impl::process_message, this, _1));
    }

    /*
     * Our virtual destructor.
     */
    message_file_sink_impl::~message_file_sink_impl()
    {
        if (d_output_file.is_open())
        {
            d_output_file.close();
        }
    }

    void message_file_sink_impl::process_message(pmt::pmt_t msg)
    {
        std::string s = pmt::serialize_str(msg);
        const char *serialized = s.data();
        d_output_file.write(serialized, s.length());
    }
  } /* namespace gsm */
} /* namespace gr */

