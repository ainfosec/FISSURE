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
#include "message_source_impl.h"
#include <stdio.h>
#include <grgsm/gsmtap.h>
#include <grgsm/endian.h>
#include <algorithm>
#include <boost/scoped_ptr.hpp>
#include <iostream>
#include <string>
#include <sstream>

#define MSG_BYTE_LEN 39


namespace gr {
  namespace gsm {

    message_source::sptr
    message_source::make(const std::vector<std::string> &msg_data)
    {
      return gnuradio::get_initial_sptr
        (new message_source_impl(msg_data));
    }

    /*
     * The private constructor
     */
    message_source_impl::message_source_impl(const std::vector<std::string> &msg_data)
      : gr::block("message_source",
              gr::io_signature::make(0, 0, 0),
              gr::io_signature::make(0, 0, 0)),
              d_finished(false)
    {
        message_port_register_out(pmt::mp("msgs"));
        set_msg_data(msg_data);
    }

    /*
     * Our virtual destructor.
     */
    message_source_impl::~message_source_impl()
    {
        if (d_finished == false){
            d_finished = true;
        }
    }

    void message_source_impl::set_msg_data(const std::vector<std::string> &msg_data)
    {
        for (int i=0; i<msg_data.size(); i++)
        {
            std::istringstream iss(msg_data[i]);
            std::vector<uint8_t> bytes;
            unsigned int c;

            while (iss >> std::hex >> c)
            {
                if (c < 256)
                {
                    bytes.push_back(c);
                }
            }

            if (bytes.size() == MSG_BYTE_LEN)
            {
                d_msgs.push_back(bytes);
            }
        }
    }

    bool message_source_impl::start()
    {
        d_finished = false;
        d_thread = boost::shared_ptr<gr::thread::thread>
            (new gr::thread::thread(boost::bind(&message_source_impl::run, this)));
        return block::start();
    }

    bool message_source_impl::stop()
    {
        d_finished = true;
        d_thread->interrupt();
        d_thread->join();
        return block::stop();
    }

    bool message_source_impl::finished()
    {
        return d_finished;
    }

    void message_source_impl::run()
    {
        for (int i=0; i<d_msgs.size(); i++)
        {
            std::vector<uint8_t> current = d_msgs[i];
            pmt::pmt_t blob_header_plus_burst = pmt::make_blob(&current[0], current.size());
            pmt::pmt_t msg = pmt::cons(pmt::PMT_NIL, blob_header_plus_burst);
            message_port_pub(pmt::mp("msgs"), msg);
        }
        post(pmt::mp("system"), pmt::cons(pmt::mp("done"), pmt::from_long(1)));
    }
  } /* namespace gsm */
} /* namespace gr */

