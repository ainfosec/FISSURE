/* -*- c++ -*- */
/*
 * @file
 * @author (C) 2014 by Piotr Krysik <ptrkrysik@gmail.com>
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
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <gnuradio/io_signature.h>
#include <stdio.h>
#include "message_printer_impl.h"
#include "gsm/gsmtap.h"
#include <gsm/endian.h>
#include <iomanip>

extern "C" {
    #include <osmocom/gsm/a5.h>
}

namespace gr {
  namespace gsm {

    void message_printer_impl::message_print(pmt::pmt_t msg)
    {
        pmt::pmt_t message_plus_header_blob = pmt::cdr(msg);
        uint8_t * message_plus_header = (uint8_t *)pmt::blob_data(message_plus_header_blob);
        size_t message_plus_header_len=pmt::blob_length(message_plus_header_blob);
        gsmtap_hdr * header = (gsmtap_hdr *)message_plus_header;
        uint32_t frame_nr = be32toh(header->frame_number);
        
        std::ostringstream out;
        out << d_prepend_string;
        if (d_prepend_fnr)
        {
            out << frame_nr;
        }

        if (d_prepend_fnr && d_prepend_frame_count)
        {
            out << " ";
        }

        if (d_prepend_frame_count)
        {
            // calculate fn count using libosmogsm
            out << osmo_a5_fn_count(frame_nr);
        }

        if (d_prepend_fnr || d_prepend_frame_count)
        {
            out << ": ";
        }
        
        int start_index = sizeof(gsmtap_hdr);
        
        if (d_print_gsmtap_header)
        {
            start_index = 0;
        }
        
        for(int ii=start_index; ii<message_plus_header_len; ii++)
        {
            out<<" "<<(std::hex)<<std::setw(2)<<std::setfill('0')<<(uint32_t)message_plus_header[ii];
        }

        out << std::endl;
        std::cout << out.str() << std::flush;
    }

    message_printer::sptr
    message_printer::make(pmt::pmt_t prepend_string, bool prepend_fnr,
        bool prepend_frame_count, bool print_gsmtap_header)
    {
      return gnuradio::get_initial_sptr
        (new message_printer_impl(prepend_string, prepend_fnr,
            prepend_frame_count, print_gsmtap_header));
    }

    /*
     * The private constructor
     */
    message_printer_impl::message_printer_impl(pmt::pmt_t prepend_string, bool prepend_fnr,
        bool prepend_frame_count, bool print_gsmtap_header)
      : gr::block("message_printer",
              gr::io_signature::make(0, 0, 0),
              gr::io_signature::make(0, 0, 0))
    {
        d_prepend_string = prepend_string;
        d_prepend_fnr = prepend_fnr;
        d_prepend_frame_count = prepend_frame_count;
        d_print_gsmtap_header = print_gsmtap_header;
        message_port_register_in(pmt::mp("msgs"));
        set_msg_handler(pmt::mp("msgs"), boost::bind(&message_printer_impl::message_print, this, boost::placeholders::_1));
    }

    /*
     * Our virtual destructor.
     */
    message_printer_impl::~message_printer_impl()
    {
    }
  } /* namespace gsm */
} /* namespace gr */

