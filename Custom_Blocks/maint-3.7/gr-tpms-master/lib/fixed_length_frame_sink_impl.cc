/* -*- c++ -*- */
/* 
 * Copyright 2014 Jared Boone <jared@sharebrained.com>.
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
#include "fixed_length_frame_sink_impl.h"

#include <string>

namespace gr {
  namespace tpms {
    fixed_length_frame_sink::sptr
    fixed_length_frame_sink::make(int frame_length, pmt::pmt_t attributes)
    {
      return gnuradio::get_initial_sptr
        //(new fixed_length_frame_sink_impl(frame_length, target_queue));
        (new fixed_length_frame_sink_impl(frame_length, attributes));
    }

    /*
     * The private constructor
     */
    fixed_length_frame_sink_impl::fixed_length_frame_sink_impl(int frame_length, pmt::pmt_t attributes)
      : gr::sync_block("fixed_length_frame_sink",
              gr::io_signature::make(1, 1, sizeof(unsigned char)),
              gr::io_signature::make(0, 0, 0)),
      d_frame_length(frame_length),
      d_message_port(pmt::mp("packet_source")),
      d_attributes(attributes),
      d_packets()
    {
      message_port_register_out(d_message_port);
    }

    /*
     * Our virtual destructor.
     */
    fixed_length_frame_sink_impl::~fixed_length_frame_sink_impl()
    {
    }

    int
    fixed_length_frame_sink_impl::work(int noutput_items,
			  gr_vector_const_void_star &input_items,
			  gr_vector_void_star &output_items)
    {
        const unsigned char *in = (const unsigned char *)input_items[0];
        int count = 0;

        while(count < noutput_items) {
          const bool start = (in[count] & 0x2) != 0;
          if( start ) {
            d_packets.push_back(bits_t());
          }

          if( !d_packets.empty() ) {
            const uint8_t bit = in[count] & 0x1;          
            for(packets_t::iterator it = d_packets.begin(); it != d_packets.end(); ++it) {
              (*it).push_back(bit);
            }

            if( d_packets.front().size() == d_frame_length ) {
              pmt::pmt_t data_vector = pmt::init_u8vector(d_packets.front().size(), &(d_packets.front().front()));
              pmt::pmt_t attributes = pmt::dict_add(d_attributes, pmt::mp("data"), data_vector);
              message_port_pub(d_message_port, attributes);

              d_packets.pop_front();
            }
          }

          count++;
        }

        return noutput_items;
    }

  } /* namespace tpms */
} /* namespace gr */

