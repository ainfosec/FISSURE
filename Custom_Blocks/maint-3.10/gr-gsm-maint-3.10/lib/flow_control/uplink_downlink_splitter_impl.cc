/* -*- c++ -*- */
/* @file
 * @author (C) 2016 by Piotr Krysik <ptrkrysik@gmail.com>
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
#include "uplink_downlink_splitter_impl.h"
#include <gsm/gsmtap.h>
#include <gsm/endian.h>
#define BURST_SIZE 148
namespace gr {
  namespace gsm {

    uplink_downlink_splitter::sptr
    uplink_downlink_splitter::make()
    {
      return gnuradio::get_initial_sptr
        (new uplink_downlink_splitter_impl());
    }

    /*
     * The private constructor
     */
    uplink_downlink_splitter_impl::uplink_downlink_splitter_impl()
      : gr::block("uplink_downlink_splitter",
              gr::io_signature::make(0,0,0),
              gr::io_signature::make(0,0,0))
    {
        message_port_register_in(pmt::mp("in"));
        message_port_register_out(pmt::mp("uplink"));
        message_port_register_out(pmt::mp("downlink"));
        set_msg_handler(pmt::mp("in"), boost::bind(&uplink_downlink_splitter_impl::process_msg, this, boost::placeholders::_1));
    }

    void uplink_downlink_splitter_impl::process_msg(pmt::pmt_t msg)
    {
        gsmtap_hdr * header = (gsmtap_hdr *)(pmt::blob_data(pmt::cdr(msg)));
        bool uplink_burst = (be16toh(header->arfcn) & 0x4000) ? true : false;
        if(uplink_burst)
        {
            message_port_pub(pmt::mp("uplink"), msg);
        } else {
            message_port_pub(pmt::mp("downlink"), msg);
        }
    }

    /*
     * Our virtual destructor.
     */
    uplink_downlink_splitter_impl::~uplink_downlink_splitter_impl()
    {
    }
  } /* namespace gsm */
} /* namespace gr */

