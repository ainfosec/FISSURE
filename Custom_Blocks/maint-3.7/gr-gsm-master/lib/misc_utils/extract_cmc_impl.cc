/* -*- c++ -*- */
/*
 * @file
 * @author (C) 2016 by Roman Khassraf <rkhassraf@gmail.com>
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
#include <grgsm/gsmtap.h>
//#include <unistd.h>
#include <grgsm/endian.h>

#include "extract_cmc_impl.h"

namespace gr {
  namespace gsm {
    void extract_cmc_impl::process_messages(pmt::pmt_t msg)
    {
        pmt::pmt_t message_plus_header_blob = pmt::cdr(msg);
        uint8_t * message_plus_header = (uint8_t *)pmt::blob_data(message_plus_header_blob);
        gsmtap_hdr * header = (gsmtap_hdr *)message_plus_header;
        uint8_t * msg_elements = (uint8_t *)(message_plus_header+sizeof(gsmtap_hdr));

        if((msg_elements[3] & 0xFF) == 0x06 && msg_elements[4] == 0x35)
        {

            int frame_nr = be32toh(header->frame_number);
            int a5_version = ((msg_elements[5] & 0xE) >> 1) + 1; //10.5.2.9 Cipher Mode Setting
            int start_ciphering = ((msg_elements[5] & 0x1));
            d_start_ciphering.push_back(start_ciphering);
            d_framenumbers.push_back(frame_nr);
            d_a5_versions.push_back(a5_version);
        }
    }
    
    std::vector<int> extract_cmc_impl::get_framenumbers()
    {
        return d_framenumbers;
    }
    
    std::vector<int> extract_cmc_impl::get_a5_versions()
    {
        return d_a5_versions;
    }

    std::vector<int> extract_cmc_impl::get_start_ciphering()
    {
        return d_start_ciphering;
    }
    
    extract_cmc::sptr
    extract_cmc::make()
    {
      return gnuradio::get_initial_sptr
        (new extract_cmc_impl());
    }

    /*
     * The private constructor
     */
    extract_cmc_impl::extract_cmc_impl()
      : gr::block("extract_cmc",
              gr::io_signature::make(0, 0, 0),
              gr::io_signature::make(0, 0, 0))
    {
        message_port_register_in(pmt::mp("msgs"));
        set_msg_handler(pmt::mp("msgs"), boost::bind(&extract_cmc_impl::process_messages, this, _1));
    }
    
    /*
     * Our virtual destructor.
     */
    extract_cmc_impl::~extract_cmc_impl()
    {
    }
  } /* namespace gsm */
} /* namespace gr */
