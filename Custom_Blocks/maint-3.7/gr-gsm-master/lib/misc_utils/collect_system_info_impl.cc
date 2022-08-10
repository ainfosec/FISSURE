/* -*- c++ -*- */
/*
 * @file
 * @author (C) 2017 by Roman Khassraf <rkhassraf@gmail.com>
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

#include "collect_system_info_impl.h"

namespace gr {
  namespace gsm {
    
    void collect_system_info_impl::process_messages(pmt::pmt_t msg){
        pmt::pmt_t message_plus_header_blob = pmt::cdr(msg);
        uint8_t * message_plus_header = (uint8_t *)pmt::blob_data(message_plus_header_blob);
        gsmtap_hdr * header = (gsmtap_hdr *)message_plus_header;
        uint8_t * msg_elements = (uint8_t *)(message_plus_header+sizeof(gsmtap_hdr));
        
        uint8_t chan_type = header->sub_type;
                
        if (chan_type == GSMTAP_CHANNEL_BCCH && msg_elements[1] == 0x06) 
        {
            int frame_nr = be32toh(header->frame_number);
                        
            if (msg_elements[2]  == 0x19)
            {
                d_framenumbers.push_back(frame_nr);
                d_sit_types.push_back("System Information Type 1");
                d_sit_data.push_back(get_hex_string(msg_elements));
            }
            else if (msg_elements[2]  == 0x1a)
            {
                d_framenumbers.push_back(frame_nr);
                d_sit_types.push_back("System Information Type 2");
                d_sit_data.push_back(get_hex_string(msg_elements));
            }
            else if (msg_elements[2]  == 0x1b)
            {
                d_framenumbers.push_back(frame_nr);
                d_sit_types.push_back("System Information Type 3");
                d_sit_data.push_back(get_hex_string(msg_elements));
            }
            else if (msg_elements[2]  == 0x1c)
            {
                d_framenumbers.push_back(frame_nr);
                d_sit_types.push_back("System Information Type 4");
                d_sit_data.push_back(get_hex_string(msg_elements));
            }
            else if (msg_elements[2]  == 0x02)
            {
                d_framenumbers.push_back(frame_nr);
                d_sit_types.push_back("System Information Type 2bis");
                d_sit_data.push_back(get_hex_string(msg_elements));
            }
            else if (msg_elements[2]  == 0x03)
            {
                d_framenumbers.push_back(frame_nr);
                d_sit_types.push_back("System Information Type 2ter");
                d_sit_data.push_back(get_hex_string(msg_elements));
            }
            else if (msg_elements[2]  == 0x07)
            {
                d_framenumbers.push_back(frame_nr);
                d_sit_types.push_back("System Information Type 2quater");
                d_sit_data.push_back(get_hex_string(msg_elements));
            }
            else if (msg_elements[2]  == 0x00)
            {
                d_framenumbers.push_back(frame_nr);
                d_sit_types.push_back("System Information Type 13");
                d_sit_data.push_back(get_hex_string(msg_elements));
            }
        }
        else if ((chan_type == (GSMTAP_CHANNEL_ACCH|GSMTAP_CHANNEL_SDCCH)
            || chan_type == (GSMTAP_CHANNEL_ACCH|GSMTAP_CHANNEL_SDCCH4)
            || chan_type == (GSMTAP_CHANNEL_ACCH|GSMTAP_CHANNEL_SDCCH8)
            || chan_type == (GSMTAP_CHANNEL_ACCH|GSMTAP_CHANNEL_TCH_F)
            || chan_type == (GSMTAP_CHANNEL_ACCH|GSMTAP_CHANNEL_TCH_H))
            && msg_elements[5] == 0x06)
        {
            int frame_nr = be32toh(header->frame_number);
                        
            if (msg_elements[6]  == 0x1D)
            {   
                d_framenumbers.push_back(frame_nr);
                d_sit_types.push_back("System Information Type 5");
                d_sit_data.push_back(get_hex_string(msg_elements));
            }
            else if (msg_elements[6]  == 0x1E)
            {
                d_framenumbers.push_back(frame_nr);
                d_sit_types.push_back("System Information Type 6");
                d_sit_data.push_back(get_hex_string(msg_elements));
            }
            else if (msg_elements[6]  == 0x05)
            {
                d_framenumbers.push_back(frame_nr);
                d_sit_types.push_back("System Information Type 5bis");
                d_sit_data.push_back(get_hex_string(msg_elements));
            }
            else if (msg_elements[6]  == 0x06)
            {
                d_framenumbers.push_back(frame_nr);
                d_sit_types.push_back("System Information Type 5ter");
                d_sit_data.push_back(get_hex_string(msg_elements));
            }
        }
    }
    
    std::vector<int> collect_system_info_impl::get_framenumbers()
    {
        return d_framenumbers;
    }
    
    std::vector<std::string> collect_system_info_impl::get_system_information_type()
    {
        return d_sit_types;
    }
    
    std::vector<std::string> collect_system_info_impl::get_data()
    {
        return d_sit_data;
    }
    
    std::string collect_system_info_impl::get_hex_string(uint8_t * msg_elements)
    {
        std::stringstream sstream;
        for (int i=0; i<23; i++)
        {
            sstream << std::setfill ('0') << std::setw(2) << std::hex << static_cast<int>(msg_elements[i]);
        }
        return sstream.str();
    }
    
    collect_system_info::sptr
    collect_system_info::make()
    {
      return gnuradio::get_initial_sptr
        (new collect_system_info_impl());
    }

    /*
     * The private constructor
     */
    collect_system_info_impl::collect_system_info_impl()
      : gr::block("collect_system_info",
              gr::io_signature::make(0, 0, 0),
              gr::io_signature::make(0, 0, 0))
    {
        message_port_register_in(pmt::mp("msgs"));
        set_msg_handler(pmt::mp("msgs"), boost::bind(&collect_system_info_impl::process_messages, this, _1));
    }
    
    /*
     * Our virtual destructor.
     */
    collect_system_info_impl::~collect_system_info_impl()
    {
    }
  } /* namespace gsm */
} /* namespace gr */
