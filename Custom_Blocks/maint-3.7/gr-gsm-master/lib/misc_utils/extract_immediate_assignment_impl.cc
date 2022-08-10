/* -*- c++ -*- */
/*
 * @file
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
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <gnuradio/io_signature.h>
#include <grgsm/gsmtap.h>
//#include <unistd.h>
#include <map>
#include <grgsm/endian.h>
#include <boost/foreach.hpp>

#include "extract_immediate_assignment_impl.h"

namespace gr {
  namespace gsm {
    boost::mutex extract_immediate_assignment_mutex;

    void extract_immediate_assignment_impl::process_message(pmt::pmt_t msg){
        pmt::pmt_t message_plus_header_blob = pmt::cdr(msg);
        uint8_t * message_plus_header = (uint8_t *)pmt::blob_data(message_plus_header_blob);
        gsmtap_hdr * header = (gsmtap_hdr *)message_plus_header;
        uint8_t * msg_elements = (uint8_t *)(message_plus_header+sizeof(gsmtap_hdr));
        uint32_t frame_nr = be32toh(header->frame_number);

        if(msg_elements[2]==0x3f)
        {
            immediate_assignment current;
            current.frame_nr = frame_nr;

            /*
                channel description, see table 10.23 in GSM 04.08

                msg_elements[4], octet 2 in specs

                5 bits channel type
                    ignored in TBF
                    00001   TCH/F
                    0001T   TCH/H, subchannel/TDMA offset T
                    001TT   SDCCH/4, subchannel/TDMA offset TT
                    01TTT   SDCCH/8, subchannel/TDMA offset TTT
                3 bits timeslot number TN
            */
            current.timeslot = (msg_elements[4] & 7);

            uint8_t channeltype = (msg_elements[4] >> 3);
            uint8_t mode = msg_elements[3] & (1 << 4);
            if (mode == 0)
            {
                if (channeltype >= 8)
                {
                    current.channel_type = "SDCCH/8";
                    current.subchannel = (channeltype & 7);
                }
                else if (channeltype >= 4 && channeltype <= 7)
                {
                    current.channel_type = "SDCCH/4";
                    current.subchannel = (channeltype & 3);
                }
                else if (channeltype >= 2 && channeltype <= 3)
                {
                    current.channel_type = "TCH/H";
                    current.subchannel = (channeltype & 1);
                }
                else
                {
                    current.channel_type = "TCH/F";
                }
            }
            else
            {
                // We return if ignore_gprs is set true
                if (d_ignore_gprs)
                {
                    return;
                }
                current.channel_type = "GPRS - Temporary Block Flow TBF";
            }

            /*
                msg_elements[5], msg_elements[6] are octets 3 and 4 in specs

                    3 bits training sequence (we dont process this for the moment)
                    1 bit hopping channel H

                    if H = 0:
                        2 bit spare
                        2 bit high part of single channel arfcn

                        8 bit low part of single channel arfcn

                    if H = 1:
                        4 bit high part of MAIO

                        2 bit low part of MAIO
                        6bit HSN
            */
            current.hopping = (msg_elements[5] >> 4) & 1;
            if (current.hopping)
            {
                uint8_t maio = (msg_elements[5] & 0xf) << 2;
                maio |= (msg_elements[6] >> 6);
                current.maio = maio;
                current.hsn = (msg_elements[6] & 0x3f);
            }
            else
            {
                uint16_t arfcn = (msg_elements[5] & 3) << 8;
                arfcn |= msg_elements[6];
                current.arfcn = arfcn;
            }

            /*
                msg_elements[7 - 9], octets 5 - 7 in specs, see 10.5.2.30 request reference, maybe later
            */
            uint8_t random_access_info = msg_elements[7];
            uint8_t rr_t1 = (msg_elements[8] >> 3);
            uint8_t rr_t2 = (msg_elements[9] & 0x1F);
            uint8_t rr_t3 = (msg_elements[8] & 0x7) << 3;
            rr_t3 |= (msg_elements[9] >> 5);
            uint32_t request_fnr = 51*((rr_t3-rr_t2) % 26) + rr_t3 + (51*26*rr_t1);

            // we will use random_access_info and request_fnr together as request_reference in the map,
            // if unique_references is set true
            uint32_t request_ref = (random_access_info << 0x16);
            request_ref |= request_fnr;

            /*
                msg_elements[10]:   timing advance
            */
            current.timing_advance = msg_elements[10];

            /*
                msg_elements[11 - 20]:   mobile allocation, flexible length, see 10.5.2.21
            */
            uint8_t mobile_allocation_len = msg_elements[11];
            if (mobile_allocation_len > 0)
            {
                std::string ma;
                for (int i=0; i<mobile_allocation_len; i++)
                {
                    for (int j=0; j<8; j++)
                    {
                        ma.push_back('0' + ((msg_elements[12 + i] >> (7-j)) & 0x1));
                    }
                }
                current.mobile_allocation = ma;
            }

            bool is_duplicate = false;
            if (d_unique_references)
            {
                if (d_assignment_map.find(request_ref) != d_assignment_map.end())
                {
                    is_duplicate = true;
                }
                else
                {
                    d_assignment_map[request_ref] = current;
                }
            }
            else
            {
                d_assignment_map[current.frame_nr] = current;
            }

            if (d_print_immediate_assignments && !is_duplicate)
            {
                std::cout << "\n------------------------------------------------\n" << std::endl;
                std::cout << "FrameNr: " << (unsigned)current.frame_nr << std::endl;
                std::cout << "Channel type: " << current.channel_type << std::endl;
                std::cout << "Timeslot: " << (unsigned)current.timeslot << std::endl;
                // Dont print subchannel if mode == 1 or if the assigned channel is TCH/F
                if (mode == 0 && channeltype >= 2)
                {
                    std::cout << "Subchannel: " << (unsigned)current.subchannel << std::endl;
                }
                std::cout << "Hopping: " << (unsigned)current.hopping << std::endl;
                if (current.hopping)
                {
                    std::cout << "MAIO: " << (unsigned)current.maio << std::endl;
                    std::cout << "HSN: " << (unsigned)current.hsn << std::endl;
                    std::cout << "Mobile Allocation: " << current.mobile_allocation << std::endl;
                }
                else
                {
                    std::cout << "ARFCN: " << (unsigned)current.arfcn << std::endl;
                }
                std::cout << "Timing Advance: " << (unsigned)current.timing_advance << std::endl;
            }
        }
    }

    std::vector<int> extract_immediate_assignment_impl::get_frame_numbers()
    {
        std::vector<int> fnrs;
        BOOST_FOREACH(immediate_assignment_map::value_type &i, d_assignment_map)
        {
            fnrs.push_back(i.second.frame_nr);
        }
        return fnrs;
    }

    std::vector<std::string> extract_immediate_assignment_impl::get_channel_types()
    {
        std::vector<std::string> types;
        BOOST_FOREACH(immediate_assignment_map::value_type &i, d_assignment_map)
        {
            types.push_back(i.second.channel_type);
        }
        return types;
    }

    std::vector<int> extract_immediate_assignment_impl::get_timeslots()
    {
        std::vector<int> timeslots;
        BOOST_FOREACH(immediate_assignment_map::value_type &i, d_assignment_map)
        {
            timeslots.push_back(i.second.timeslot);
        }
        return timeslots;
    }

    std::vector<int> extract_immediate_assignment_impl::get_subchannels()
    {
        std::vector<int> subchannels;
        BOOST_FOREACH(immediate_assignment_map::value_type &i, d_assignment_map)
        {
            subchannels.push_back(i.second.subchannel);
        }
        return subchannels;
    }

    std::vector<int> extract_immediate_assignment_impl::get_hopping()
    {
        std::vector<int> hopping;
        BOOST_FOREACH(immediate_assignment_map::value_type &i, d_assignment_map)
        {
            hopping.push_back(i.second.hopping);
        }
        return hopping;
    }

    std::vector<int> extract_immediate_assignment_impl::get_maios()
    {
        std::vector<int> maios;
        BOOST_FOREACH(immediate_assignment_map::value_type &i, d_assignment_map)
        {
            maios.push_back(i.second.maio);
        }
        return maios;
    }

    std::vector<int> extract_immediate_assignment_impl::get_hsns()
    {
        std::vector<int> hsns;
        BOOST_FOREACH(immediate_assignment_map::value_type &i, d_assignment_map)
        {
            hsns.push_back(i.second.hsn);
        }
        return hsns;
    }

    std::vector<int> extract_immediate_assignment_impl::get_arfcns()
    {
        std::vector<int> arfcns;
        BOOST_FOREACH(immediate_assignment_map::value_type &i, d_assignment_map)
        {
            arfcns.push_back(i.second.arfcn);
        }
        return arfcns;
    }

    std::vector<int> extract_immediate_assignment_impl::get_timing_advances()
    {
        std::vector<int> tas;
        BOOST_FOREACH(immediate_assignment_map::value_type &i, d_assignment_map)
        {
            tas.push_back(i.second.timing_advance);
        }
        return tas;
    }

    std::vector<std::string> extract_immediate_assignment_impl::get_mobile_allocations()
    {
        std::vector<std::string> mobile_allocations;
        BOOST_FOREACH(immediate_assignment_map::value_type &i, d_assignment_map)
        {
            mobile_allocations.push_back(i.second.mobile_allocation);
        }
        return mobile_allocations;
    }

    extract_immediate_assignment::sptr
    extract_immediate_assignment::make(bool print_immediate_assignments, bool ignore_gprs, bool unique_references)
    {
      return gnuradio::get_initial_sptr
        (new extract_immediate_assignment_impl(print_immediate_assignments, ignore_gprs, unique_references));
    }

    /*
     * The private constructor
     */
    extract_immediate_assignment_impl::extract_immediate_assignment_impl(bool print_immediate_assignments,
        bool ignore_gprs, bool unique_references)
      : gr::block("extract_immediate_assignment",
              gr::io_signature::make(0, 0, 0),
              gr::io_signature::make(0, 0, 0))
    {
        d_print_immediate_assignments = print_immediate_assignments;
        d_ignore_gprs = ignore_gprs;
        d_unique_references = unique_references;
        message_port_register_in(pmt::mp("msgs"));
        set_msg_handler(pmt::mp("msgs"), boost::bind(&extract_immediate_assignment_impl::process_message, this, _1));
    }

    /*
     * Our virtual destructor.
     */
    extract_immediate_assignment_impl::~extract_immediate_assignment_impl()
    {
    }
  } /* namespace gsm */
} /* namespace gr */

