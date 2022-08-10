/* -*- c++ -*- */
/* @file
 * @author (C) 2015 by Piotr Krysik <ptrkrysik@gmail.com>
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
#include "tmsi_dumper_impl.h"
#include "grgsm/gsmtap.h"
#include <iostream>
#include <boost/format.hpp>

namespace gr {
namespace gsm {

void tmsi_dumper_impl::dump_tmsi(pmt::pmt_t msg)
{
    time_t t = time(0);
    tm *now = localtime(&t);

    pmt::pmt_t message_plus_header_blob = pmt::cdr(msg);
    uint8_t * message_plus_header = (uint8_t *)pmt::blob_data(message_plus_header_blob);
    gsmtap_hdr * header = (gsmtap_hdr *)message_plus_header;
    uint8_t * m = (uint8_t *)(message_plus_header+sizeof(gsmtap_hdr)); //message content

    uint8_t msg_len = m[0];
    uint8_t direction_and_protocol = m[1];
    uint8_t msg_type = m[2];

    if( direction_and_protocol == 0x06 &&                    //direction from originating site, transaction id==0, Radio Resouce Management protocol
            (msg_type==0x21 || msg_type==0x22 || msg_type==0x24) //types corresponding to paging requests
      )
    {
        //write timestamp
        switch(msg_type) {
        case 0x21: //Paging Request Type 1
        {
            uint8_t mobile_identity_type = m[5] & 0x07;
            unsigned int next_element_index = 0; //position of the next element
            bool found_id_element = false;

            if(mobile_identity_type == 0x04) //identity type: TMSI
            {
                write_tmsi(m+6);
                dump_file << "-";
                write_timestamp(now);
                dump_file << "-0";
                dump_file << std::endl;

                next_element_index = 10;
                found_id_element = true;
            } else if(mobile_identity_type == 0x01) //identity type: IMSI
            {
                dump_file << "0-";
                write_timestamp(now);
                dump_file << "-";
                write_imsi(m+5);
                dump_file << std::endl;

                next_element_index = 13;
                found_id_element = true;
            }

            if(found_id_element == true)
            {
                //check if there is additional id element
                uint8_t element_id = m[next_element_index];
                if((next_element_index < (msg_len+1)) && (element_id == 0x17)) {
                    //check if there is another element
                    uint8_t element_len = m[next_element_index+1];
                    mobile_identity_type = m[next_element_index+2] & 0x07;

                    if(mobile_identity_type == 0x04) //identity type: TMSI
                    {
                        write_tmsi(m+next_element_index+3); //write starting from position of the TMSI in the message
                        dump_file << "-";
                        write_timestamp(now);
                        dump_file << "-0";
                        dump_file << std::endl;
                    } else if(mobile_identity_type == 0x01) //identity type: IMSI
                    {
                        dump_file << "0-";
                        write_timestamp(now);
                        dump_file << "-";
                        write_imsi(m+next_element_index+2); //write starting from position of the IMSI in the message
                        dump_file << std::endl;
                    }
                }
                int ii;
            }
        }
        break; 
        case 0x22: //Paging Request Type 2
        {
            uint8_t mobile_identity_type = m[14] & 0x07;

            write_tmsi(m+4);//1st tmsi location
            dump_file << "-";
            write_timestamp(now);
            dump_file << "-0";
            dump_file << std::endl;

            write_tmsi(m+8);//2nd tmsi location
            dump_file << "-";
            write_timestamp(now);
            dump_file << "-0";
            dump_file << std::endl;

            if(mobile_identity_type == 0x04) //identity type: TMSI
            {
                write_tmsi(m+15);
                dump_file << "-";
                write_timestamp(now);
                dump_file << "-0";
                dump_file << std::endl;

            } else if(mobile_identity_type == 0x01) //identity type: IMSI
            {
                dump_file << "0-";
                write_timestamp(now);
                dump_file << "-";
                write_imsi(m+14);
                dump_file << std::endl;

            }
        }
        break;
        case 0x24: //Paging Request Type 3
        {
            int TMSI_INDEX[4] = {4,8,12,16}; // indexes of the 4 tmsi's

            for(int x =0; x < 4; x++)
            {
                write_tmsi(m+TMSI_INDEX[x]);
                dump_file << "-";
                write_timestamp(now);
                dump_file << "-0";
                dump_file << std::endl;
            }

        }
        break;
        }
    }
}

inline void tmsi_dumper_impl::write_timestamp(tm * now)
{
    dump_file << boost::format("%d%02d%02d%02d%02d%02d")
              % (now->tm_year + 1900-2000)                   //year -2000 here after the 1900 leaves you with 15 instead of 2015 (delivery reports format is 150112223501)
              % (now->tm_mon + 1)                           //month
              % now->tm_mday                                //day
              % now->tm_hour % now->tm_min % now->tm_sec;  //time of day
    return;
}

inline int swap(uint8_t c)
{
    uint8_t temp1, temp2;
    temp1 = c & 0x0F;
    temp2 = c & 0xF0;
    temp1=temp1 << 4;
    temp2=temp2 >> 4;
    return(temp2|temp1);
}

void tmsi_dumper_impl::write_imsi(uint8_t * imsi)
{
    dump_file << boost::format("%1x%02x%02x%02x%02x%02x%02x%02x")
              % (swap(imsi[0]) & 0x0f)
              % swap(imsi[1]) % swap(imsi[2]) % swap(imsi[3]) % swap(imsi[4]) % swap(imsi[5]) % swap(imsi[6]) % swap(imsi[7]);
    return;
}

void tmsi_dumper_impl::write_tmsi(uint8_t * tmsi)
{
    dump_file << boost::format("%02x%02x%02x%02x")
              % (int)tmsi[0] % (int)tmsi[1] % (int)tmsi[2] % (int)tmsi[3];
    return;
}


tmsi_dumper::sptr
tmsi_dumper::make()
{
    return gnuradio::get_initial_sptr
           (new tmsi_dumper_impl());
}

/*
 * The private constructor
 */
tmsi_dumper_impl::tmsi_dumper_impl()
    : gr::block("tmsi_dumper",
                gr::io_signature::make(0, 0, 0),
                gr::io_signature::make(0, 0, 0))
{
    dump_file.open("tmsicount.txt", std::ios_base::app);
    message_port_register_in(pmt::mp("msgs"));
    set_msg_handler(pmt::mp("msgs"), boost::bind(&tmsi_dumper_impl::dump_tmsi, this, _1));
}

/*
 * Our virtual destructor.
 */
tmsi_dumper_impl::~tmsi_dumper_impl()
{
    dump_file.close();
}
} /* namespace gsm */
} /* namespace gr */

