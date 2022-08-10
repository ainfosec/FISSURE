/* -*- c++ -*- */
/*
 * Copyright 2013 Airbus DS CyberSecurity.
 * Authors: Jean-Michel Picod, Arnaud Lebrun, Jonathan Christofer Demay
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
#include "preamble_impl.h"
#include <string.h>
#include <gnuradio/block_detail.h>

#define ZWAVE 0x01
#define PREAMBLE_SIZE 25 // <<<< of preamble table size

namespace gr {
  namespace Zwave {

    preamble::sptr
    preamble::make()
    {
      return gnuradio::get_initial_sptr
        (new preamble_impl());
    }

    //Construtor
    preamble_impl::preamble_impl()
      : gr::block("preamble",
        gr::io_signature::make(0, 0, 0),
        gr::io_signature::make(0, 0, 0))
{
    int jojo=0;
    for(;jojo<PREAMBLE_SIZE;jojo++) preamble[jojo]=0x55;
    preamble[jojo]=0xF0;

    //Queue stuff
    message_port_register_out(pmt::mp("out"));
    message_port_register_in(pmt::mp("in"));
    set_msg_handler(pmt::mp("in"), boost::bind(&preamble_impl::general_work, this, _1));

}

    //Destructor
    preamble_impl::~preamble_impl()
    {
    }


    // """main""" function
void preamble_impl::general_work (pmt::pmt_t msg){

	if(pmt::is_eof_object(msg)) {
		message_port_pub(pmt::mp("out"), pmt::PMT_EOF);
		detail().get()->set_done(true);
		return;
	}

	assert(pmt::is_pair(msg));
	pmt::pmt_t blob = pmt::cdr(msg);

	size_t data_len = pmt::blob_length(blob);
	assert(data_len);
	assert(data_len < 256 - 1);
	//Check if Zwave frame
    char temp[256];
    std::memcpy(temp, pmt::blob_data(blob), data_len);
    if(temp[0] == ZWAVE){

    std::memcpy(preamble + 1 + PREAMBLE_SIZE, ((const char*)pmt::blob_data(blob))+8, data_len-8); // blob_data+1 to remove the 2 byte header

    //2 byte added at the end of the packet
    preamble[data_len+1+PREAMBLE_SIZE-8] = 0xAA;


//    for(int toto=0;toto< (PREAMBLE_SIZE+data_len-8+2);toto++)  preamble[toto] ^=  0xff;

	pmt::pmt_t packet = pmt::make_blob(preamble, data_len-8 + 1+1+PREAMBLE_SIZE); //padding of 1 octets

	message_port_pub(pmt::mp("out"), pmt::cons(pmt::PMT_NIL, packet));
	}
    }

  } /* namespace Zwave */
} /* namespace gr */

