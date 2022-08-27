/* -*- c++ -*- */
/* @file
 * @author Piotr Krysik <ptrkrysik@gmail.com>
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
#include <gsm/endian.h>
#include <gsm/gsmtap.h>
#include <gsm/gsm_constants.h>
#include "gen_test_ab_impl.h"

namespace gr {
  namespace gsm {

    static uint8_t rach_synch_seq[] = {
      0, 1, 0, 0, 1, 0, 1, 1, 0, 1, 1, 1, 1, 1,
      1, 1, 1, 0, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0  ,
      1, 0, 1, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0,
    };
  
    static uint8_t AB[] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 1, 0, 1, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 1, 1, 0, 1, 1, 1, 0, 1, 0, 1, 0, 1, 1, 0, 1, 0, 1, 0, 0, 1, 0, 0, 1, 1, 0, 1, 0, 1, 1, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
//    static uint8_t AB[] = {0, 0, 1, 0, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1, 1, 1, 1};
// static uint8_t AB[] = { 1, 1, 0, 0, 0, 1, 0, 1, 1, 0, 1, 1, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 1, 0, 1, 0, 1, 0, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, 0, 0, 1, 1, 0, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1, 1, 1, 0, 0, 1, 1, 0, 0, 0, 1, 0, 1, 0, 1, 0, 0, 1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 1, 1, 0, 0, 1, 1};
//  static uint8_t AB[] = {1,1,1,1,1,1,1,1,1,0,1,1,0,1,0,0,1,0,0,0,0,0,0,0,0,1,1,0,0,1,1,0,0,1,0,1,0,1,0,1,1,1,0,0,0,0,1,1,1,0,0,1,0,0,0,1,0,1,0,1,0,0,1,0,1,0,1,1,0,1,1,0,0,1,0,1,0,0,0,1,1,0,0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1
//  ,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1};
    gen_test_ab::sptr
    gen_test_ab::make()
    {
      return gnuradio::get_initial_sptr
        (new gen_test_ab_impl());
    }

    /*
     * The private constructor
     */
    gen_test_ab_impl::gen_test_ab_impl()
      : gr::block("gen_test_ab",
              gr::io_signature::make(0, 0, 0),
              gr::io_signature::make(0, 0, 0))
    {
        message_port_register_in(pmt::intern("bursts_in"));
        message_port_register_out(pmt::intern("bursts_out"));

        set_msg_handler(pmt::intern("bursts_in"),  boost::bind(&gen_test_ab_impl::generate_ab,   this, boost::placeholders::_1));
    }

    /*
     * Our virtual destructor.
     */
    gen_test_ab_impl::~gen_test_ab_impl()
    {
    }
    
    void gen_test_ab_impl::generate_ab(pmt::pmt_t burst)
    {
        uint8_t buf[sizeof(gsmtap_hdr) + 148];
        struct gsmtap_hdr *tap_header = (struct gsmtap_hdr *) buf;
        uint8_t *access_burst = buf + sizeof(gsmtap_hdr);

//        memset(access_burst, 0, 8); /* TB */
//        memcpy(access_burst + 8, rach_synch_seq, 41); /* sync seq */
//        memcpy(access_burst + 49, AB, 36); /* payload */
//        memset(access_burst + 85, 0, 63); /* TB + GP */
        
        memcpy(access_burst, AB, 148);
        
        gsmtap_hdr * header = (gsmtap_hdr *)(pmt::blob_data(pmt::cdr(burst)));
        uint32_t frame_nr = be32toh(header->frame_number);
        frame_nr = (frame_nr+51)% (26*51*2048);
        
        tap_header->version = GSMTAP_VERSION;
        tap_header->hdr_len = sizeof(gsmtap_hdr) / 4;
        tap_header->type = GSMTAP_TYPE_UM_BURST;
        tap_header->sub_type = GSMTAP_BURST_ACCESS;
        tap_header->frame_number = htobe32(frame_nr);
        tap_header->timeslot = header->timeslot;
        tap_header->arfcn = 0;
        
        pmt::pmt_t blob = pmt::make_blob(buf, sizeof(gsmtap_hdr) + BURST_SIZE);
        pmt::pmt_t pdu_header = pmt::make_dict();
        
        pmt::pmt_t new_msg = pmt::cons(pdu_header, blob);
        message_port_pub(pmt::intern("bursts_out"), new_msg);
    }
  } /* namespace gsm */
} /* namespace gr */

