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
#include <gsm/gsmtap.h>
#include "control_channels_decoder_impl.h"

#define DATA_BYTES 23

namespace gr {
  namespace gsm {

    static int ubits2sbits(ubit_t *ubits, sbit_t *sbits, int count)
    {
      int i;

      for (i = 0; i < count; i++) {
        if (*ubits == 0x23) {
          ubits++;
          sbits++;
          continue;
        }
        if ((*ubits++) & 1)
          *sbits++ = -127;
        else
          *sbits++ = 127;
      }

      return count;
    }

    control_channels_decoder::sptr
    control_channels_decoder::make()
    {
      return gnuradio::get_initial_sptr
        (new control_channels_decoder_impl());
    }

    /*
     * Constructor
     */
    control_channels_decoder_impl::control_channels_decoder_impl()
      : gr::block("control_channels_decoder",
              gr::io_signature::make(0, 0, 0),
              gr::io_signature::make(0, 0, 0)),
              d_collected_bursts_num(0)
    {
      //setup input/output ports
      message_port_register_in(pmt::mp("bursts"));
      set_msg_handler(pmt::mp("bursts"), boost::bind(&control_channels_decoder_impl::decode, this, boost::placeholders::_1));
      message_port_register_out(pmt::mp("msgs"));
    }

    control_channels_decoder_impl::~control_channels_decoder_impl()
    {
    }

    void control_channels_decoder_impl::decode(pmt::pmt_t msg)
    {
      ubit_t bursts_u[116 * 4];
      sbit_t bursts_s[116 * 4];
      uint8_t result[23];
      int n_errors, n_bits_total;
      int8_t header_plus_data[sizeof(gsmtap_hdr)+DATA_BYTES];

      d_bursts[d_collected_bursts_num] = msg;
      d_collected_bursts_num++;

      //get convecutive bursts
      if(d_collected_bursts_num==4)
      {
        d_collected_bursts_num=0;
        //reorganize data from input bursts
        for(int ii = 0; ii < 4; ii++)
        {
          pmt::pmt_t header_plus_burst = pmt::cdr(d_bursts[ii]);
          int8_t * burst_bits = (int8_t *)(pmt::blob_data(header_plus_burst))+sizeof(gsmtap_hdr);

          memcpy(&bursts_u[ii*116], &burst_bits[3],58);
          memcpy(&bursts_u[ii*116+58], &burst_bits[3+57+1+26],58);
        }
        //convert to soft bits
        ubits2sbits(bursts_u, bursts_s, 116 * 4);
        //decode
        if (gsm0503_xcch_decode(result, bursts_s, &n_errors, &n_bits_total) != -1)
        {
         //extract header of the first burst of the four bursts
          pmt::pmt_t first_header_plus_burst = pmt::cdr(d_bursts[0]);
          gsmtap_hdr * header = (gsmtap_hdr *)pmt::blob_data(first_header_plus_burst);
          //copy header and data
          memcpy(header_plus_data, header, sizeof(gsmtap_hdr));
          memcpy(header_plus_data+sizeof(gsmtap_hdr), result, DATA_BYTES);
          //set data type in the header
          ((gsmtap_hdr*)header_plus_data)->type = GSMTAP_TYPE_UM;
          //prepare message
          pmt::pmt_t msg_out = pmt::cons(pmt::PMT_NIL, pmt::make_blob(header_plus_data,DATA_BYTES+sizeof(gsmtap_hdr)));
          //send message to the output
          message_port_pub(pmt::mp("msgs"), msg_out);
        }
      }
    }
  } /* namespace gsm */
} /* namespace gr */

