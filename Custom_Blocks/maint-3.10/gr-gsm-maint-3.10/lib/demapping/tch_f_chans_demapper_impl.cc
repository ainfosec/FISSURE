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
#include "tch_f_chans_demapper_impl.h"
#include <gsm/endian.h>
#include <gsm/gsmtap.h>

#define BURST_SIZE 148

namespace gr {
  namespace gsm {

    tch_f_chans_demapper::sptr
    tch_f_chans_demapper::make(unsigned int timeslot_nr)
    {
      return gnuradio::get_initial_sptr
        (new tch_f_chans_demapper_impl(timeslot_nr));
    }

    /*
     * The private constructor
     *
     */
    tch_f_chans_demapper_impl::tch_f_chans_demapper_impl(unsigned int timeslot_nr)
      : gr::block("tch_f_chans_demapper",
              gr::io_signature::make(0, 0, 0),
              gr::io_signature::make(0, 0, 0)),
       d_timeslot(timeslot_nr)

    {
//        for (int ii=0; ii<3; ii++)
//        {
        //            d_bursts_stolen[ii] = false;
        //        }

        message_port_register_in(pmt::mp("bursts"));
        set_msg_handler(pmt::mp("bursts"), boost::bind(&tch_f_chans_demapper_impl::filter_tch_chans, this, boost::placeholders::_1));
        message_port_register_out(pmt::mp("tch_bursts"));
        message_port_register_out(pmt::mp("acch_bursts"));
    }

    /*
     * Our virtual destructor.
     */
    tch_f_chans_demapper_impl::~tch_f_chans_demapper_impl()
    {
    }

    void tch_f_chans_demapper_impl::filter_tch_chans(pmt::pmt_t msg)
    {
        pmt::pmt_t header_plus_burst = pmt::cdr(msg);
        gsmtap_hdr * header = (gsmtap_hdr *)pmt::blob_data(header_plus_burst);

        uint32_t frame_nr = be32toh(header->frame_number);
        uint32_t fn_mod26 = frame_nr % 26;
        uint32_t fn_mod13 = frame_nr % 13;
        int8_t * burst_bits = (int8_t *)(pmt::blob_data(header_plus_burst))+sizeof(gsmtap_hdr);

        if(header->timeslot == d_timeslot){
            int8_t new_msg[sizeof(gsmtap_hdr)+BURST_SIZE];
            gsmtap_hdr * new_hdr = (gsmtap_hdr*)new_msg;
            memcpy(new_msg, header, sizeof(gsmtap_hdr)+BURST_SIZE);

            new_hdr->sub_type = GSMTAP_CHANNEL_TCH_F;
            if (fn_mod13 == 12)
                new_hdr->sub_type = GSMTAP_CHANNEL_ACCH|GSMTAP_CHANNEL_TCH_F;

            pmt::pmt_t msg_binary_blob = pmt::make_blob(new_msg,sizeof(gsmtap_hdr)+BURST_SIZE);
            pmt::pmt_t msg_out = pmt::cons(pmt::PMT_NIL, msg_binary_blob);

            //distinguishing uplink and downlink bursts
            bool uplink_burst = (be16toh(header->arfcn) & 0x4000) ? true : false;

            if(uplink_burst)
            {
                sacch_tch_demapper(fn_mod13, fn_mod26, frame_nr,d_bursts_sacch_ul,
                                   d_frame_numbers_sacch_ul, d_bursts_ul, d_frame_numbers_ul, msg_out);
            }
            else
            {
                sacch_tch_demapper(fn_mod13, fn_mod26, frame_nr,d_bursts_sacch_dl,
                                   d_frame_numbers_sacch_dl, d_bursts_dl, d_frame_numbers_dl, msg_out);
            }

        }
    }

    void tch_f_chans_demapper_impl::sacch_tch_demapper(uint32_t fn_mod13, u_int32_t fn_mod26, uint32_t frame_nr,
                                                       pmt::pmt_t *d_bursts_sacch,
                                                       uint32_t *d_frame_numbers_sacch, pmt::pmt_t d_bursts[3][8],
                                                       uint32_t d_frame_numbers[3][8], pmt::pmt_t msg_out)
    {
        bool frames_are_consecutive = true;
        if (fn_mod13 == 12)
        {
            // position of SACCH burst based on timeslot
            // see specification gsm 05.02
            uint32_t index;
            bool is_sacch = false;

            if (d_timeslot % 2 == 0 && fn_mod26 == 12)
            {
                index = (((frame_nr - 12) / 26) - (d_timeslot / 2)) % 4;
                is_sacch = true;
            }
            else if (d_timeslot % 2 == 1 && fn_mod26 == 25)
            {
                index = (((frame_nr - 25) / 26) - ((d_timeslot - 1) / 2)) % 4;
                is_sacch = true;
            }

            if (is_sacch)
            {
                d_bursts_sacch[index] = msg_out;
                d_frame_numbers_sacch[index] = frame_nr;

                if (index == 3)
                {
                    //check for a situation where some bursts were lost
                    //in this situation frame numbers won't be consecutive
                    frames_are_consecutive = true;
                    for(int jj=1; jj<4; jj++)
                    {
                        if((d_frame_numbers_sacch[jj]-d_frame_numbers_sacch[jj-1]) != 26)
                        {
                            frames_are_consecutive = false;
                        }
                    }
                    if(frames_are_consecutive)
                    {
                        //send bursts to the output
                        for(int jj=0; jj<4; jj++)
                        {
                            message_port_pub(pmt::mp("acch_bursts"), d_bursts_sacch[jj]);
                        }
                    }
                }
            }
        }
        else
        {
            if (fn_mod13 <= 3)
            {
                // add to b1 and b3
                d_bursts[0][fn_mod13] = msg_out;
                d_bursts[2][fn_mod13 + 4] = msg_out;

                // set framenumber for later checking of continuity
                d_frame_numbers[0][fn_mod13] = frame_nr;
                d_frame_numbers[2][fn_mod13 + 4] = frame_nr;
            }
            else if (fn_mod13 >= 4 && fn_mod13 <= 7)
            {
                // add to b1 and b2
                d_bursts[0][fn_mod13] = msg_out;
                d_bursts[1][fn_mod13 - 4] = msg_out;

                // set framenumber for later checking of continuity
                d_frame_numbers[0][fn_mod13] = frame_nr;
                d_frame_numbers[1][fn_mod13 - 4] = frame_nr;
            }
            else if (fn_mod13 >= 8 && fn_mod13 <= 11)
            {
                // add to b2 and b3
                d_bursts[1][fn_mod13 - 4] = msg_out;
                d_bursts[2][fn_mod13 - 8] = msg_out;

                // set framenumber for later checking of continuity
                d_frame_numbers[1][fn_mod13 - 4] = frame_nr;
                d_frame_numbers[2][fn_mod13 - 8] = frame_nr;
            }

            // send burst 1 or burst 2 to output
            if (fn_mod13 == 3 || fn_mod13 == 7 || fn_mod13 == 11)
            {
                int tch_burst_nr = 0;

                if (fn_mod13 == 11)
                {
                    tch_burst_nr = 1;
                }
                else if (fn_mod13 == 3)
                {
                    tch_burst_nr = 2;
                }

                //check for a situation where some bursts were lost
                //in this situation frame numbers won't be consecutive
                frames_are_consecutive = true;

                for(int jj=1; jj<8; jj++)
                {
                    if (((d_frame_numbers[tch_burst_nr][jj] - d_frame_numbers[tch_burst_nr][jj-1]) != 1) && frames_are_consecutive)
                    {
                        frames_are_consecutive = false;
                        // burst 3 has 1 sacch burst in between
                        if (tch_burst_nr == 2 && jj == 4
                            && d_frame_numbers[tch_burst_nr][jj] - d_frame_numbers[tch_burst_nr][jj - 1] == 2)
                        {
                            frames_are_consecutive = true;
                        }
                    }
                }

                if(frames_are_consecutive)
                {
                    //send bursts to the output
                    for(int jj=0; jj<8; jj++)
                    {
                        message_port_pub(pmt::mp("tch_bursts"), d_bursts[tch_burst_nr][jj]);
                    }
                    // useless
//                        d_bursts_stolen[tch_burst_nr] = false;
                }
            }
        }
    }
  } /* namespace gsm */
} /* namespace gr */

