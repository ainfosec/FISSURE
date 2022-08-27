/* -*- c++ -*- */
/*
 * @file
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
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <gnuradio/io_signature.h>
#include "universal_ctrl_chans_demapper_impl.h"
#include <gsm/endian.h>
#include <gsm/gsmtap.h>
#include <set>

#define BURST_SIZE 148

namespace gr {
  namespace gsm {

    universal_ctrl_chans_demapper::sptr
    universal_ctrl_chans_demapper::make(unsigned int timeslot_nr, const std::vector<int> &downlink_starts_fn_mod51, const std::vector<int> &downlink_channel_types, const std::vector<int> &downlink_subslots, const std::vector<int> &uplink_starts_fn_mod51, const std::vector<int> &uplink_channel_types, const std::vector<int> &uplink_subslots)
    {     
      return gnuradio::get_initial_sptr
        (new universal_ctrl_chans_demapper_impl(timeslot_nr, downlink_starts_fn_mod51, downlink_channel_types, downlink_subslots, uplink_starts_fn_mod51, uplink_channel_types, uplink_subslots));
    }

    /*
     * The private constructor
     */
    universal_ctrl_chans_demapper_impl::universal_ctrl_chans_demapper_impl(unsigned int timeslot_nr, const std::vector<int> &downlink_starts_fn_mod51, const std::vector<int> &downlink_channel_types, const std::vector<int> &downlink_subslots, const std::vector<int> &uplink_starts_fn_mod51, const std::vector<int> &uplink_channel_types, const std::vector<int> &uplink_subslots)
      : gr::block("universal_ctrl_chans_demapper",
              gr::io_signature::make(0, 0, 0),
              gr::io_signature::make(0, 0, 0)),
        d_timeslot_nr(timeslot_nr),
        d_downlink_starts_fn_mod51(51, 0),
        d_downlink_channel_types(51, 0),
        d_downlink_subslots(102, 0),
        d_uplink_starts_fn_mod51(51, 0),
        d_uplink_channel_types(51, 0),
        d_uplink_subslots(102, 0)
    {
        if(downlink_starts_fn_mod51.size() != 51  ||
           downlink_channel_types.size()   != 51  ||
           downlink_subslots.size()        != 102 ||
           uplink_starts_fn_mod51.size()   != 51  ||
           uplink_channel_types.size()     != 51  ||
           uplink_subslots.size()          != 102 )
        {
            std::cout << "Check lengths of the vectors passed to the universal demapper - _starts_fn_mod15 and _sublots should have 51 elements, _subslots should have 102 elements" << std::endl;
            std::runtime_error("Check lengths of the vectors passed to the universal demapper - _starts_fn_mod15 and _sublots should have 51 elements, _subslots should have 102 elements");
        }
        std::copy(downlink_starts_fn_mod51.begin(), downlink_starts_fn_mod51.end(), d_downlink_starts_fn_mod51.begin());
        std::copy(downlink_channel_types.begin(), downlink_channel_types.end(), d_downlink_channel_types.begin());
        std::copy(downlink_subslots.begin(), downlink_subslots.end(), d_downlink_subslots.begin());
        std::copy(uplink_starts_fn_mod51.begin(), uplink_starts_fn_mod51.end(), d_uplink_starts_fn_mod51.begin());
        std::copy(uplink_channel_types.begin(), uplink_channel_types.end(), d_uplink_channel_types.begin());
        std::copy(uplink_subslots.begin(), uplink_subslots.end(), d_uplink_subslots.begin());
        
        message_port_register_in(pmt::mp("bursts"));
        set_msg_handler(pmt::mp("bursts"), boost::bind(&universal_ctrl_chans_demapper_impl::filter_ctrl_chans, this, boost::placeholders::_1));
        message_port_register_out(pmt::mp("bursts"));
    }

    /*
     * Our virtual destructor.
     */
    universal_ctrl_chans_demapper_impl::~universal_ctrl_chans_demapper_impl()
    {
    }
    
    void universal_ctrl_chans_demapper_impl::filter_ctrl_chans(pmt::pmt_t burst_in)
    {
        pmt::pmt_t header_plus_burst = pmt::cdr(burst_in);
        int8_t * burst_in_int8 = (int8_t *)pmt::blob_data(header_plus_burst);        
        gsmtap_hdr * header = (gsmtap_hdr *)(burst_in_int8);

        if(header->timeslot==d_timeslot_nr)
        {
            int * starts_fn_mod51;
            int * channel_types;
            int * subslots;
            uint32_t * frame_numbers;
            pmt::pmt_t * bursts;                  
            
            uint32_t frame_nr = be32toh(header->frame_number); //get frame number
            uint32_t fn_mod51 = frame_nr % 51; //frame number modulo 51
            uint32_t fn_mod102 = frame_nr % 102; //frame number modulo 102
            
            //create new burst
            int8_t burst_tmp[sizeof(gsmtap_hdr)+BURST_SIZE];
            memcpy(burst_tmp, burst_in_int8, sizeof(gsmtap_hdr)+BURST_SIZE);
            pmt::pmt_t msg_binary_blob = pmt::make_blob(burst_tmp,sizeof(gsmtap_hdr)+BURST_SIZE);
            pmt::pmt_t burst_out = pmt::cons(pmt::PMT_NIL, msg_binary_blob);
            gsmtap_hdr * new_header = (gsmtap_hdr *)pmt::blob_data(msg_binary_blob);
                        
            //get information if burst is from uplink or downlink            
            bool uplink_burst = (be16toh(header->arfcn) & 0x4000) ? true : false;

            //select right set of configuration and history for uplink or downlink
            if(uplink_burst) {
                starts_fn_mod51 = &d_uplink_starts_fn_mod51[0];
                channel_types = &d_uplink_channel_types[0];
                subslots = &d_uplink_subslots[0];
                frame_numbers = d_uplink_frame_numbers;
                bursts = d_uplink_bursts;
            } else {
                starts_fn_mod51 = &d_downlink_starts_fn_mod51[0];
                channel_types = &d_downlink_channel_types[0];
                subslots = &d_downlink_subslots[0];
                frame_numbers = d_downlink_frame_numbers;
                bursts = d_downlink_bursts;
            }

            //set type
            new_header->type = GSMTAP_TYPE_UM;
            //set type of the channel
            uint32_t ch_type = channel_types[fn_mod51];
            if(ch_type != 0)
            {
                new_header->sub_type = ch_type;
            }
            new_header->sub_slot = subslots[fn_mod102];

            if (ch_type == GSMTAP_CHANNEL_RACH)
            {
                message_port_pub(pmt::mp("bursts"), burst_out);
                return;
            }

            uint32_t fn51_start = starts_fn_mod51[fn_mod51];
            uint32_t fn51_stop = fn51_start + 3;

            if(fn_mod51>=fn51_start && fn_mod51<=fn51_stop)
            {
                uint32_t ii = fn_mod51 - fn51_start;
                frame_numbers[ii] = frame_nr;
                bursts[ii] = burst_out;
            }
            
            if(fn_mod51==fn51_stop)
            {
                //check for a situation where some bursts were lost
                //in this situation frame numbers won't be consecutive
                bool frames_are_consecutive = true;
                for(int jj=1; jj<4; jj++)
                {
                    if((frame_numbers[jj] - frame_numbers[jj-1])!=1)
                    {
                        frames_are_consecutive = false;
                    }
                }
                if(frames_are_consecutive)
                {
                    //send bursts to the output
                    for(int jj=0; jj<4; jj++)
                    {
                        message_port_pub(pmt::mp("bursts"), bursts[jj]);
                    }
                }
            }
        }
    }
  } /* namespace gsm */
} /* namespace gr */
