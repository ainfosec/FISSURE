/* -*- c++ -*- */
/* 
 * Copyright 2014 Jared Boone <jared@sharebrained.com>.
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

#ifndef INCLUDED_TPMS_FIXED_LENGTH_FRAME_SINK_IMPL_H
#define INCLUDED_TPMS_FIXED_LENGTH_FRAME_SINK_IMPL_H

#include <tpms/fixed_length_frame_sink.h>

namespace gr {
  namespace tpms {

    class fixed_length_frame_sink_impl : public fixed_length_frame_sink
    {
     private:
      enum state_t { STATE_SYNC_SEARCH, STATE_HAVE_SYNC };

      static const int MAX_PKT_LEN = 4096;

      //msg_queue::sptr d_target_queue;
      pmt::pmt_t d_message_port;
      pmt::pmt_t d_attributes;
      state_t d_state;
      /*
      unsigned char d_packet[MAX_PKT_LEN];
      unsigned char d_packet_byte;
      int d_packet_byte_index;
      int d_packetlen;
      int d_packetlen_cnt;
      */
      typedef std::vector<uint8_t> bits_t;
      typedef std::list<bits_t> packets_t;

      packets_t d_packets;

      int d_frame_length;

     protected:
      void enter_search();
      void enter_have_sync();

     public:
      //fixed_length_frame_sink_impl(int frame_length, msg_queue::sptr target_queue);
      fixed_length_frame_sink_impl(int frame_length, pmt::pmt_t attributes);
      ~fixed_length_frame_sink_impl();

      // Where all the action really happens
      int work(int noutput_items,
	       gr_vector_const_void_star &input_items,
	       gr_vector_void_star &output_items);
    };

  } // namespace tpms
} // namespace gr

#endif /* INCLUDED_TPMS_FIXED_LENGTH_FRAME_SINK_IMPL_H */

