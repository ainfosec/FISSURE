/* -*- c++ -*- */
/*
 * Copyright 2014 Airbus DS CyberSecurity.
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

#ifndef INCLUDED_ZWAVE_PACKET_SINK_9_6_IMPL_H
#define INCLUDED_ZWAVE_PACKET_SINK_9_6_IMPL_H

#include <Zwave/packet_sink_9_6.h>

#define MAX_PDU_SIZE 47 //frame size not pdu

namespace gr {
  namespace Zwave {

    class packet_sink_9_6_impl : public packet_sink_9_6
    {
          private:
      // Nothing to declare in this block.
    	enum {PREAMBLE_SEARCH, SYNC_SEARCH, HEADER_READING, READ_DATA} state;
        unsigned int frame_shift_reg;
        unsigned int frame_shift;
        unsigned int data_shift;
        //manchester_related
        unsigned int bit_pair;
        unsigned int manchester_last;
        //**********************
        struct s_frame_struct
        {
            unsigned int home_id;
            unsigned int length;
            unsigned int device_id;
            unsigned int frame_ctrl;
            unsigned int dest_id;
            unsigned char frame[MAX_PDU_SIZE+1];
            unsigned int CRC;
        };
        struct s_frame_struct  frame_struct;
        unsigned char buf[512];


     public:
      packet_sink_9_6_impl();
      ~packet_sink_9_6_impl();
      void crc_computing(void);

      int general_work(int noutput_items,
		       gr_vector_int &ninput_items,
		       gr_vector_const_void_star &input_items,
		       gr_vector_void_star &output_items);
    };

  } // namespace Zwave
} // namespace gr

#endif /* INCLUDED_ZWAVE_PACKET_SINK_9_6_IMPL_H */

