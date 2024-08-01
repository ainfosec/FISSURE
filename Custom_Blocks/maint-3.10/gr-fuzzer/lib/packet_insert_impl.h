/* -*- c++ -*- */
/*
 * Copyright 2022 gr-fuzzer author.
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

#ifndef INCLUDED_FUZZER_PACKET_INSERT_IMPL_H
#define INCLUDED_FUZZER_PACKET_INSERT_IMPL_H

#include <gnuradio/fuzzer/packet_insert.h>

namespace gr {
  namespace fuzzer {

    class packet_insert_impl : public packet_insert
    {
     private:
      std::vector<unsigned char> d_data;
      int d_offset;
      int d_periodicity;
      unsigned char d_data1[1000];
      long d_length;

     public:
      packet_insert_impl(const std::vector<unsigned char> &data,
                  int periodicity, int offset);
      ~packet_insert_impl();

      void rewind() { d_offset=0; }
      void set_data(const std::vector<unsigned char> &data) {
        d_data = data; rewind(); }

      int general_work(int noutput_items,
           gr_vector_int &ninput_items,
           gr_vector_const_void_star &input_items,
           gr_vector_void_star &output_items);
           
      void read_message(pmt::pmt_t msg);  

    };

  } // namespace fuzzer
} // namespace gr

#endif /* INCLUDED_FUZZER_PACKET_INSERT_IMPL_H */

