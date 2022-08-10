/* -*- c++ -*- */
/*
 * Copyright 2017 Clayton Smith.
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

#ifndef INCLUDED_NRSC5_SIS_ENCODER_IMPL_H
#define INCLUDED_NRSC5_SIS_ENCODER_IMPL_H

#include <nrsc5/sis_encoder.h>

namespace gr {
  namespace nrsc5 {

    class sis_encoder_impl : public sis_encoder
    {
     private:
      unsigned int alfn;
      std::string short_name;
      unsigned char *bit;

      int crc12(unsigned char *sis);
      void write_bit(int b);
      void write_int(int n, int len);
      void write_char5(char c);
      void write_station_name_short();

     public:
      sis_encoder_impl(const std::string &short_name="ABCD");
      ~sis_encoder_impl();

      // Where all the action really happens
      int work(int noutput_items,
         gr_vector_const_void_star &input_items,
         gr_vector_void_star &output_items);
    };

  } // namespace nrsc5
} // namespace gr

#endif /* INCLUDED_NRSC5_SIS_ENCODER_IMPL_H */
