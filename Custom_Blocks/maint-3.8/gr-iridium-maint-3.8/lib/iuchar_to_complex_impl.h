/* -*- c++ -*- */
/*
 * Copyright 2020 Free Software Foundation, Inc.
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

#ifndef INCLUDED_IRIDIUM_IUCHAR_TO_COMPLEX_IMPL_H
#define INCLUDED_IRIDIUM_IUCHAR_TO_COMPLEX_IMPL_H

#include <iridium/iuchar_to_complex.h>

namespace gr {
  namespace iridium {

    class iuchar_to_complex_impl : public iuchar_to_complex
    {
     private:
        std::vector<gr_complex> d_lut;

     public:
      iuchar_to_complex_impl();
      ~iuchar_to_complex_impl();

      // Where all the action really happens
      int work(int noutput_items,
         gr_vector_const_void_star &input_items,
         gr_vector_void_star &output_items);
    };

  } // namespace iridium
} // namespace gr

#endif /* INCLUDED_IRIDIUM_IUCHAR_TO_COMPLEX_IMPL_H */

