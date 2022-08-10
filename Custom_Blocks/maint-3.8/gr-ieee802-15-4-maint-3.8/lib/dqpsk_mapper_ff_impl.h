/* -*- c++ -*- */
/* 
 * Copyright 2015 Felix Wunsch, Communications Engineering Lab (CEL) / Karlsruhe Institute of Technology (KIT) <wunsch.felix@googlemail.com>.
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

#ifndef INCLUDED_IEEE802_15_4_DQPSK_MAPPER_FF_IMPL_H
#define INCLUDED_IEEE802_15_4_DQPSK_MAPPER_FF_IMPL_H

#include <ieee802_15_4/dqpsk_mapper_ff.h>
#include <boost/circular_buffer.hpp>

namespace gr {
  namespace ieee802_15_4 {

    class dqpsk_mapper_ff_impl : public dqpsk_mapper_ff
    {
     private:
      bool d_forward;
      int d_framelen;
      int d_symctr;
      int d_nmem;
      boost::circular_buffer<float> d_mem;
      float d_init_val;
      void reset_mem();

     public:
      dqpsk_mapper_ff_impl(int framelen, bool forward);
      ~dqpsk_mapper_ff_impl();

      int work(int noutput_items,
	       gr_vector_const_void_star &input_items,
	       gr_vector_void_star &output_items);
    };

  } // namespace ieee802_15_4
} // namespace gr

#endif /* INCLUDED_IEEE802_15_4_DQPSK_MAPPER_FF_IMPL_H */

