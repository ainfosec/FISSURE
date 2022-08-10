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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <gnuradio/io_signature.h>
#include "qpsk_mapper_if_impl.h"

namespace gr {
  namespace ieee802_15_4 {

    qpsk_mapper_if::sptr
    qpsk_mapper_if::make()
    {
      return gnuradio::get_initial_sptr
        (new qpsk_mapper_if_impl());
    }

    /*
     * The private constructor
     */
    qpsk_mapper_if_impl::qpsk_mapper_if_impl()
      : gr::sync_block("qpsk_mapper_if",
              gr::io_signature::make(2,2, sizeof(int)),
              gr::io_signature::make(1,1, sizeof(float)))
    {
      d_angle_tab = new float[4];
      d_angle_tab[0] = 0;
      d_angle_tab[1] = M_PI/2;
      d_angle_tab[2] = -M_PI/2;
      d_angle_tab[3] = M_PI; 
    }

    /*
     * Our virtual destructor.
     */
    qpsk_mapper_if_impl::~qpsk_mapper_if_impl()
    {
      delete[] d_angle_tab;
    }

    int
    qpsk_mapper_if_impl::work(int noutput_items,
			  gr_vector_const_void_star &input_items,
			  gr_vector_void_star &output_items)
    {
        const int *in_I = (const int *) input_items[0];
        const int *in_Q = (const int *) input_items[1];
        float *out = (float *) output_items[0];

        for(int i=0; i<noutput_items; i++)
        {
          if(in_I[i] == 1 && in_Q[i] == 1)
            out[i] = d_angle_tab[0];
          else if(in_I[i] == -1 && in_Q[i] == 1)
            out[i] = d_angle_tab[1];
          else if(in_I[i] == 1 && in_Q[i] == -1)
            out[i] = d_angle_tab[2];
          else if(in_I[i] == -1 && in_Q[i] == -1)
            out[i] = d_angle_tab[3];
          else
          {
            std::cerr << "QPSK mapper input: " << int(in_I[i]) << "/" << int(in_Q[i]) << std::endl;
            throw std::runtime_error("Invalid input value");
          }
        }

        return noutput_items;
    }

  } /* namespace ieee802_15_4 */
} /* namespace gr */

