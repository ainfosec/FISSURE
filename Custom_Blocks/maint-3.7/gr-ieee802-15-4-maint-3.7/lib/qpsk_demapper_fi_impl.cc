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
#include "qpsk_demapper_fi_impl.h"

namespace gr {
  namespace ieee802_15_4 {

    qpsk_demapper_fi::sptr
    qpsk_demapper_fi::make()
    {
      return gnuradio::get_initial_sptr
        (new qpsk_demapper_fi_impl());
    }

    /*
     * The private constructor
     */
    qpsk_demapper_fi_impl::qpsk_demapper_fi_impl()
      : gr::sync_block("qpsk_demapper_fi",
              gr::io_signature::make(1,1, sizeof(float)),
              gr::io_signature::make(2,2, sizeof(int)))
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
    qpsk_demapper_fi_impl::~qpsk_demapper_fi_impl()
    {
      delete[] d_angle_tab;
    }

    void
    qpsk_demapper_fi_impl::decide(int* out_I, int* out_Q, const float* in, int nitems)
    {
      float p; // phase
      for(int i=0; i<nitems; i++)
      {
        p = in[i]; 
        if(p >= -M_PI/4 && p < M_PI/4)
        {
          out_I[i] = 1;
          out_Q[i] = 1;
        }
        else if(p >= M_PI/4 && p < 3.0*M_PI/4)
        {
          out_I[i] = -1;
          out_Q[i] = 1;
        }
        else if(p >= 3.0*M_PI/4 || p < -3.0*M_PI/4)
        {
          out_I[i] = -1;
          out_Q[i] = -1;          
        }
        else if(p >= -3.0*M_PI/4 && p < -M_PI/4)
        {
          out_I[i] = 1;
          out_Q[i] = -1;         
        }
        else
          throw std::runtime_error(std::string("Invalid input value: ")+std::to_string(p));
      }
    }

    int
    qpsk_demapper_fi_impl::work(int noutput_items,
			  gr_vector_const_void_star &input_items,
			  gr_vector_void_star &output_items)
    {
        const float *in = (const float *) input_items[0];
        int *out_I = (int *) output_items[0];
        int *out_Q = (int *) output_items[1];

        decide(out_I, out_Q, in, noutput_items);

        return noutput_items;
    }

  } /* namespace ieee802_15_4 */
} /* namespace gr */

