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
#include "dqpsk_mapper_ff_impl.h"

namespace gr {
  namespace ieee802_15_4 {

    dqpsk_mapper_ff::sptr
    dqpsk_mapper_ff::make(int framelen, bool forward)
    {
      return gnuradio::get_initial_sptr
        (new dqpsk_mapper_ff_impl(framelen, forward));
    }

    /*
     * The private constructor
     */
    dqpsk_mapper_ff_impl::dqpsk_mapper_ff_impl(int framelen, bool forward)
      : gr::sync_block("dqpsk_mapper_ff",
              gr::io_signature::make(1,1,sizeof(float)),
              gr::io_signature::make(1,1,sizeof(float))),
      d_forward(forward),
      d_framelen(framelen),
      d_symctr(0),
      d_nmem(4)
    {
      if(d_forward)
        d_init_val = M_PI/4;
      else
        d_init_val = -M_PI/4;
      d_mem.assign(d_nmem, d_nmem, d_init_val);
    }

    /*
     * Our virtual destructor.
     */
    dqpsk_mapper_ff_impl::~dqpsk_mapper_ff_impl()
    {}

    void
    dqpsk_mapper_ff_impl::reset_mem()
    {
      for(int i=0; i<d_nmem; i++)
        d_mem[i] = d_init_val;
    }

    int
    dqpsk_mapper_ff_impl::work(int noutput_items,
			  gr_vector_const_void_star &input_items,
			  gr_vector_void_star &output_items)
    {
        const float *in = (const float *) input_items[0];
        float *out = (float *) output_items[0];

        if(d_forward)
        {
          for(int i=0; i<noutput_items; i++)
          {
            out[i] = fmod(in[i] + d_mem[3], 2*M_PI);
            // std::cout << "i: " << i << " | " << in[i]*180/M_PI << " + " << d_mem[3]*180/M_PI << " = " << out[i]*180/M_PI << std::endl;
            d_mem.push_front(out[i]);
            d_symctr++;
            if(d_symctr == d_framelen)
            {
              reset_mem();
              d_symctr = 0;
            }
          }          
        }
        else
        {
          // make sure the output lies in [-pi, pi]
          for(int i=0; i<noutput_items; i++)
          {
            out[i] = in[i] + d_mem[3];
            if(out[i] > M_PI)
              out[i] -= 2*M_PI;
            else if(out[i] < -M_PI)
              out[i] += 2*M_PI;  
                        
            d_mem.push_front(-in[i]);
            d_symctr++;
            if(d_symctr == d_framelen)
            {
              reset_mem(); 
              d_symctr = 0;           
            }
          }
        }

        return noutput_items;
    }

  } /* namespace ieee802_15_4 */
} /* namespace gr */

