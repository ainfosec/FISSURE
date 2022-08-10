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
#include "dqpsk_soft_demapper_cc_impl.h"

namespace gr {
  namespace ieee802_15_4 {

    dqpsk_soft_demapper_cc::sptr
    dqpsk_soft_demapper_cc::make(int framelen)
    {
      return gnuradio::get_initial_sptr
        (new dqpsk_soft_demapper_cc_impl(framelen));
    }

    /*
     * The private constructor
     */
    dqpsk_soft_demapper_cc_impl::dqpsk_soft_demapper_cc_impl(int framelen)
      : gr::sync_block("dqpsk_soft_demapper_cc",
              gr::io_signature::make(1,1, sizeof(gr_complex)),
              gr::io_signature::make(1,1, sizeof(gr_complex))),
      d_framelen(framelen),
      d_symctr(0),
      d_nmem(4)
    {
      d_init_val = std::exp(gr_complex(0,-1*M_PI/4));
      d_mem.assign(d_nmem, d_nmem, d_init_val);
    }

    /*
     * Our virtual destructor.
     */
    dqpsk_soft_demapper_cc_impl::~dqpsk_soft_demapper_cc_impl()
    {
    }

    void
    dqpsk_soft_demapper_cc_impl::reset_mem()
    {
      for(int i=0; i<d_nmem; i++)
        d_mem[i] = d_init_val;
    }

    int
    dqpsk_soft_demapper_cc_impl::work(int noutput_items,
			  gr_vector_const_void_star &input_items,
			  gr_vector_void_star &output_items)
    {
        const gr_complex *in = (const gr_complex *) input_items[0];
        gr_complex *out = (gr_complex *) output_items[0];

        for(int i=0; i<noutput_items; i++)
        {
          out[i] = in[i]*d_mem[3];
          d_mem.push_front(conj(in[i]));
          d_symctr++;
          if(d_symctr == d_framelen)
          {
            reset_mem(); 
            d_symctr = 0;           
          }
        }

        return noutput_items;
    }

  } /* namespace ieee802_15_4 */
} /* namespace gr */

