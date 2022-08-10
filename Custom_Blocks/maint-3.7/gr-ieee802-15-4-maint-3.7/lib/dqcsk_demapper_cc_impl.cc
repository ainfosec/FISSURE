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
#include "dqcsk_demapper_cc_impl.h"
#include <volk/volk.h>

namespace gr {
  namespace ieee802_15_4 {

    dqcsk_demapper_cc::sptr
    dqcsk_demapper_cc::make(std::vector< gr_complex> chirp_seq, std::vector< gr_complex > time_gap_1, std::vector< gr_complex > time_gap_2, int len_subchirp, int num_subchirps)
    {
      return gnuradio::get_initial_sptr
        (new dqcsk_demapper_cc_impl(chirp_seq, time_gap_1, time_gap_2, len_subchirp, num_subchirps));
    }

    /*
     * The private constructor
     */
    dqcsk_demapper_cc_impl::dqcsk_demapper_cc_impl(std::vector< gr_complex> chirp_seq, std::vector< gr_complex > time_gap_1, std::vector< gr_complex > time_gap_2, int len_subchirp, int num_subchirps)
      : gr::block("dqcsk_demapper_cc",
              gr::io_signature::make(1,1, sizeof(gr_complex)),
              gr::io_signature::make(1,1, sizeof(gr_complex))),
      d_chirp_seq(chirp_seq),
      d_time_gap_1(time_gap_1),
      d_time_gap_2(time_gap_2),
      d_len_subchirp(len_subchirp),
      d_num_subchirps(num_subchirps),
      d_chirp_seq_ctr(0)
    {
      set_min_output_buffer(d_num_subchirps);
    }

    /*
     * Our virtual destructor.
     */
    dqcsk_demapper_cc_impl::~dqcsk_demapper_cc_impl()
    {
    }

    void
    dqcsk_demapper_cc_impl::forecast (int noutput_items, gr_vector_int &ninput_items_required)
    {
      if(d_chirp_seq_ctr % 2 == 0)
        ninput_items_required[0] = d_num_subchirps*d_len_subchirp+d_time_gap_1.size();
      else
        ninput_items_required[0] = d_num_subchirps*d_len_subchirp+d_time_gap_2.size();
    }

    int
    dqcsk_demapper_cc_impl::general_work (int noutput_items,
                       gr_vector_int &ninput_items,
                       gr_vector_const_void_star &input_items,
                       gr_vector_void_star &output_items)
    {
        const gr_complex *in = (const gr_complex *) input_items[0];
        gr_complex *out = (gr_complex *) output_items[0];

        // correlate signal with chirp sequence to extract the DQPSK symbol phase
        gr_complex corrval;
        for(int i=0; i<d_num_subchirps; i++)
        {
          volk_32fc_x2_conjugate_dot_prod_32fc(&corrval, in+i*d_len_subchirp, &d_chirp_seq[i*d_len_subchirp], d_len_subchirp);
          out[i] = corrval;
        }

        int nitems_consumed = d_num_subchirps*d_len_subchirp;

        // drop the time gap
        if(d_chirp_seq_ctr % 2 == 0)
          nitems_consumed += d_time_gap_1.size();
        else
          nitems_consumed += d_time_gap_2.size();
        d_chirp_seq_ctr = (d_chirp_seq_ctr+1) % 2;

        consume_each (nitems_consumed);
        return d_num_subchirps;
    }

  } /* namespace ieee802_15_4 */
} /* namespace gr */

