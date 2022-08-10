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
#include "dqcsk_mapper_fc_impl.h"
#include <volk/volk.h>

namespace gr {
  namespace ieee802_15_4 {

    dqcsk_mapper_fc::sptr
    dqcsk_mapper_fc::make(std::vector<gr_complex> chirp_seq, std::vector<gr_complex> time_gap_1, std::vector<gr_complex> time_gap_2, int len_subchirp, int num_subchirps, int nsym_frame)
    {
      return gnuradio::get_initial_sptr
        (new dqcsk_mapper_fc_impl(chirp_seq, time_gap_1, time_gap_2, len_subchirp, num_subchirps, nsym_frame));
    }

    /*
     * The private constructor
     */
    dqcsk_mapper_fc_impl::dqcsk_mapper_fc_impl(std::vector<gr_complex> chirp_seq, std::vector<gr_complex> time_gap_1, std::vector<gr_complex> time_gap_2, int len_subchirp, int num_subchirps, int nsym_frame)
      : gr::block("dqcsk_mapper_fc",
              gr::io_signature::make(1,1, sizeof(float)),
              gr::io_signature::make(1,1, sizeof(gr_complex))),
      d_chirp_seq(chirp_seq),
      d_time_gap_1(time_gap_1),
      d_time_gap_2(time_gap_2),
      d_len_subchirp(len_subchirp),
      d_num_subchirps(num_subchirps),
      d_chirp_seq_ctr(0),
      d_subchirp_ctr(0),
      d_nsym_frame(nsym_frame),
      d_sym_ctr(0)
    {
      max_len_timegap = std::max(d_time_gap_1.size(), d_time_gap_2.size());
      set_output_multiple(d_len_subchirp + max_len_timegap);
    }

    /*
     * Our virtual destructor.
     */
    dqcsk_mapper_fc_impl::~dqcsk_mapper_fc_impl()
    {}

    void
    dqcsk_mapper_fc_impl::forecast (int noutput_items, gr_vector_int &ninput_items_required)
    {
        ninput_items_required[0] = 1; 
    }

    void
    dqcsk_mapper_fc_impl::reset()
    {
      d_sym_ctr = 0;
      d_subchirp_ctr = 0;
      d_chirp_seq_ctr = 0;
    }

    int
    dqcsk_mapper_fc_impl::general_work (int noutput_items,
                       gr_vector_int &ninput_items,
                       gr_vector_const_void_star &input_items,
                       gr_vector_void_star &output_items)
    {
        const float *in = (const float*) input_items[0];
        gr_complex *out = (gr_complex*) output_items[0];

        int samples_consumed = 0;
        int samples_produced = 0;

        while(ninput_items[0] - samples_consumed > 0 && noutput_items - samples_produced > d_len_subchirp + max_len_timegap)
        {
          volk_32fc_s32fc_multiply_32fc(out+samples_produced, &d_chirp_seq[d_len_subchirp*d_subchirp_ctr], std::polar(float(1.0),in[samples_consumed]), d_len_subchirp);
          samples_consumed++;
          samples_produced += d_len_subchirp;
          d_sym_ctr++;
          d_subchirp_ctr++;
          if(d_subchirp_ctr == 4)
          {
            if(d_chirp_seq_ctr == 0)
            {
              memcpy(out+samples_produced, &d_time_gap_1[0], sizeof(gr_complex)*d_time_gap_1.size());
              samples_produced += d_time_gap_1.size();
            }
            else
            {
              memcpy(out+samples_produced, &d_time_gap_2[0], sizeof(gr_complex)*d_time_gap_2.size());
              samples_produced += d_time_gap_2.size();
            }
            d_chirp_seq_ctr = (d_chirp_seq_ctr+1) % 2;
            d_subchirp_ctr = 0;
          }
          if(d_sym_ctr == d_nsym_frame) 
          {
            // std::cout << "DQCSK Mapper: EOF reached, reset" << std::endl;
            d_sym_ctr = 0;
            d_subchirp_ctr = 0;
            d_chirp_seq_ctr = 0;
          }
        }

        consume_each(samples_consumed);
        return samples_produced;  
    }

  } /* namespace ieee802_15_4 */
} /* namespace gr */

