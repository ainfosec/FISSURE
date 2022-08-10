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
#include "multiuser_chirp_detector_cc_impl.h"
#include <volk/volk.h>


namespace gr {
  namespace ieee802_15_4 {

    multiuser_chirp_detector_cc::sptr
    multiuser_chirp_detector_cc::make(std::vector<gr_complex> chirp_seq, int time_gap_1, int time_gap_2, int len_subchirp, float threshold)
    {
      return gnuradio::get_initial_sptr
        (new multiuser_chirp_detector_cc_impl(chirp_seq, time_gap_1, time_gap_2, len_subchirp, threshold));
    }

    /*
     * The private constructor
     */
    multiuser_chirp_detector_cc_impl::multiuser_chirp_detector_cc_impl(std::vector<gr_complex> chirp_seq, int time_gap_1, int time_gap_2, int len_subchirp, float threshold)
      : gr::block("multiuser_chirp_detector_cc",
              gr::io_signature::make(1, 1, sizeof(gr_complex)),
              gr::io_signature::make(1, 1, sizeof(gr_complex))),
      d_chirp_seq(chirp_seq),
      d_time_gap_1(time_gap_1),
      d_time_gap_2(time_gap_2),
      d_len_subchirp(len_subchirp),
      d_threshold(threshold)
    {
      if(d_chirp_seq.size() != NUM_SUBCHIRPS*d_len_subchirp)
        throw std::runtime_error("Chirp sequence has invalid length");

      // calculate energy per subchirp
      volk_32fc_x2_conjugate_dot_prod_32fc(&d_e_subchirp, &d_chirp_seq[0], &d_chirp_seq[0], d_len_subchirp);

      reset();
      set_output_multiple(d_len_subchirp);
    }

    /*
     * Our virtual destructor.
     */
    multiuser_chirp_detector_cc_impl::~multiuser_chirp_detector_cc_impl()
    {
    }

    void
    multiuser_chirp_detector_cc_impl::forecast (int noutput_items, gr_vector_int &ninput_items_required)
    {
      ninput_items_required[0] = required_input_items();
      dout << "forecast() requests at least " << required_input_items() << " input items" << std::endl;
    }

    void
    multiuser_chirp_detector_cc_impl::reset()
    {
      d_state = STATE_SEARCH;
      d_chirp_ctr = 0;
      d_subchirp_ctr = 0;
    }

    gr_complex
    multiuser_chirp_detector_cc_impl::correlate_current_subchirp(const gr_complex* buf)
    {
      gr_complex corrval = 0;
      volk_32fc_x2_conjugate_dot_prod_32fc(&corrval, buf, &d_chirp_seq[d_subchirp_ctr*d_len_subchirp], d_len_subchirp);
      gr_complex e_buf = 0;
      volk_32fc_x2_conjugate_dot_prod_32fc(&e_buf, buf, buf, d_len_subchirp);
      // dout << "correlation result:" << corrval << "/" << std::sqrt(e_buf*d_e_subchirp) << "=> norm = " << std::norm(corrval/(std::sqrt(e_buf*d_e_subchirp)+gr_complex(1e-6,0))) << std::endl;
      // normalize using standard deviations of both signals (assuming mean==0)
      // add 1e-6 to avoid divide-by-zero errors
      return corrval/(std::sqrt(e_buf*d_e_subchirp)+gr_complex(1e-6,0)); 
    }

    bool 
    multiuser_chirp_detector_cc_impl::corr_over_threshold(gr_complex corrval)
    {
      if(std::norm(corrval) > d_threshold)
        return true;
      else
        return false;
    }

    int 
    multiuser_chirp_detector_cc_impl::dist_to_next_subchirp()
    {
      d_subchirp_ctr++;

      int ret = d_len_subchirp;
      if(d_subchirp_ctr == NUM_SUBCHIRPS)
      {
        if(d_chirp_ctr == 0)
        {
          ret += d_time_gap_1;
          d_chirp_ctr++;
        }
        else
        {
          ret += d_time_gap_2;
          d_chirp_ctr = 0;
        }
        d_subchirp_ctr = 0;
        dout << "advance by " << ret << " samples" << std::endl;
      }
      dout << "next: chirp #" << d_chirp_ctr << ", subchirp #" << d_subchirp_ctr << std::endl;
      return ret;
    }

    int
    multiuser_chirp_detector_cc_impl::required_input_items()
    {
      int ret = 0;
      if(d_state == STATE_SEARCH)
        ret = d_len_subchirp;
      else if(d_state == STATE_TRACKING)
        return ret = d_len_subchirp + std::max(d_time_gap_1, d_time_gap_2);
      else
        throw std::runtime_error("Invalid state");
      return ret;
    }
    int
    multiuser_chirp_detector_cc_impl::general_work (int noutput_items,
                       gr_vector_int &ninput_items,
                       gr_vector_const_void_star &input_items,
                       gr_vector_void_star &output_items)
    {
        const gr_complex *in = (const gr_complex *) input_items[0];
        gr_complex *out = (gr_complex *) output_items[0];

        int available_samples = ninput_items[0];
        int samples_consumed = 0;
        int samples_produced = 0;

        while(available_samples >= required_input_items() && samples_produced < noutput_items)
        {
          if(d_state == STATE_SEARCH) // look for first subchirp of chosen chirp sequence
          {
            gr_complex sym = correlate_current_subchirp(in+samples_consumed);
            if(corr_over_threshold(sym))
            {
              dout << "#SEARCH# " << std::norm(sym) << ": chirp #" << d_subchirp_ctr << " detected" << std::endl;
              // std::cout << "Chirp detector: SEARCH->TRACKING at pos " << nitems_read(0) + samples_consumed << std::endl;
              d_state = STATE_TRACKING;
              samples_consumed += dist_to_next_subchirp();
              out[samples_produced] = sym;
              add_item_tag(0, nitems_written(0) + samples_produced, pmt::string_to_symbol("RESYNC"), pmt::from_long(0));
              // std::cout << "Chirp Detector: Resync after " << nitems_written(0) + samples_produced << " symbols" << std::endl;
              samples_produced++;
            }
            else
            {
              dout << "#SEARCH# " << std::norm(sym) << ": no symbol detected" << std::endl;
              dout << "#SEARCH# " << "advance by 1 sample" << std::endl;
              samples_consumed += 1;
            }
          }
          else if(d_state == STATE_TRACKING) // look for next subchirp at expected position
          {
            gr_complex sym = correlate_current_subchirp(in+samples_consumed);
            if(corr_over_threshold(sym))
            {
              dout << "#TRACK# " << std::norm(sym) << ": chirp #" << d_subchirp_ctr << " detected" << std::endl;
              samples_consumed += dist_to_next_subchirp();
              out[samples_produced] = sym;
              samples_produced++;
            }
            else
            {
              dout << "#TRACK# " << std::norm(sym) << ": no symbol detected at expected position - reset" << std::endl;
              samples_consumed += 1;
              dout << "#TRACK# " << "advance by 1 samples" << std::endl;
              // std::cout << "Chirp detector: TRACKING->SEARCH after " << nitems_written(0) + samples_produced << " symbols" << std::endl;
              reset();
            }
          }
          else
            throw std::runtime_error("Invalid state");
          available_samples -= samples_consumed;
        }
        
        dout << "consume: " << samples_consumed << "/" << ninput_items[0] << std::endl;
        dout << "produce: " << samples_produced << "/" << noutput_items << std::endl;
        consume_each (samples_consumed);
        return samples_produced;
    }

  } /* namespace ieee802_15_4 */
} /* namespace gr */

