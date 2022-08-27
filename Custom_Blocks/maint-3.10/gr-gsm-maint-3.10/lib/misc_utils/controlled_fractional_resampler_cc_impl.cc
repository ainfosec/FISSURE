/* -*- c++ -*- */
/* @file
 * @author (C) 2016 by Piotr Krysik <ptrkrysik@gmail.com>
 * @section LICENSE
 * 
 * Gr-gsm is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3, or (at your option)
 * any later version.
 * 
 * Gr-gsm is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with gr-gsm; see the file COPYING.  If not, write to
 * the Free Software Foundation, Inc., 51 Franklin Street,
 * Boston, MA 02110-1301, USA.
 * 
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <gnuradio/io_signature.h>
#include "controlled_fractional_resampler_cc_impl.h"
#include <stdexcept>

namespace gr {
  namespace gsm {

    controlled_fractional_resampler_cc::sptr
    controlled_fractional_resampler_cc::make(float phase_shift, float resamp_ratio)
    {
      return gnuradio::get_initial_sptr
        (new controlled_fractional_resampler_cc_impl(phase_shift, resamp_ratio));
    }

    controlled_fractional_resampler_cc_impl::controlled_fractional_resampler_cc_impl
                                     (float phase_shift, float resamp_ratio)
      : block("controlled_fractional_resampler_cc",
              io_signature::make(1, 1, sizeof(gr_complex)),
              io_signature::make(1, 1, sizeof(gr_complex))),
        d_mu(phase_shift), d_mu_inc(resamp_ratio),
        d_resamp(new mmse_fir_interpolator_cc())
    {
      this->set_tag_propagation_policy(TPP_DONT);
      if(resamp_ratio <=  0)
        throw std::out_of_range("resampling ratio must be > 0");
      if(phase_shift <  0  || phase_shift > 1)
        throw std::out_of_range("phase shift ratio must be > 0 and < 1");

      set_relative_rate(1.0 / resamp_ratio);
    }

    controlled_fractional_resampler_cc_impl::~controlled_fractional_resampler_cc_impl()
    {
      delete d_resamp;
    }

    void
    controlled_fractional_resampler_cc_impl::forecast(int noutput_items,
                                           gr_vector_int &ninput_items_required)
    {
      unsigned ninputs = ninput_items_required.size();
      for(unsigned i=0; i < ninputs; i++) {
        ninput_items_required[i] =
          (int)ceil((noutput_items * d_mu_inc) + d_resamp->ntaps());
      }
    }

    int
    controlled_fractional_resampler_cc_impl::general_work(int noutput_items,
                                               gr_vector_int &ninput_items,
                                               gr_vector_const_void_star &input_items,
                                               gr_vector_void_star &output_items)
    {
      const gr_complex *in = (const gr_complex*)input_items[0];
      gr_complex *out = (gr_complex*)output_items[0];
      
      uint64_t processed_in = 0; //input samples processed in the last call to resample function
      uint64_t processed_in_sum = 0; //input samples processed during a whole call to general_work function
      uint64_t produced_out_sum = 0; //output samples produced during a whole call to general_work function

      std::vector<tag_t> set_resamp_ratio_tags;

      pmt::pmt_t key = pmt::string_to_symbol("set_resamp_ratio");
      get_tags_in_window(set_resamp_ratio_tags, 0, 0, ninput_items[0]);
      
      bool all_output_samples_produced = false;
      for(std::vector<tag_t>::iterator i_tag = set_resamp_ratio_tags.begin(); i_tag < set_resamp_ratio_tags.end(); i_tag++)
      {
        uint64_t tag_offset_rel = i_tag->offset - nitems_read(0);
        
        if(pmt::symbol_to_string(i_tag->key) == "set_resamp_ratio")
        {
          uint64_t samples_to_produce = static_cast<uint64_t>(round(static_cast<double>(tag_offset_rel-processed_in_sum)/d_mu_inc)); //tu może być problem - bo to jest głupota przy d_mu_inc różnym od 1.0
          
          if( (samples_to_produce + produced_out_sum) > noutput_items)
          {
            samples_to_produce = noutput_items - produced_out_sum;
            all_output_samples_produced = true;
          }
          
          processed_in = resample(in, processed_in_sum, out, produced_out_sum, samples_to_produce);
          processed_in_sum = processed_in_sum + processed_in;
          produced_out_sum = produced_out_sum + samples_to_produce;

          if(all_output_samples_produced)
          {
            break;
          } else {
              add_item_tag(0, produced_out_sum + nitems_written(0), i_tag->key, i_tag->value);                       
              set_resamp_ratio(pmt::to_double(i_tag->value));
          }
        } else {
          uint64_t out_samples_to_tag = round(static_cast<double>(tag_offset_rel-processed_in_sum)/d_mu_inc);
          if( (out_samples_to_tag + produced_out_sum) <= noutput_items)
          {
            add_item_tag(0, produced_out_sum + out_samples_to_tag + nitems_written(0), i_tag->key, i_tag->value);
          }
        }
      }

      if(!all_output_samples_produced)
      {
        processed_in = resample(in, processed_in_sum, out, produced_out_sum, (noutput_items-produced_out_sum));
        processed_in_sum = processed_in_sum + processed_in;
      }
      
      consume_each(processed_in_sum);
      return noutput_items;
    }
    
    inline uint64_t 
    controlled_fractional_resampler_cc_impl::resample(const gr_complex *in, uint64_t first_in_sample, gr_complex *out, uint64_t first_out_sample, uint64_t samples_to_produce)
    {
      int ii = first_in_sample;
      int oo = first_out_sample;
      while(oo < (first_out_sample+samples_to_produce)) //produce samples_to_produce number of samples
      {
        out[oo++] = d_resamp->interpolate(&in[ii], d_mu);
      
        double s = d_mu + d_mu_inc;
        double f = floor(s);
        int incr = (int)f;
        d_mu = s - f;
        ii += incr;
      }
      return ii-first_in_sample; //number of input samples processed
    }

    float
    controlled_fractional_resampler_cc_impl::mu() const
    {
      return d_mu;
    }

    float
    controlled_fractional_resampler_cc_impl::resamp_ratio() const
    {
      return d_mu_inc;
    }

    void
    controlled_fractional_resampler_cc_impl::set_mu(float mu)
    {
      d_mu = mu;
    }

    void
    controlled_fractional_resampler_cc_impl::set_resamp_ratio(float resamp_ratio)
    {
      d_mu_inc = resamp_ratio;
      set_relative_rate(1.0 / resamp_ratio);
    }

  } /* namespace gsm */
} /* namespace gr */

