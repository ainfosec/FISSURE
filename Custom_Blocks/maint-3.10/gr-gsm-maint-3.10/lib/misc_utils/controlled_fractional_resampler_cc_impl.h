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

#ifndef INCLUDED_GSM_CONTROLLED_FRACTIONAL_RESAMPLER_CC_IMPL_H
#define INCLUDED_GSM_CONTROLLED_FRACTIONAL_RESAMPLER_CC_IMPL_H

#include <gsm/misc_utils/controlled_fractional_resampler_cc.h>
#include <gnuradio/filter/mmse_fir_interpolator_cc.h>

using namespace gr::filter;

namespace gr {
  namespace gsm {

    class controlled_fractional_resampler_cc_impl : public controlled_fractional_resampler_cc
    {
    private:
      float d_mu;
      float d_mu_inc;
      mmse_fir_interpolator_cc *d_resamp;
      
      inline uint64_t resample(const gr_complex *in, 
           uint64_t first_in_sample, 
           gr_complex *out, 
           uint64_t first_out_sample, 
           uint64_t samples_to_produce);
                                               
    public:
      controlled_fractional_resampler_cc_impl(float phase_shift,
                                   float resamp_ratio);
      ~controlled_fractional_resampler_cc_impl();

      void forecast(int noutput_items,
		       gr_vector_int &ninput_items_required);

      int general_work(int noutput_items,
		       gr_vector_int &ninput_items,
		       gr_vector_const_void_star &input_items,
		       gr_vector_void_star &output_items);


      float mu() const;
      float resamp_ratio() const;
      void set_mu(float mu);
      void set_resamp_ratio(float resamp_ratio);
    };

  } // namespace gsm
} // namespace gr

#endif /* INCLUDED_GSM_CONTROLLED_FRACTIONAL_RESAMPLER_CC_IMPL_H */

