/* -*- c++ -*- */
/*
 * @file
 * @author (C) 2014 by Piotr Krysik <ptrkrysik@gmail.com>
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
 */

#ifndef INCLUDED_GSM_CONTROLLED_ROTATOR_CC_IMPL_H
#define INCLUDED_GSM_CONTROLLED_ROTATOR_CC_IMPL_H

#include <grgsm/misc_utils/controlled_rotator_cc.h>
#include <gnuradio/blocks/rotator.h>

namespace gr {
  namespace gsm {

    class controlled_rotator_cc_impl : public controlled_rotator_cc
    {
     private:
      gr_complex d_phase_inc;
//      double d_samp_rate;
      blocks::rotator d_r;

     public:
      controlled_rotator_cc_impl(double phase_inc);
      ~controlled_rotator_cc_impl();

      virtual void set_phase_inc(double phase_inc);
//      virtual void set_samp_rate(double samp_rate);

      // Where all the action really happens
      int work(int noutput_items,
	       gr_vector_const_void_star &input_items,
	       gr_vector_void_star &output_items);
    };

  } // namespace gsm
} // namespace gr

#endif /* INCLUDED_GSM_CONTROLLED_ROTATOR_CC_IMPL_H */

