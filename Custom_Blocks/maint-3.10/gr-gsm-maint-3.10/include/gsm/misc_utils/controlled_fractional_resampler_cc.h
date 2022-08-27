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


#ifndef INCLUDED_GSM_CONTROLLED_FRACTIONAL_RESAMPLER_CC_H
#define INCLUDED_GSM_CONTROLLED_FRACTIONAL_RESAMPLER_CC_H

#include <gsm/api.h>
#include <gnuradio/block.h>
//#include <gnuradio/filter/fractional_resampler_cc.h>

namespace gr {
  namespace gsm {

    /*!
     * \brief <+description of block+>
     * \ingroup grgsm
     *
     */
    class GSM_API controlled_fractional_resampler_cc :  virtual public block
    {
     public:
      typedef std::shared_ptr<controlled_fractional_resampler_cc> sptr;

      /*!
       * \brief Return a shared_ptr to a new instance of grgsm::controlled_fractional_resampler_cc.
       *
       * To avoid accidental use of raw pointers, grgsm::controlled_fractional_resampler_cc's
       * constructor is in a private implementation
       * class. grgsm::controlled_fractional_resampler_cc::make is the public interface for
       * creating new instances.
       */
      static sptr make(float phase_shift, float resamp_ratio);
      
      virtual float mu() const = 0;
      virtual float resamp_ratio() const = 0;
      virtual void set_mu (float mu) = 0;
      virtual void set_resamp_ratio(float resamp_ratio) = 0;
    };

  } // namespace gsm
} // namespace gr

#endif /* INCLUDED_GSM_CONTROLLED_FRACTIONAL_RESAMPLER_CC_H */

