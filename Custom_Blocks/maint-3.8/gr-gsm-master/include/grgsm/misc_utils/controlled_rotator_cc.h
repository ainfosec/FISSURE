/* -*- c++ -*- */
/*
 * @file
 * @author (C) 2014-2016 by Piotr Krysik <ptrkrysik@gmail.com>
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


#ifndef INCLUDED_GSM_CONTROLLED_ROTATOR_CC_H
#define INCLUDED_GSM_CONTROLLED_ROTATOR_CC_H

#include <grgsm/api.h>
#include <gnuradio/sync_block.h>

namespace gr {
  namespace gsm {

    /*!
     * \brief <+description of block+>
     * \ingroup gsm
     *
     */
    class GRGSM_API controlled_rotator_cc : virtual public sync_block
    {
     public:
      typedef boost::shared_ptr<controlled_rotator_cc> sptr;

      /*!
       * \brief Return a shared_ptr to a new instance of gsm::controlled_rotator_cc.
       *
       * To avoid accidental use of raw pointers, gsm::controlled_rotator_cc's
       * constructor is in a private implementation
       * class. gsm::controlled_rotator_cc::make is the public interface for
       * creating new instances.
       */
      static sptr make(double phase_inc);
      
      virtual void set_phase_inc(double phase_inc) = 0;
//      virtual void set_samp_rate(double samp_rate) = 0;
    };

  } // namespace gsm
} // namespace gr

#endif /* INCLUDED_GSM_CONTROLLED_ROTATOR_CC_H */

