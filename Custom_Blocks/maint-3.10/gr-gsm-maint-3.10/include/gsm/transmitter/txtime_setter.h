/* -*- c++ -*- */
/* @file
 * @author Piotr Krysik <ptrkrysik@gmail.com>
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


#ifndef INCLUDED_GSM_TXTIME_SETTER_H
#define INCLUDED_GSM_TXTIME_SETTER_H

#include <gsm/api.h>
#include <gnuradio/block.h>

namespace gr {
  namespace gsm {

    /*!
     * \brief <+description of block+>
     * \ingroup gsm
     *
     */
    class GSM_API txtime_setter : virtual public gr::block
    {
     public:
      typedef std::shared_ptr<txtime_setter> sptr;

      /*!
       * \brief Return a shared_ptr to a new instance of gsm::txtime_setter.
       *
       * To avoid accidental use of raw pointers, gsm::txtime_setter's
       * constructor is in a private implementation
       * class. gsm::txtime_setter::make is the public interface for
       * creating new instances.
       */
      static sptr make(uint32_t init_fn, uint64_t init_time_secs, double init_time_fracs, uint64_t time_hint_secs, double time_hint_fracs, double timing_advance, double delay_correction);
      virtual void set_fn_time_reference(uint32_t fn, uint32_t ts, uint64_t time_secs, double time_fracs) = 0;
      virtual void set_time_hint(uint64_t time_hint_secs, double time_hint_fracs) = 0;
      virtual void set_delay_correction(double delay_correction) = 0;
      virtual void set_timing_advance(double timing_advance) = 0;
    };

  } // namespace gsm
} // namespace gr

#endif /* INCLUDED_GSM_TXTIME_SETTER_H */

