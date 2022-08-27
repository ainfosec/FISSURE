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

#ifndef INCLUDED_GSM_TXTIME_SETTER_IMPL_H
#define INCLUDED_GSM_TXTIME_SETTER_IMPL_H

#include <gsm/transmitter/txtime_setter.h>
#include <gsm/misc_utils/time_spec.h>
#include <gsm/misc_utils/fn_time.h>

namespace gr {
  namespace gsm {

    class txtime_setter_impl : public txtime_setter
    {
     private:
      uint32_t d_fn_ref;
      uint32_t d_ts_ref;
      time_format d_time_ref;
      time_format d_time_hint;
      double d_timing_advance;
      double d_delay_correction;

      void process_fn_time_reference(pmt::pmt_t msg);
      void process_txtime_of_burst(pmt::pmt_t msg);

     public:
      txtime_setter_impl(uint32_t init_fn, uint64_t init_time_secs,
        double init_time_fracs, uint64_t time_hint_secs,
        double time_hint_fracs, double timing_advance,
        double delay_correction);
      ~txtime_setter_impl();

      // Where all the action really happens
      void set_fn_time_reference(uint32_t fn, uint32_t ts,
        uint64_t time_secs, double time_fracs);
      void set_time_hint(uint64_t time_hint_secs, double time_hint_fracs);
      void set_delay_correction(double delay_correction);
      void set_timing_advance(double timing_advance);
    };

  } // namespace gsm
} // namespace gr

#endif /* INCLUDED_GSM_TXTIME_SETTER_IMPL_H */
