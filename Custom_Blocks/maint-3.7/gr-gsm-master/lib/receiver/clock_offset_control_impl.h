/* -*- c++ -*- */
/*
 * @file
 * @author (C) 2015-2017 by Piotr Krysik <ptrkrysik@gmail.com>
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

#ifndef INCLUDED_GSM_CLOCK_OFFSET_CONTROL_IMPL_H
#define INCLUDED_GSM_CLOCK_OFFSET_CONTROL_IMPL_H

#include <grgsm/receiver/clock_offset_control.h>
#include <string>

namespace gr {
  namespace gsm {
    class clock_offset_control_impl : public clock_offset_control
    {
     private:
        float d_fc;
        float d_samp_rate;
        unsigned int d_osr;
        float d_alfa;
        float d_ppm_estimate;
        float d_last_ppm_estimate;    
        bool  d_first_measurement;
        int   d_counter;
        std::string d_last_state;
        float d_current_time;
        float d_last_fcch_time;
        bool  d_first_time;
                        
        void process_measurement(pmt::pmt_t msg);
        void send_ctrl_messages(float freq_offset);
        void timed_reset();
        void reset();
     public:
       clock_offset_control_impl(float fc, float samp_rate, unsigned int osr);
      ~clock_offset_control_impl();

      virtual void set_fc(float fc);
      virtual void set_samp_rate(float samp_rate);
      virtual void set_osr(unsigned int osr);
    };
  } // namespace gsm
} // namespace gr

#endif /* INCLUDED_GSM_CLOCK_OFFSET_CONTROL_IMPL_H */

