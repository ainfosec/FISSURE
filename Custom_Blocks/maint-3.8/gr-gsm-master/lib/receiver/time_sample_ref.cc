/* -*- c++ -*- */
/*
 * @file
 * @author (C) 2017 by Piotr Krysik <ptrkrysik@gmail.com>
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

#include <math.h>
#include "time_sample_ref.h"

namespace gr {
  namespace gsm {
    time_sample_ref::time_sample_ref(double samp_rate): d_samp_rate(samp_rate)
    {
    }
    
    time_sample_ref::~time_sample_ref()
    {
    }
    
    void time_sample_ref::update(time_spec_t last_rx_time, uint64_t current_start_offset)
    {
        d_last_rx_time = last_rx_time;
        d_current_start_offset = current_start_offset;
    }
    
    time_spec_t time_sample_ref::offset_to_time(uint64_t offset)
    {
      uint64_t samples_from_last_rx_time = offset - d_current_start_offset;
      time_spec_t time = time_spec_t(static_cast<double>(samples_from_last_rx_time)/d_samp_rate) + d_last_rx_time;
      
      return time;
    }

    uint64_t time_sample_ref::time_to_offset(time_spec_t time)
    {
      double samples_since_last_rx_time_tag = (time-d_last_rx_time).get_real_secs()*d_samp_rate;
//      double fractional_part = round(samples_since_last_rx_time_tag) - samples_since_last_rx_time_tag;
      uint64_t offset = static_cast<uint64_t>(round(samples_since_last_rx_time_tag)) + d_current_start_offset;
      
      return offset;
    }
  } // namespace gsm
} // namespace gr

