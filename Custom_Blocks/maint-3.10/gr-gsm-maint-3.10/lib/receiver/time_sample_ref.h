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

#ifndef INCLUDED_TIME_SAMPLE_REF_IMPL_H
#define INCLUDED_TIME_SAMPLE_REF_IMPL_H

#include <stdint.h>
#include <gsm/misc_utils/time_spec.h>

namespace gr {
  namespace gsm {
    /*
    Class for storing time reference and for conversions time<->sample number 
    */
    class time_sample_ref
    {
     private:
        double d_samp_rate;
        time_spec_t d_last_rx_time;
        uint64_t d_current_start_offset;
     public:
        time_sample_ref(double samp_rate);
        ~time_sample_ref();
        void update(time_spec_t last_rx_time, uint64_t current_start_offset);
        time_spec_t offset_to_time(uint64_t offset);
        uint64_t time_to_offset(time_spec_t time);
    };
  } // namespace gsm
} // namespace gr
#endif// INCLUDED_TIME_SAMPLE_REF_IMPL_H
