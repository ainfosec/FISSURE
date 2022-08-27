/* -*- c++ -*- */
/*
 * @file
 * @author (C) 2009-2017 by Piotr Krysik <ptrkrysik@gmail.com>
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
#ifndef INCLUDED_GSM_RECEIVER_CONFIG_H
#define INCLUDED_GSM_RECEIVER_CONFIG_H

#include <vector>
#include <algorithm>
#include <stdint.h>
#include <gsm/gsm_constants.h>

class multiframe_configuration
{
  private:
    multiframe_type d_type;
    std::vector<burst_type> d_burst_types;
  public:
    multiframe_configuration() {
      d_type = unknown;
      fill(d_burst_types.begin(), d_burst_types.end(), empty);
    }

    ~multiframe_configuration() {}

    void set_type(multiframe_type type) {
      if (type == multiframe_26) {
        d_burst_types.resize(26);
      } else {
        d_burst_types.resize(51);
      }

      d_type = type;
    }

    void set_burst_type(int nr, burst_type type) {
      d_burst_types[nr] = type;
    }

    multiframe_type get_type() {
      return d_type;
    }

    burst_type get_burst_type(int nr) {
      return d_burst_types[nr];
    }
};

class burst_counter
{
  private:
    const int d_OSR;
    uint32_t d_t1, d_t2, d_t3, d_timeslot_nr;
    double d_offset_fractional;
    double d_offset_integer;
  public:
    burst_counter(int osr):
        d_OSR(osr),
        d_t1(0),
        d_t2(0),
        d_t3(0),
        d_timeslot_nr(0),
        d_offset_fractional(0.0),
        d_offset_integer(0.0) {
    }

    burst_counter(int osr, uint32_t t1, uint32_t t2, uint32_t t3, uint32_t timeslot_nr):
        d_OSR(osr),
        d_t1(t1),
        d_t2(t2),
        d_t3(t3),
        d_timeslot_nr(timeslot_nr),
        d_offset_fractional(0.0),
        d_offset_integer(0.0) 
    {
      d_offset_integer = 0;
      d_offset_fractional = 0;
    }

    burst_counter & operator++(int);
    burst_counter subtract_timeslots(unsigned int number_of_timeslots);
    void set(uint32_t t1, uint32_t t2, uint32_t t3, uint32_t timeslot_nr);

    uint32_t get_t1() {
      return d_t1;
    }

    uint32_t get_t2() {
      return d_t2;
    }

    uint32_t get_t3() {
      return d_t3;
    }

    uint32_t get_timeslot_nr() {
      return d_timeslot_nr;
    }

    uint32_t get_frame_nr() {
      return (51 * 26 * d_t1) + (51 * (((d_t3 + 26) - d_t2) % 26)) + d_t3;
    }
    
    uint32_t get_frame_nr_mod() {
      return (d_t1 << 11) + (d_t3 << 5) + d_t2;
    }

    unsigned get_offset() {
      return (unsigned)d_offset_integer;
    }
};

class channel_configuration
{
  private:
    multiframe_configuration d_timeslots_descriptions[TS_PER_FRAME];
  public:
    channel_configuration() {
      for (int i = 0; i < TS_PER_FRAME; i++) {
        d_timeslots_descriptions[i].set_type(unknown);
      }
    }

    void set_multiframe_type(int timeslot_nr, multiframe_type type) {
      d_timeslots_descriptions[timeslot_nr].set_type(type);
    }

    void set_burst_types(int timeslot_nr, const unsigned mapping[], unsigned mapping_size, burst_type b_type) {
      unsigned i;
      for (i = 0; i < mapping_size; i++) {
        d_timeslots_descriptions[timeslot_nr].set_burst_type(mapping[i], b_type);
      }
    }

    void set_single_burst_type(int timeslot_nr, int burst_nr, burst_type b_type) {
      d_timeslots_descriptions[timeslot_nr].set_burst_type(burst_nr, b_type);
    }

    burst_type get_burst_type(burst_counter burst_nr);
};

#endif /* INCLUDED_GSM_RECEIVER_CONFIG_H */
