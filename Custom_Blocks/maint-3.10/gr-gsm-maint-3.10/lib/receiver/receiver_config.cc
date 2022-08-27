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
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <cmath>
#include <receiver_config.h>


burst_counter & burst_counter::operator++(int)
{
  d_timeslot_nr++;
  if (d_timeslot_nr == TS_PER_FRAME) {
    d_timeslot_nr = 0;

    if ((d_t2 == 25) && (d_t3 == 50)) {
      d_t1 = (d_t1 + 1) % (1 << 11);
    }

    d_t2 = (d_t2 + 1) % 26;
    d_t3 = (d_t3 + 1) % 51;
  }

  //update offset - this is integer for d_OSR which is multiple of four
  d_offset_fractional += GUARD_FRACTIONAL * d_OSR;
  d_offset_integer = floor(d_offset_fractional);
  d_offset_fractional = d_offset_fractional - d_offset_integer;
  return (*this);
}

burst_counter burst_counter::subtract_timeslots(unsigned int number_of_timeslots)
{
  int timeslot_nr = (int)d_timeslot_nr - (int)number_of_timeslots;
  int t1,t2,t3;
  if (timeslot_nr < 0) {
    timeslot_nr = timeslot_nr + 8;

    t2 = (d_t2+26 - 1) % 26;
    t3 = (d_t3+51 - 1) % 51;

    if ((d_t2 == 0) && (d_t3 == 0)) {
      t1 = (d_t1 - 1) % (1 << 11);
    } else
    {
      t1 = d_t1;
    }
  }
  else
  {
    t1 = d_t1;
    t2 = d_t2;
    t3 = d_t3;
  }
  
  return burst_counter(d_OSR, t1, t2, t3, timeslot_nr);
}

void burst_counter::set(uint32_t t1, uint32_t t2, uint32_t t3, uint32_t timeslot_nr)
{
  d_t1 = t1;
  d_t2 = t2;
  d_t3 = t3;
  d_timeslot_nr = timeslot_nr;
  double first_sample_position = (get_frame_nr() * 8 + timeslot_nr) * TS_BITS;
  d_offset_fractional = first_sample_position - floor(first_sample_position);
  d_offset_integer = 0;
}

burst_type channel_configuration::get_burst_type(burst_counter burst_nr)
{
  uint32_t timeslot_nr = burst_nr.get_timeslot_nr();
  multiframe_type m_type = d_timeslots_descriptions[timeslot_nr].get_type();
  uint32_t nr;

  switch (m_type) {
    case multiframe_26:
      nr = burst_nr.get_t2();
      break;
    case multiframe_51:
      nr = burst_nr.get_t3();
      break;
    default:
      nr = 0;
      break;
  }

  return d_timeslots_descriptions[timeslot_nr].get_burst_type(nr);
}
