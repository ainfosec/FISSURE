/* -*- c++ -*- */
/* 
 * Copyright 2015 Ron Economos.
 * 
 * This is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3, or (at your option)
 * any later version.
 * 
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this software; see the file COPYING.  If not, write to
 * the Free Software Foundation, Inc., 51 Franklin Street,
 * Boston, MA 02110-1301, USA.
 */

#ifndef INCLUDED_PAINT_CONFIG_H
#define INCLUDED_PAINT_CONFIG_H

namespace gr {
  namespace paint {
    enum paint_random_t {
      INTERNAL = 0,
      EXTERNAL,
    };

    enum paint_equalization_t {
      EQUALIZATION_OFF = 0,
      EQUALIZATION_ON,
    };

  } // namespace paint
} // namespace gr

typedef gr::paint::paint_random_t paint_random_t;
typedef gr::paint::paint_equalization_t paint_equalization_t;

#endif /* INCLUDED_PAINT_CONFIG_H */

