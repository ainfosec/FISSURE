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


#ifndef INCLUDED_PAINT_PAINT_BC_H
#define INCLUDED_PAINT_PAINT_BC_H

#include <paint/api.h>
#include <paint/paint_config.h>
#include <gnuradio/block.h>

namespace gr {
  namespace paint {

    /*!
     * \brief <+description of block+>
     * \ingroup paint
     *
     */
    class PAINT_API paint_bc : virtual public gr::block
    {
     public:
      typedef std::shared_ptr<paint_bc> sptr;

      /*!
       * \brief Return a shared_ptr to a new instance of paint::paint_bc.
       *
       * To avoid accidental use of raw pointers, paint::paint_bc's
       * constructor is in a private implementation
       * class. paint::paint_bc::make is the public interface for
       * creating new instances.
       */
      static sptr make(int width, int repeats, int equalization, int randomsrc, int inputs);
    };

  } // namespace paint
} // namespace gr

#endif /* INCLUDED_PAINT_PAINT_BC_H */

