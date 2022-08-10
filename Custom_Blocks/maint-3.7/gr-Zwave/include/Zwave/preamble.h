/* -*- c++ -*- */
/* 
 * Copyright 2013 Airbus DS CyberSecurity.
 * Authors: Jean-Michel Picod, Arnaud Lebrun, Jonathan Christofer Demay
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


#ifndef INCLUDED_ZWAVE_PREAMBLE_H
#define INCLUDED_ZWAVE_PREAMBLE_H

#include <Zwave/api.h>
#include <gnuradio/block.h>

namespace gr {
  namespace Zwave {

    /*!
     * \brief <+description of block+>
     * \ingroup Zwave
     *
     */
    class ZWAVE_API preamble : virtual public gr::block
    {
     public:
      typedef boost::shared_ptr<preamble> sptr;

      /*!
       * \brief Return a shared_ptr to a new instance of Zwave::preamble.
       *
       * To avoid accidental use of raw pointers, Zwave::preamble's
       * constructor is in a private implementation
       * class. Zwave::preamble::make is the public interface for
       * creating new instances.
       */
      static sptr make();
    };

  } // namespace Zwave
} // namespace gr

#endif /* INCLUDED_ZWAVE_PREAMBLE_H */

