/* -*- c++ -*- */
/* 
 * Copyright 2013 <+YOU OR YOUR COMPANY+>.
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


#ifndef INCLUDED_AIS_FREQEST_H
#define INCLUDED_AIS_FREQEST_H

#include <gnuradio/ais/api.h>
#include <gnuradio/sync_block.h>

namespace gr {
  namespace ais {

    /*!
     * \brief <+description of block+>
     * \ingroup ais
     *
     */
    class GR_AIS_API freqest : virtual public gr::sync_block
    {
     public:
      typedef std::shared_ptr<freqest> sptr;

      /*!
       * \brief Return a shared_ptr to a new instance of ais::freqest.
       *
       * To avoid accidental use of raw pointers, ais::freqest's
       * constructor is in a private implementation
       * class. ais::freqest::make is the public interface for
       * creating new instances.
       */
      static sptr make(float sample_rate, int data_rate, int fftlen);
    };

  } // namespace ais
} // namespace gr

#endif /* INCLUDED_AIS_FREQEST_H */

