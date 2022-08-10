/* -*- c++ -*- */
/* 
 * Copyright 2014 Jared Boone <jared@sharebrained.com>.
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

#ifndef INCLUDED_TPMS_BURST_DETECTOR_H
#define INCLUDED_TPMS_BURST_DETECTOR_H

#include <tpms/api.h>
#include <gnuradio/block.h>

namespace gr {
  namespace tpms {

    /*!
     * \brief Identify and tag stream ranges that contain significant bursts of energy.
     * \ingroup tpms
     *
     */
    class TPMS_API burst_detector : virtual public gr::block
    {
     public:
      typedef boost::shared_ptr<burst_detector> sptr;

      /*!
       * \brief Return a shared_ptr to a new instance of tpms::burst_detector.
       *
       * To avoid accidental use of raw pointers, tpms::burst_detector's
       * constructor is in a private implementation
       * class. tpms::burst_detector::make is the public interface for
       * creating new instances.
       */
      static sptr make();
    };

  } // namespace tpms
} // namespace gr

#endif /* INCLUDED_TPMS_BURST_DETECTOR_H */

