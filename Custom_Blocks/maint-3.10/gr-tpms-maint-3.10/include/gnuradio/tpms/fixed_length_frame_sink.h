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

#ifndef INCLUDED_TPMS_FIXED_LENGTH_FRAME_SINK_H
#define INCLUDED_TPMS_FIXED_LENGTH_FRAME_SINK_H

#include <gnuradio/tpms/api.h>
#include <gnuradio/sync_block.h>
#include <pmt/pmt.h>

namespace gr {
  namespace tpms {

    /*!
     * \brief <+description of block+>
     * \ingroup tpms
     *
     */
    class TPMS_API fixed_length_frame_sink : virtual public gr::sync_block
    {
     public:
      typedef std::shared_ptr<fixed_length_frame_sink> sptr;

      /*!
       * \brief Return a shared_ptr to a new instance of tpms::fixed_length_frame_sink.
       *
       * To avoid accidental use of raw pointers, tpms::fixed_length_frame_sink's
       * constructor is in a private implementation
       * class. tpms::fixed_length_frame_sink::make is the public interface for
       * creating new instances.
       */
      static sptr make(int frame_length, pmt::pmt_t attributes);
    };

  } // namespace tpms
} // namespace gr

#endif /* INCLUDED_TPMS_FIXED_LENGTH_FRAME_SINK_H */

