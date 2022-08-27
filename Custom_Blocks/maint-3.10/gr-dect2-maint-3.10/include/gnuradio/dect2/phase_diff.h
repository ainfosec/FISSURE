/* -*- c++ -*- */
/* 
 * Copyright 2014 <+YOU OR YOUR COMPANY+>.
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


#ifndef INCLUDED_DECT2_PHASE_DIFF_H
#define INCLUDED_DECT2_PHASE_DIFF_H

#include <gnuradio/dect2/api.h>
#include <gnuradio/sync_block.h>

namespace gr {
  namespace dect2 {

    /*!
     * \brief <+description of block+>
     * \ingroup dect2
     *
     */
    class DECT2_API phase_diff : virtual public gr::sync_block
    {
     public:
      typedef std::shared_ptr<phase_diff> sptr;

      /*!
       * \brief Return a shared_ptr to a new instance of dect2::phase_diff.
       *
       * To avoid accidental use of raw pointers, dect2::phase_diff's
       * constructor is in a private implementation
       * class. dect2::phase_diff::make is the public interface for
       * creating new instances.
       */
      static sptr make();
    };

  } // namespace dect2
} // namespace gr

#endif /* INCLUDED_DECT2_PHASE_DIFF_H */

