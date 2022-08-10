/* -*- c++ -*- */
/* 
 * Copyright 2016 Free Software Foundation, Inc
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


#ifndef INCLUDED_IRIDIUM_TOOLKIT_IRIDIUM_QPSK_DEMOD_CPP_H
#define INCLUDED_IRIDIUM_TOOLKIT_IRIDIUM_QPSK_DEMOD_CPP_H

#include <iridium/api.h>
#include <gnuradio/sync_block.h>

namespace gr {
  namespace iridium {

    /*!
     * \brief <+description of block+>
     * \ingroup iridium
     *
     */
    class IRIDIUM_TOOLKIT_API iridium_qpsk_demod_cpp : virtual public gr::sync_block
    {
     public:
      typedef boost::shared_ptr<iridium_qpsk_demod_cpp> sptr;

      /*!
       * \brief Return a shared_ptr to a new instance of iridium::iridium_qpsk_demod_cpp.
       *
       * To avoid accidental use of raw pointers, iridium::iridium_qpsk_demod_cpp's
       * constructor is in a private implementation
       * class. iridium::iridium_qpsk_demod_cpp::make is the public interface for
       * creating new instances.
       */
      static sptr make();

      virtual uint64_t get_n_handled_bursts() = 0;
      virtual uint64_t get_n_access_ok_bursts() = 0;
    };

  } // namespace iridium
} // namespace gr

#endif /* INCLUDED_IRIDIUM_TOOLKIT_IRIDIUM_QPSK_DEMOD_CPP_H */

