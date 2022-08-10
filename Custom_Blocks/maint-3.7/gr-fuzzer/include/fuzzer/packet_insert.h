/* -*- c++ -*- */
/* 
 * Copyright 2016 <+YOU OR YOUR COMPANY+>.
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

#ifndef INCLUDED_FUZZER_PACKET_INSERT_H
#define INCLUDED_FUZZER_PACKET_INSERT_H

#include <fuzzer/api.h>
#include <gnuradio/block.h>

namespace gr {
  namespace fuzzer {

    /*!
     * \brief <+description of block+>
     * \ingroup fuzzer
     *
     */
    class FUZZER_API packet_insert : virtual public gr::block
    {
     public:
      typedef boost::shared_ptr<packet_insert> sptr;

      /*!
       * \brief Return a shared_ptr to a new instance of chris_fuzzer::packet_insert.
       *
       * To avoid accidental use of raw pointers, chris_fuzzer::packet_insert's
       * constructor is in a private implementation
       * class. chris_fuzzer::packet_insert::make is the public interface for
       * creating new instances.
       */
      //static sptr make();
      static sptr make(const std::vector<unsigned char> &data,
                       int periodicity, int offset=0);

      virtual void rewind() = 0;
      virtual void set_data(const std::vector<unsigned char> &data) = 0;
    };

  } // namespace fuzzer
} // namespace gr

#endif /* INCLUDED_FUZZER_PACKET_INSERT_H */
