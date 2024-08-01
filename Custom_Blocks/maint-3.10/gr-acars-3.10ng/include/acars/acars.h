/* -*- c++ -*- */
/*
 * Copyright 2022 gr-acars author.
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

#ifndef INCLUDED_ACARS_ACARS_H
#define INCLUDED_ACARS_ACARS_H

#include <gnuradio/sync_block.h>
#include <acars/api.h>

namespace gr {
namespace acars {

    /*!
     * \brief <+description of block+>
     * \ingroup acars
     *
     */
    class ACARS_API acars : virtual public gr::sync_block
    {
     public:
      typedef std::shared_ptr<acars> sptr;

      /*!
       * \brief Return a shared_ptr to a new instance of acars::acars.
       *
       * To avoid accidental use of raw pointers, acars::acars's
       * constructor is in a private implementation
       * class. acars::acars::make is the public interface for
       * creating new instances.
       */
      static sptr make(float seuil, std::string filename, bool saveall);
      virtual void set_seuil(float)=0;
    };

} // namespace acars
} // namespace gr

#endif /* INCLUDED_ACARS_ACARS_H */

