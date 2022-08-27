/* -*- c++ -*- */
/*
 * Copyright 2020 Free Software Foundation, Inc.
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

#ifndef INCLUDED_IRIDIUM_IUCHAR_TO_COMPLEX_H
#define INCLUDED_IRIDIUM_IUCHAR_TO_COMPLEX_H

#include <gnuradio/sync_decimator.h>
#include <iridium/api.h>

namespace gr {
namespace iridium {

/*!
 * \brief <+description of block+>
 * \ingroup iridium
 *
 */
class IRIDIUM_API iuchar_to_complex : virtual public gr::sync_decimator
{
public:
    typedef std::shared_ptr<iuchar_to_complex> sptr;

    /*!
     * \brief Return a shared_ptr to a new instance of iridium::iuchar_to_complex.
     *
     * To avoid accidental use of raw pointers, iridium::iuchar_to_complex's
     * constructor is in a private implementation
     * class. iridium::iuchar_to_complex::make is the public interface for
     * creating new instances.
     */
    static sptr make();
};

} // namespace iridium
} // namespace gr

#endif /* INCLUDED_IRIDIUM_IUCHAR_TO_COMPLEX_H */
