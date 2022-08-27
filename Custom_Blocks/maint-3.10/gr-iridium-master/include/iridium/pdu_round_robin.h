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

#ifndef INCLUDED_IRIDIUM_PDU_ROUND_ROBIN_H
#define INCLUDED_IRIDIUM_PDU_ROUND_ROBIN_H

#include <gnuradio/block.h>
#include <iridium/api.h>

namespace gr {
namespace iridium {

/*!
 * \brief <+description of block+>
 * \ingroup iridium
 *
 */
class IRIDIUM_API pdu_round_robin : virtual public gr::block
{
public:
    typedef std::shared_ptr<pdu_round_robin> sptr;

    /*!
     * \brief Return a shared_ptr to a new instance of iridium::pdu_round_robin.
     *
     * To avoid accidental use of raw pointers, iridium::pdu_round_robin's
     * constructor is in a private implementation
     * class. iridium::pdu_round_robin::make is the public interface for
     * creating new instances.
     */
    static sptr make(int output_count);
};

} // namespace iridium
} // namespace gr

#endif /* INCLUDED_IRIDIUM_PDU_ROUND_ROBIN_H */
