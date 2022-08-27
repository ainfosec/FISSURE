/* -*- c++ -*- */
/*
 * Copyright 2021 Anton Ottosson.
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

#ifndef INCLUDED_IEEE802_11_EXTRACT_CSI_H
#define INCLUDED_IEEE802_11_EXTRACT_CSI_H

#include <gnuradio/sync_block.h>
#include <ieee802_11/api.h>

namespace gr {
namespace ieee802_11 {

class IEEE802_11_API extract_csi : virtual public gr::sync_block
{
public:
    typedef std::shared_ptr<extract_csi> sptr;
    static sptr make();
};

} // namespace ieee802_11
} // namespace gr

#endif /* INCLUDED_IEEE802_11_EXTRACT_CSI_H */
