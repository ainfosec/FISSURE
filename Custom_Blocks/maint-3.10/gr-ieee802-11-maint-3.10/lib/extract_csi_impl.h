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

#ifndef INCLUDED_IEEE802_11_EXTRACT_CSI_IMPL_H
#define INCLUDED_IEEE802_11_EXTRACT_CSI_IMPL_H

#include <ieee802_11/extract_csi.h>

namespace gr {
namespace ieee802_11 {

class extract_csi_impl : public extract_csi
{
private:
    pmt::pmt_t d_meta;
    std::vector<gr_complex> d_csi;

public:
    extract_csi_impl();
    ~extract_csi_impl();

    int work(int noutput_items,
             gr_vector_const_void_star& input_items,
             gr_vector_void_star& output_items);
};

} // namespace ieee802_11
} // namespace gr

#endif /* INCLUDED_IEEE802_11_EXTRACT_CSI_IMPL_H */
