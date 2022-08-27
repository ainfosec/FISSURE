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

#ifndef INCLUDED_IRIDIUM_BURST_DOWNMIX_H
#define INCLUDED_IRIDIUM_BURST_DOWNMIX_H

#include <gnuradio/block.h>
#include <iridium/api.h>

namespace gr {
namespace iridium {

/*!
 * \brief <+description of block+>
 * \ingroup iridium
 *
 */
class IRIDIUM_API burst_downmix : virtual public gr::block
{
public:
    typedef std::shared_ptr<burst_downmix> sptr;

    /*!
     * \brief Return a shared_ptr to a new instance of iridium::burst_downmix.
     *
     * To avoid accidental use of raw pointers, iridium::burst_downmix's
     * constructor is in a private implementation
     * class. iridium::burst_downmix::make is the public interface for
     * creating new instances.
     */
    static sptr make(int output_sample_rate,
                     int search_depth,
                     size_t hard_max_queue_len,
                     const std::vector<float>& input_taps,
                     const std::vector<float>& start_finder_taps,
                     bool handle_multiple_frames_per_burst);

    virtual uint64_t get_n_dropped_bursts() = 0;
    virtual size_t get_input_queue_size() = 0;
    virtual void debug_id(uint64_t id) = 0;
};

} // namespace iridium
} // namespace gr

#endif /* INCLUDED_IRIDIUM_BURST_DOWNMIX_H */
