/* -*- c++ -*- */
/*
 * Copyright 2021 gr-iridium author.
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef INCLUDED_IRIDIUM_FRAME_SORTER_CPP_IMPL_H
#define INCLUDED_IRIDIUM_FRAME_SORTER_CPP_IMPL_H

#include <iridium/frame_sorter.h>

namespace gr {
namespace iridium {

class frame
{
public:
    double timestamp;
    double center_frequency;

    friend bool operator<(const frame& l, const frame& r)
    {
        if (std::abs(l.timestamp - r.timestamp) < 1000000 &&
            std::abs(l.center_frequency - r.center_frequency) < 10000) {
            return false;
        }

        return std::tie(l.timestamp, l.center_frequency) <
               std::tie(r.timestamp, r.center_frequency);
    }
};


class frame_sorter_impl : public frame_sorter
{
private:
    std::map<frame, pmt::pmt_t> frames;

    void handler(const pmt::pmt_t& msg);


public:
    frame_sorter_impl();
    ~frame_sorter_impl();

    bool stop();

    // Where all the action really happens
    int work(int noutput_items,
             gr_vector_const_void_star& input_items,
             gr_vector_void_star& output_items);
};

} // namespace iridium
} // namespace gr

#endif /* INCLUDED_IRIDIUM_FRAME_SORTER_CPP_IMPL_H */
