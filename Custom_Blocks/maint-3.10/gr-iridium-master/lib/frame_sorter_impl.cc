/* -*- c++ -*- */
/*
 * Copyright 2021 gr-iridium author.
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#include "frame_sorter_impl.h"
#include <gnuradio/io_signature.h>

namespace gr {
namespace iridium {

frame_sorter::sptr frame_sorter::make()
{
    return gnuradio::make_block_sptr<frame_sorter_impl>();
}


/*
 * The private constructor
 */
frame_sorter_impl::frame_sorter_impl()
    : gr::block("frame_sorter",
                gr::io_signature::make(0, 0, 0),
                gr::io_signature::make(0, 0, 0))
{
    message_port_register_out(pmt::mp("pdus"));
    auto port_name = pmt::mp("pdus");
    message_port_register_in(port_name);
    set_msg_handler(port_name, [this](const pmt::pmt_t& msg) { this->handler(msg); });
}

/*
 * Our virtual destructor.
 */
frame_sorter_impl::~frame_sorter_impl() {}

void frame_sorter_impl::handler(const pmt::pmt_t& msg)
{
    pmt::pmt_t symbols = pmt::cdr(msg);
    pmt::pmt_t meta = pmt::car(msg);

    frame f;

    f.timestamp = pmt::to_uint64(pmt::dict_ref(meta, pmt::mp("timestamp"), pmt::PMT_NIL));
    f.center_frequency =
        pmt::to_double(pmt::dict_ref(meta, pmt::mp("center_frequency"), pmt::PMT_NIL));


    auto it = frames.begin();

    while (it != frames.end()) {
        if (it->first.timestamp < f.timestamp - 2000000000) {
            message_port_pub(pmt::mp("pdus"), it->second);
            it = frames.erase(it);
        } else {
            break;
        }
    }

    it = frames.find(f);

    if (it == frames.end()) {
        frames.insert({ f, msg });
    } else {
        int confidence =
            pmt::to_long(pmt::dict_ref(meta, pmt::mp("confidence"), pmt::PMT_NIL));

        pmt::pmt_t meta_old = pmt::car(it->second);
        int confidence_old =
            pmt::to_long(pmt::dict_ref(meta_old, pmt::mp("confidence"), pmt::PMT_NIL));

        if (confidence > confidence_old) {
            // insert_or_assign with it2 as a hint would be nice but is C++17
            frames.erase(it);
            frames.insert({ f, msg });
        }
    }
}

bool frame_sorter_impl::stop()
{
    // Flush remaining messages
    auto it = frames.begin();
    while (it != frames.end()) {
        message_port_pub(pmt::mp("pdus"), it->second);
        it = frames.erase(it);
    }

    // Signal end of messages
    message_port_pub(pmt::mp("pdus"), pmt::PMT_EOF);
    return true;
}

} /* namespace iridium */
} /* namespace gr */
