/* -*- c++ -*- */
/*
 * Copyright 2021 gr-iridium author.
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef INCLUDED_IRIDIUM_IRIDIUM_FRAME_PRINTER_CPP_IMPL_H
#define INCLUDED_IRIDIUM_IRIDIUM_FRAME_PRINTER_CPP_IMPL_H

#include <iridium/iridium_frame_printer.h>

namespace gr {
namespace iridium {

class iridium_frame_printer_impl : public iridium_frame_printer
{
private:
    std::string d_file_info;
    uint64_t d_t0;

    void handler(const pmt::pmt_t& msg);
    void handle_msg_sys(const pmt::pmt_t& msg);

public:
    iridium_frame_printer_impl(std::string file_info);
    ~iridium_frame_printer_impl();

    // Where all the action really happens
    int work(int noutput_items,
             gr_vector_const_void_star& input_items,
             gr_vector_void_star& output_items);
};

} // namespace iridium
} // namespace gr

#endif /* INCLUDED_IRIDIUM_IRIDIUM_FRAME_PRINTER_CPP_IMPL_H */
