/* -*- c++ -*- */
/*
 * Copyright 2017 Clayton Smith.
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef INCLUDED_NRSC5_SIS_ENCODER_IMPL_H
#define INCLUDED_NRSC5_SIS_ENCODER_IMPL_H

#include <nrsc5/sis_encoder.h>

namespace gr {
namespace nrsc5 {

class sis_encoder_impl : public sis_encoder
{
private:
    unsigned int alfn;
    std::string short_name;
    unsigned char* bit;

    int crc12(unsigned char* sis);
    void write_bit(int b);
    void write_int(int n, int len);
    void write_char5(char c);
    void write_station_name_short();

public:
    sis_encoder_impl(const std::string& short_name = "ABCD");
    ~sis_encoder_impl();

    // Where all the action really happens
    int work(int noutput_items,
             gr_vector_const_void_star& input_items,
             gr_vector_void_star& output_items);
};

} // namespace nrsc5
} // namespace gr

#endif /* INCLUDED_NRSC5_SIS_ENCODER_IMPL_H */
