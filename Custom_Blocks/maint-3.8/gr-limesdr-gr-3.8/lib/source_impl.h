/* -*- c++ -*- */
/*
 * Copyright 2019 Lime Microsystems <info@limemicro.com>
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

#ifndef INCLUDED_LIMESDR_SOURCE_IMPL_H
#define INCLUDED_LIMESDR_SOURCE_IMPL_H

#include <limesdr/source.h>

#include "device_handler.h"

static const pmt::pmt_t TIME_TAG = pmt::string_to_symbol("rx_time");

namespace gr {
namespace limesdr {

class source_impl : public source
{
private:
    lms_stream_t streamId[2];

    bool stream_analyzer = false;

    int source_block = 1;

    bool add_tag = false;
    uint32_t pktLoss = 0;

    struct constant_data {
        std::string serial;
        int device_number;
        int channel_mode;
        double samp_rate = 10e6;
        uint32_t FIFO_size = 0;
        int align;
    } stored;

    std::chrono::high_resolution_clock::time_point t1, t2;

    void print_stream_stats(lms_stream_status_t status);

    void add_time_tag(int channel, lms_stream_meta_t meta);

public:
    source_impl(std::string serial,
                int channel_mode,
                const std::string& filename,
                bool align_ch_phase);
    ~source_impl();

    bool start(void);

    bool stop(void);

    // Where all the action really happens
    int work(int noutput_items,
             gr_vector_const_void_star& input_items,
             gr_vector_void_star& output_items);

    inline gr::io_signature::sptr args_to_io_signature(int channel_mode);

    void init_stream(int device_number, int channel);
    void release_stream(int device_number, lms_stream_t* stream);

    double set_center_freq(double freq, size_t chan = 0);

    void set_antenna(int antenna, int channel = 0);

    void set_nco(float nco_freq, int channel = 0);

    double set_bandwidth(double analog_bandw, int channel = 0);

    void set_digital_filter(double digital_bandw, int channel = 0);

    unsigned set_gain(unsigned gain_dB, int channel = 0);

    double set_sample_rate(double rate);

    void set_oversampling(int oversample);

    void set_buffer_size(uint32_t size);

    void calibrate(double bandw, int channel = 0);

    void set_tcxo_dac(uint16_t dacVal = 125);

    void write_lms_reg(uint32_t address, uint16_t val);
};

} // namespace limesdr
} // namespace gr

#endif /* INCLUDED_LIMESDR_SOURCE_IMPL_H */
