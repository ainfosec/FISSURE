/* -*- c++ -*- */
/*
 * Copyright 2018 Lime Microsystems info@limemicro.com
 *
 * GNU Radio is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3, or (at your option)
 * any later version.
 *
 * GNU Radio is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GNU Radio; see the file COPYING.  If not, write to
 * the Free Software Foundation, Inc., 51 Franklin Street,
 * Boston, MA 02110-1301, USA.
 */

#ifndef INCLUDED_LIMESDR_SINK_IMPL_H
#define INCLUDED_LIMESDR_SINK_IMPL_H

#include "common/device_handler.h"
#include <limesdr/sink.h>


static const pmt::pmt_t TIME_TAG = pmt::string_to_symbol("tx_time");

namespace gr {
namespace limesdr {
class sink_impl : public sink {
    private:
    lms_stream_t streamId[2];

    bool stream_analyzer = false;

    int sink_block = 2;

    pmt::pmt_t LENGTH_TAG;
    lms_stream_meta_t tx_meta;
    long burst_length = 0;
    int nitems_send = 0;
    int ret[2] = {0};
    int pa_path[2] = {0}; // TX PA path NONE

    struct constant_data {
        std::string serial;
        int device_number;
        int channel_mode;
        double samp_rate = 10e6;
        uint32_t FIFO_size = 0;
    } stored;

    std::chrono::high_resolution_clock::time_point t1, t2;

    void work_tags(int noutput_items);

    void print_stream_stats(int channel);

    public:
    sink_impl(std::string serial,
              int channel_mode,
              const std::string& filename,
              const std::string& length_tag_name);
    ~sink_impl();

    int general_work(int noutput_items,
                     gr_vector_int& ninput_items,
                     gr_vector_const_void_star& input_items,
                     gr_vector_void_star& output_items);

    bool start(void);

    bool stop(void);

    inline gr::io_signature::sptr args_to_io_signature(int channel_number);

    void init_stream(int device_number, int channel);
    void release_stream(int device_number, lms_stream_t* stream);

    double set_center_freq(double freq, size_t chan = 0);
    
    void set_antenna(int antenna, int channel = 0);
    void toggle_pa_path(int device_number, bool enable);

    void set_nco(float nco_freq, int channel = 0);

    double set_bandwidth(double analog_bandw, int channel = 0);

    void set_digital_filter(double digital_bandw, int channel = 0);

    unsigned set_gain(unsigned gain_dB, int channel = 0);

    double set_sample_rate(double rate);

    void set_oversampling(int oversample);

    void set_buffer_size(uint32_t size);

    void calibrate(double bandw, int channel = 0);
    
    void set_tcxo_dac(uint16_t dacVal = 125);
};
} // namespace limesdr
} // namespace gr

#endif
