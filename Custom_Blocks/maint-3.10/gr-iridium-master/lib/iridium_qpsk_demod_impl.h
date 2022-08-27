/* -*- c++ -*- */
/*
 * Copyright 2020 gr-iridium author.
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

#ifndef INCLUDED_IRIDIUM_IRIDIUM_QPSK_DEMOD_CPP_IMPL_H
#define INCLUDED_IRIDIUM_IRIDIUM_QPSK_DEMOD_CPP_IMPL_H

#include <iridium/iridium_qpsk_demod.h>

namespace gr {
namespace iridium {

class iridium_qpsk_demod_impl : public iridium_qpsk_demod
{
private:
    size_t d_max_burst_size;
    float d_alpha;

    float* d_magnitude_f;
    gr_complex* d_burst_after_pll;
    gr_complex* d_decimated_burst;
    int* d_demodulated_burst;
    int d_symbol_mapping[4];
    uint64_t d_n_handled_bursts;
    uint64_t d_n_access_ok_bursts;
    uint64_t d_n_access_ok_sub_bursts;

    std::vector<uint8_t> d_bits;
    std::vector<uint64_t> d_channel_id;

    void handler(int channel, pmt::pmt_t msg);
    void update_buffer_sizes(size_t burst_size);
    int decimate(const gr_complex* in, int size, int sps, gr_complex* out);
    void qpskFirstOrderPLL(const gr_complex* x, int size, float alpha, gr_complex* y);
    size_t demod_qpsk(const gr_complex* burst,
                      size_t n_symbols,
                      int* out,
                      float* level,
                      int* confidence);
    bool check_sync_word(int* d_demodulated_burst,
                         size_t n_symbols,
                         ::iridium::direction direction);
    void decode_deqpsk(int* demodulated_burst, size_t n_symbols);
    void map_symbols_to_bits(const int* demodulated_burst,
                             size_t n_symbols,
                             std::vector<uint8_t>& bits);

public:
    iridium_qpsk_demod_impl(int n_channels);
    ~iridium_qpsk_demod_impl();

    uint64_t get_n_handled_bursts();
    uint64_t get_n_access_ok_bursts();
    uint64_t get_n_access_ok_sub_bursts();

    int work(int noutput_items,
             gr_vector_const_void_star& input_items,
             gr_vector_void_star& output_items);
};

} // namespace iridium
} // namespace gr

#endif /* INCLUDED_IRIDIUM_IRIDIUM_QPSK_DEMOD_CPP_IMPL_H */
