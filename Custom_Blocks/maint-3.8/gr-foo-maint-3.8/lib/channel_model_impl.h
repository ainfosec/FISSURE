/*
 * Copyright (C) 2017 Bastian Bloessl <mail@bastibl.net>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef INCLUDED_FOO_CHANNEL_MODEL_IMPL_H
#define INCLUDED_FOO_CHANNEL_MODEL_IMPL_H

#include <foo/channel_model.h>

#include <gnuradio/top_block.h>
#include <gnuradio/blocks/add_blk.h>
#include <gnuradio/blocks/multiply.h>
#include <gnuradio/analog/sig_source.h>
#include <gnuradio/analog/noise_source.h>
#include <gnuradio/filter/mmse_resampler_cc.h>
#include <gnuradio/filter/fir_filter_blk.h>

namespace gr {
namespace foo {

class FOO_API channel_model_impl : public foo::channel_model
{
private:
    blocks::add_cc::sptr d_noise_adder;
    blocks::multiply_cc::sptr d_mixer_offset;

    analog::sig_source_c::sptr d_freq_offset;
    analog::noise_source_c::sptr d_noise;

    filter::mmse_resampler_cc::sptr d_timing_offset;
    filter::fir_filter_ccc::sptr d_multipath;

    std::vector<gr_complex> d_taps;

public:
    channel_model_impl(double noise_voltage,
			double frequency_offset,
			double epsilon,
			const std::vector<gr_complex> &taps,
			double noise_seed,
			bool block_tags);

    ~channel_model_impl();

    void set_noise_voltage(double noise_voltage);
    void set_frequency_offset(double frequency_offset);
    void set_taps(const std::vector<gr_complex> &taps);
    void set_timing_offset(double epsilon);

    double noise_voltage() const;
    double frequency_offset() const;
    std::vector<gr_complex> taps() const;
    double timing_offset() const;
};

} // namespace foo
} // namespace gr

#endif /* INCLUDED_FOO_CHANNEL_MODEL_IMPL_H */
