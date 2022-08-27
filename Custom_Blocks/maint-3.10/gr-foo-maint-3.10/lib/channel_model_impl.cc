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

#include "channel_model_impl.h"
#include <gnuradio/io_signature.h>
#include <iostream>

namespace gr {
namespace foo {

channel_model::sptr
channel_model::make(double noise_voltage,
		    double frequency_offset,
		    double epsilon,
		    const std::vector<gr_complex> &taps,
		    double noise_seed,
		    bool block_tags)
{
    return gnuradio::get_initial_sptr
    (new channel_model_impl(noise_voltage,
			    frequency_offset,
			    epsilon,
			    taps,
			    noise_seed,
			    block_tags));
}

// Hierarchical block constructor
channel_model_impl::channel_model_impl(double noise_voltage,
					double frequency_offset,
					double epsilon,
					const std::vector<gr_complex> &taps,
					double noise_seed,
					bool block_tags
					)
    : hier_block2("channel_model",
		    io_signature::make(1, 1, sizeof(gr_complex)),
		    io_signature::make(1, 1, sizeof(gr_complex)))
{
    d_taps = taps;
    while(d_taps.size() < 2) {
    d_taps.push_back(0);
    }

    d_timing_offset = filter::mmse_resampler_cc::make(0, epsilon);

    d_multipath = filter::fir_filter_ccc::make(1, d_taps);

    d_noise_adder = blocks::add_cc::make();
    d_noise = analog::noise_source_c::make(analog::GR_GAUSSIAN,
						noise_voltage, noise_seed);
    d_freq_offset = analog::sig_source_c::make(1, analog::GR_SIN_WAVE,
						frequency_offset, 1.0, 0.0);
    d_mixer_offset = blocks::multiply_cc::make();

    connect(self(), 0, d_timing_offset, 0);
    connect(d_timing_offset, 0, d_multipath, 0);
    connect(d_multipath, 0, d_mixer_offset, 0);
    connect(d_freq_offset, 0, d_mixer_offset, 1);
    connect(d_mixer_offset, 0, d_noise_adder, 1);
    connect(d_noise, 0, d_noise_adder, 0);
    connect(d_noise_adder, 0, self(), 0);

    if (block_tags) {
    d_timing_offset->set_tag_propagation_policy(gr::block::TPP_DONT);
    }
}

channel_model_impl::~channel_model_impl()
{
}

void
channel_model_impl::set_noise_voltage(double noise_voltage)
{
    d_noise->set_amplitude(noise_voltage);
}

void
channel_model_impl::set_frequency_offset(double frequency_offset)
{
    d_freq_offset->set_frequency(frequency_offset);
}

void
channel_model_impl::set_taps(const std::vector<gr_complex> &taps)
{
    d_taps = taps;
    while(d_taps.size() < 2) {
    d_taps.push_back(0);
    }
    d_multipath->set_taps(d_taps);
}

void
channel_model_impl::set_timing_offset(double epsilon)
{
    d_timing_offset->set_resamp_ratio(epsilon);
}

double
channel_model_impl::noise_voltage() const
{
    return d_noise->amplitude();
}

double
channel_model_impl::frequency_offset() const
{
    return d_freq_offset->frequency();
}

std::vector<gr_complex>
channel_model_impl::taps() const
{
    return d_multipath->taps();
}

double
channel_model_impl::timing_offset() const
{
    return d_timing_offset->resamp_ratio();
}

} /* namespace channels */
} /* namespace gr */
