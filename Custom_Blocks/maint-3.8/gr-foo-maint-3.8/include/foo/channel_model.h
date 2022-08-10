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
#ifndef INCLUDED_FOO_CHANNEL_MODEL_H
#define INCLUDED_FOO_CHANNEL_MODEL_H

#include <foo/api.h>
#include <gnuradio/hier_block2.h>
#include <gnuradio/types.h>

namespace gr {
namespace foo {

class FOO_API channel_model : virtual public hier_block2
{
public:
    typedef boost::shared_ptr<channel_model> sptr;

    static sptr make(double noise_voltage = 0.0, double frequency_offset = 0.0,
            double epsilon = 1.0,
            const std::vector<gr_complex> &taps = std::vector<gr_complex>(1, 1),
            double noise_seed = 0, bool block_tags = false);

    virtual void set_noise_voltage(double noise_voltage) = 0;
    virtual void set_frequency_offset(double frequency_offset) = 0;
    virtual void set_taps(const std::vector<gr_complex> &taps) = 0;
    virtual void set_timing_offset(double epsilon) = 0;

    virtual double noise_voltage() const = 0;
    virtual double frequency_offset() const = 0;
    virtual std::vector<gr_complex> taps() const = 0;
    virtual double timing_offset() const = 0;
};

} // namespace foo
} // namespace gr

#endif /* INCLUDED_FOO_CHANNEL_MODEL_H */
