/* -*- c++ -*- */
/*
 * Copyright 2017 Clayton Smith.
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef INCLUDED_NRSC5_HDC_ENCODER_H
#define INCLUDED_NRSC5_HDC_ENCODER_H

#include <gnuradio/block.h>
#include <nrsc5/api.h>

#define HDC_SAMPLE_RATE 44100
#define SAMPLES_PER_FRAME 2048

namespace gr {
namespace nrsc5 {

/*!
 * \brief <+description of block+>
 * \ingroup nrsc5
 *
 */
class NRSC5_API hdc_encoder : virtual public gr::block
{
public:
    typedef std::shared_ptr<hdc_encoder> sptr;

    /*!
     * \brief Return a shared_ptr to a new instance of nrsc5::hdc_encoder.
     *
     * To avoid accidental use of raw pointers, nrsc5::hdc_encoder's
     * constructor is in a private implementation
     * class. nrsc5::hdc_encoder::make is the public interface for
     * creating new instances.
     */
    static sptr make(int channels = 2, int bitrate = 64000);
};

} // namespace nrsc5
} // namespace gr

#endif /* INCLUDED_NRSC5_HDC_ENCODER_H */
