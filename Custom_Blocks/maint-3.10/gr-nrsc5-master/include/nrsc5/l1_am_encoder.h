/* -*- c++ -*- */
/*
 * Copyright 2019 Clayton Smith.
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef INCLUDED_NRSC5_L1_AM_ENCODER_H
#define INCLUDED_NRSC5_L1_AM_ENCODER_H

#include <gnuradio/block.h>
#include <nrsc5/api.h>

#define AM_BLOCKS_PER_FRAME 8
#define SYMBOLS_PER_BLOCK 32
#define AM_SYMBOLS_PER_FRAME (8 * 32)
#define AM_FFT_SIZE 256
#define SIS_BITS 80
#define DIVERSITY_DELAY (18000 * 3)

#define CONV_E1 1
#define CONV_E2 2
#define CONV_E3 3

namespace gr {
namespace nrsc5 {

/*!
 * \brief <+description of block+>
 * \ingroup nrsc5
 *
 */
class NRSC5_API l1_am_encoder : virtual public gr::block
{
public:
    typedef std::shared_ptr<l1_am_encoder> sptr;

    /*!
     * \brief Return a shared_ptr to a new instance of nrsc5::l1_am_encoder.
     *
     * To avoid accidental use of raw pointers, nrsc5::l1_am_encoder's
     * constructor is in a private implementation
     * class. nrsc5::l1_am_encoder::make is the public interface for
     * creating new instances.
     */
    static sptr make(const int sm);
};

} // namespace nrsc5
} // namespace gr

#endif /* INCLUDED_NRSC5_L1_AM_ENCODER_H */
