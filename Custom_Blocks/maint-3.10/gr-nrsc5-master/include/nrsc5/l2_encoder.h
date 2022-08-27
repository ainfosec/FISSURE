/* -*- c++ -*- */
/*
 * Copyright 2017 Clayton Smith.
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef INCLUDED_NRSC5_L2_ENCODER_H
#define INCLUDED_NRSC5_L2_ENCODER_H

#include <gnuradio/block.h>
#include <nrsc5/api.h>

namespace gr {
namespace nrsc5 {

/*!
 * \brief <+description of block+>
 * \ingroup nrsc5
 *
 */
class NRSC5_API l2_encoder : virtual public gr::block
{
public:
    typedef std::shared_ptr<l2_encoder> sptr;

    /*!
     * \brief Return a shared_ptr to a new instance of nrsc5::l2_encoder.
     *
     * To avoid accidental use of raw pointers, nrsc5::l2_encoder's
     * constructor is in a private implementation
     * class. nrsc5::l2_encoder::make is the public interface for
     * creating new instances.
     */
    static sptr make(const int num_progs, const int first_prog, const int size);
};

} // namespace nrsc5
} // namespace gr

#endif /* INCLUDED_NRSC5_L2_ENCODER_H */
