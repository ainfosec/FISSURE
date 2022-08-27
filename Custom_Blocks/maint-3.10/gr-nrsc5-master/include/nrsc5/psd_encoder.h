/* -*- c++ -*- */
/*
 * Copyright 2017 Clayton Smith.
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef INCLUDED_NRSC5_PSD_ENCODER_H
#define INCLUDED_NRSC5_PSD_ENCODER_H

#include <gnuradio/sync_block.h>
#include <nrsc5/api.h>

#define BASIC_PACKET_FORMAT 0x21

namespace gr {
namespace nrsc5 {

/*!
 * \brief <+description of block+>
 * \ingroup nrsc5
 *
 */
class NRSC5_API psd_encoder : virtual public gr::sync_block
{
public:
    typedef std::shared_ptr<psd_encoder> sptr;

    /*!
     * \brief Return a shared_ptr to a new instance of nrsc5::psd_encoder.
     *
     * To avoid accidental use of raw pointers, nrsc5::psd_encoder's
     * constructor is in a private implementation
     * class. nrsc5::psd_encoder::make is the public interface for
     * creating new instances.
     */
    static sptr
    make(const int prog_num, const std::string& title, const std::string& artist);
};

} // namespace nrsc5
} // namespace gr

#endif /* INCLUDED_NRSC5_PSD_ENCODER_H */
