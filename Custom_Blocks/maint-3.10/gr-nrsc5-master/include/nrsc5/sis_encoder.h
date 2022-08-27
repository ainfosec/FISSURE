/* -*- c++ -*- */
/*
 * Copyright 2017 Clayton Smith.
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef INCLUDED_NRSC5_SIS_ENCODER_H
#define INCLUDED_NRSC5_SIS_ENCODER_H

#include <gnuradio/sync_block.h>
#include <nrsc5/api.h>

#define SIS_BITS 80
#define BLOCKS_PER_FRAME 16

/* 1020s.pdf Figure 4-1 */
#define PIDS_FORMATTED 0

#define NO_EXTENSION 0
#define EXTENDED_FORMAT 1

#define STATION_ID_NUMBER 0
#define STATION_NAME_SHORT 1
#define STATION_NAME_LONG 2
#define ALFN 3
#define STATION_LOCATION 4
#define STATION_MESSAGE 5
#define SERVICE_INFORMATION_MESSAGE 6
#define SIS_PARAMETER_MESSAGE 7
#define UNIVERSAL_SHORT_STATION_NAME 8
#define ACTIVE_RADIO_MESSAGE 9

#define TIME_NOT_LOCKED 0
#define TIME_LOCKED 1

#define EXTENSION_NONE 0
#define EXTENSION_FM 1

namespace gr {
namespace nrsc5 {

/*!
 * \brief <+description of block+>
 * \ingroup nrsc5
 *
 */
class NRSC5_API sis_encoder : virtual public gr::sync_block
{
public:
    typedef std::shared_ptr<sis_encoder> sptr;

    /*!
     * \brief Return a shared_ptr to a new instance of nrsc5::sis_encoder.
     *
     * To avoid accidental use of raw pointers, nrsc5::sis_encoder's
     * constructor is in a private implementation
     * class. nrsc5::sis_encoder::make is the public interface for
     * creating new instances.
     */
    static sptr make(const std::string& short_name = "ABCD");
};

} // namespace nrsc5
} // namespace gr

#endif /* INCLUDED_NRSC5_SIS_ENCODER_H */
