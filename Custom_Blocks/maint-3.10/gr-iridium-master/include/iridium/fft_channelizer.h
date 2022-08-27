/* -*- c++ -*- */
/*
 * Copyright 2022 gr-iridium author.
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef INCLUDED_IRIDIUM_FFT_CHANNELIZER_H
#define INCLUDED_IRIDIUM_FFT_CHANNELIZER_H

#include <gnuradio/sync_decimator.h>
#include <iridium/api.h>

namespace gr {
namespace iridium {

/*!
 * \brief <+description of block+>
 * \ingroup iridium
 *
 */
class IRIDIUM_API fft_channelizer : virtual public gr::sync_decimator
{
public:
    typedef std::shared_ptr<fft_channelizer> sptr;

    /*!
     * \brief Return a shared_ptr to a new instance of iridium::fft_channelizer.
     *
     * To avoid accidental use of raw pointers, iridium::fft_channelizer's
     * constructor is in a private implementation
     * class. iridium::fft_channelizer::make is the public interface for
     * creating new instances.
     */
    static sptr make(int fft_size,
                     int decimation,
                     bool activate_streams,
                     int pdu_ports,
                     int max_burst_size,
                     int outstanding_limit,
                     bool drop_overflow);

    virtual uint64_t get_n_dropped_bursts() = 0;
    virtual int get_output_queue_size() = 0;
    virtual int get_output_max_queue_size() = 0;
};
} // namespace iridium
} // namespace gr

#endif /* INCLUDED_IRIDIUM_FFT_CHANNELIZER_H */
