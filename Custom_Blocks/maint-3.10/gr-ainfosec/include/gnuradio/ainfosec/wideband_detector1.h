/* -*- c++ -*- */
/*
 * Copyright 2022 gr-ainfosec author.
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

#ifndef INCLUDED_AINFOSEC_WIDEBAND_DETECTOR1_H
#define INCLUDED_AINFOSEC_WIDEBAND_DETECTOR1_H

#include <gnuradio/ainfosec/api.h>
#include <gnuradio/sync_block.h>

namespace gr {
  namespace ainfosec {

    /*!
     * \brief <+description of block+>
     * \ingroup ainfosec
     *
     */
    class AINFOSEC_API wideband_detector1 : virtual public gr::sync_block
    {
     public:
      typedef std::shared_ptr<wideband_detector1> sptr;

      /*!
       * \brief Return a shared_ptr to a new instance of ainfosec::wideband_detector1.
       *
       * To avoid accidental use of raw pointers, ainfosec::wideband_detector1's
       * constructor is in a private implementation
       * class. ainfosec::wideband_detector1::make is the public interface for
       * creating new instances.
       */
      static sptr make(std::string address, float rx_freq, int fft_size, float sample_rate);
      virtual void set_address(std::string address) = 0;
      virtual void set_rx_freq(float rx_freq) = 0;
      virtual void set_fft_size(int fft_size) = 0;
      virtual void set_sample_rate(float sample_rate) = 0;
    };

  } // namespace ainfosec
} // namespace gr

#endif /* INCLUDED_AINFOSEC_WIDEBAND_DETECTOR1_H */

