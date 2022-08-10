/* -*- c++ -*- */
/*
 * Copyright 2017 Clayton Smith.
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

#ifndef INCLUDED_NRSC5_L1_FM_ENCODER_H
#define INCLUDED_NRSC5_L1_FM_ENCODER_H

#include <nrsc5/api.h>
#include <gnuradio/block.h>

#define FM_BLOCKS_PER_FRAME 16
#define SYMBOLS_PER_BLOCK 32
#define FM_SYMBOLS_PER_FRAME (16 * 32)
#define FM_FFT_SIZE 2048
#define SIS_BITS 80
#define FM_P1_BITS 146176

#define CONV_1_3 1
#define CONV_2_5 2
#define CONV_1_2 3
#define CONV_2_7 4

namespace gr {
  namespace nrsc5 {

    /*!
     * \brief <+description of block+>
     * \ingroup nrsc5
     *
     */
    class NRSC5_API l1_fm_encoder : virtual public gr::block
    {
     public:
      typedef boost::shared_ptr<l1_fm_encoder> sptr;

      /*!
       * \brief Return a shared_ptr to a new instance of nrsc5::l1_fm_encoder.
       *
       * To avoid accidental use of raw pointers, nrsc5::l1_fm_encoder's
       * constructor is in a private implementation
       * class. nrsc5::l1_fm_encoder::make is the public interface for
       * creating new instances.
       */
      static sptr make(const int psm, const int ssm = 0);
    };

  } // namespace nrsc5
} // namespace gr

#endif /* INCLUDED_NRSC5_L1_FM_ENCODER_H */
