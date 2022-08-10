/* -*- c++ -*- */
/*
 * @file
 * @author (C) 2014 by Piotr Krysik <ptrkrysik@gmail.com>
 * @section LICENSE
 *
 * Gr-gsm is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3, or (at your option)
 * any later version.
 *
 * Gr-gsm is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with gr-gsm; see the file COPYING.  If not, write to
 * the Free Software Foundation, Inc., 51 Franklin Street,
 * Boston, MA 02110-1301, USA.
 */


#ifndef INCLUDED_GSM_CONTROL_CHANNELS_DECODER_H
#define INCLUDED_GSM_CONTROL_CHANNELS_DECODER_H

#include <grgsm/api.h>
#include <gnuradio/block.h>

namespace gr {
  namespace gsm {

    /*!
     * \brief <+description of block+>
     * \ingroup gsm
     *
     */
    class GRGSM_API control_channels_decoder : virtual public gr::block
    {
     public:
      typedef boost::shared_ptr<control_channels_decoder> sptr;

      /*!
       * \brief Return a shared_ptr to a new instance of gsm::control_channels_decoder.
       *
       * To avoid accidental use of raw pointers, gsm::control_channels_decoder's
       * constructor is in a private implementation
       * class. gsm::control_channels_decoder::make is the public interface for
       * creating new instances.
       */
      static sptr make();

    };

  } // namespace gsm
} // namespace gr

#endif /* INCLUDED_GSM_CONTROL_CHANNELS_DECODER_H */

