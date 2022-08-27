/* -*- c++ -*- */
/* @file
 * @author (C) 2016 by Piotr Krysik <ptrkrysik@gmail.com>
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
 * 
 */


#ifndef INCLUDED_GSM_UPLINK_DOWNLINK_SPLITTER_H
#define INCLUDED_GSM_UPLINK_DOWNLINK_SPLITTER_H

#include <gsm/api.h>
#include <gnuradio/block.h>

namespace gr {
  namespace gsm {

    /*!
     * \brief <+description of block+>
     * \ingroup grgsm
     *
     */
    class GSM_API uplink_downlink_splitter : virtual public gr::block
    {
     public:
      typedef std::shared_ptr<uplink_downlink_splitter> sptr;

      /*!
       * \brief Return a shared_ptr to a new instance of grgsm::uplink_downlink_splitter.
       *
       * To avoid accidental use of raw pointers, grgsm::uplink_downlink_splitter's
       * constructor is in a private implementation
       * class. grgsm::uplink_downlink_splitter::make is the public interface for
       * creating new instances.
       */
      static sptr make();
    };

  } // namespace gsm
} // namespace gr

#endif /* INCLUDED_GSM_UPLINK_DOWNLINK_SPLITTER_H */

