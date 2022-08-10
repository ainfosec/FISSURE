/* -*- c++ -*- */
/* @file
 * @author (C) 2015 by Roman Khassraf <rkhassraf@gmail.com>
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

#ifndef INCLUDED_GSM_BURST_SDCCH_SUBSLOT_SPLITTER_H
#define INCLUDED_GSM_BURST_SDCCH_SUBSLOT_SPLITTER_H

#include <grgsm/api.h>
#include <gnuradio/block.h>

namespace gr {
  namespace gsm {
      
    enum splitter_mode
    {
        SPLITTER_SDCCH8,
        SPLITTER_SDCCH4
    };

    /*!
     * \brief <+description of block+>
     * \ingroup gsm
     *
     */
    class GRGSM_API burst_sdcch_subslot_splitter : virtual public gr::block
    {
     public:
      typedef boost::shared_ptr<burst_sdcch_subslot_splitter> sptr;

      /*!
       * \brief Return a shared_ptr to a new instance of grgsm::burst_sdcch_subslot_splitter.
       *
       * To avoid accidental use of raw pointers, grgsm::burst_sdcch_subslot_splitter's
       * constructor is in a private implementation
       * class. grgsm::burst_sdcch_subslot_splitter::make is the public interface for
       * creating new instances.
       */
      static sptr make(splitter_mode mode);

      /* External API */
      virtual splitter_mode get_mode(void) = 0;
      virtual splitter_mode set_mode(splitter_mode mode) = 0;
    };
  } // namespace gsm
} // namespace gr

#endif /* INCLUDED_GSM_BURST_SDCCH_SUBSLOT_SPLITTER_H */
