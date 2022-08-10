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


#ifndef INCLUDED_GSM_BURSTS_PRINTER_H
#define INCLUDED_GSM_BURSTS_PRINTER_H

#include <grgsm/api.h>
#include <gnuradio/block.h>
#include <string>
#include <vector>

namespace gr {
  namespace gsm {

    /*!
     * \brief <+description of block+>
     * \ingroup gsm
     *
     */
    class GRGSM_API bursts_printer : virtual public gr::block
    {
     public:
      typedef boost::shared_ptr<bursts_printer> sptr;

      /*!
       * \brief Return a shared_ptr to a new instance of gsm::bursts_printer.
       *
       * To avoid accidental use of raw pointers, gsm::bursts_printer's
       * constructor is in a private implementation
       * class. gsm::bursts_printer::make is the public interface for
       * creating new instances.
       */
      static sptr make(pmt::pmt_t prepend_string, bool prepend_fnr=false,
        bool prepend_frame_count=false, bool print_payload_only=false,
        bool ignore_dummy_bursts=false);
    };

  } // namespace gsm
} // namespace gr

#endif /* INCLUDED_GSM_BURSTS_PRINTER_H */

