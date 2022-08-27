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

#ifndef INCLUDED_GSM_BURST_SINK_H
#define INCLUDED_GSM_BURST_SINK_H

#include <gsm/api.h>
#include <gnuradio/block.h>
#include <pmt/pmt.h>

namespace gr {
  namespace gsm {

    /*!
     * \brief <+description of block+>
     * \ingroup gsm
     *
     */
    class GSM_API burst_sink : virtual public gr::block
    {
     public:
      typedef std::shared_ptr<burst_sink> sptr;

      /*!
       * \brief Return a shared_ptr to a new instance of grgsm::burst_sink.
       *
       * To avoid accidental use of raw pointers, grgsm::burst_sink's
       * constructor is in a private implementation
       * class. grgsm::burst_sink::make is the public interface for
       * creating new instances.
       */
      static sptr make();

      virtual std::vector<int> get_framenumbers() = 0;
      virtual std::vector<int> get_timeslots() = 0;
      virtual std::vector<std::string> get_burst_data() = 0;
      virtual pmt::pmt_t get_bursts() = 0;      
      virtual std::vector<uint8_t> get_sub_types() = 0;
      virtual std::vector<uint8_t> get_sub_slots() = 0;
    };
  } // namespace gsm
} // namespace gr

#endif /* INCLUDED_GSM_BURST_SINK_H */

