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

#ifndef INCLUDED_GSM_BURST_SINK_IMPL_H
#define INCLUDED_GSM_BURST_SINK_IMPL_H

#include <gsm/qa_utils/burst_sink.h>
#include <fstream>

namespace gr {
  namespace gsm {

    class burst_sink_impl : public burst_sink
    {
     private:
      std::vector<int> d_framenumbers;
      std::vector<int> d_timeslots;
      std::vector<std::string> d_burst_data;
      pmt::pmt_t d_bursts;
      std::vector<uint8_t> d_sub_types;
      std::vector<uint8_t> d_sub_slots;
     public:
      burst_sink_impl();
      ~burst_sink_impl();
      void process_burst(pmt::pmt_t msg);
      virtual std::vector<int> get_framenumbers();
      virtual std::vector<int> get_timeslots();
      virtual std::vector<std::string> get_burst_data();
      virtual pmt::pmt_t get_bursts();
      virtual std::vector<uint8_t> get_sub_types();
      virtual std::vector<uint8_t> get_sub_slots();
    };

  } // namespace gsm
} // namespace gr

#endif /* INCLUDED_GSM_BURST_SINK_IMPL_H */

