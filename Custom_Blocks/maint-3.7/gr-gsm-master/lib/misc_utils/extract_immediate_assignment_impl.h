/* -*- c++ -*- */
/*
 * @file
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
 */

#ifndef INCLUDED_GSM_EXTRACT_IMMEDIATE_ASSIGNMENT_IMPL_H
#define INCLUDED_GSM_EXTRACT_IMMEDIATE_ASSIGNMENT_IMPL_H

#include <grgsm/misc_utils/extract_immediate_assignment.h>
#include <map>
#include <vector>

namespace gr {
  namespace gsm {

    class immediate_assignment
    {
        public:
            uint32_t frame_nr;
            std::string channel_type;
            uint8_t timeslot;
            uint8_t subchannel;
            uint8_t hopping;
            uint8_t maio;
            uint8_t hsn;
            uint16_t arfcn;
            uint8_t timing_advance;
            std::string mobile_allocation;

            immediate_assignment() : frame_nr(0), channel_type("unknown"), timeslot(0), subchannel(0),
                hopping(false), maio(0), hsn(0), arfcn(0), timing_advance(0), mobile_allocation("") {};
            ~immediate_assignment() {};
    };

    typedef std::map<uint32_t, immediate_assignment> immediate_assignment_map;

    class extract_immediate_assignment_impl : public extract_immediate_assignment
    {
        private:
            void process_message(pmt::pmt_t msg);
            immediate_assignment_map d_assignment_map;
            bool d_print_immediate_assignments;
            bool d_ignore_gprs;
            bool d_unique_references;
        public:
            virtual std::vector<int> get_frame_numbers();
            virtual std::vector<std::string> get_channel_types();
            virtual std::vector<int> get_timeslots();
            virtual std::vector<int> get_subchannels();
            virtual std::vector<int> get_hopping();
            virtual std::vector<int> get_maios();
            virtual std::vector<int> get_hsns();
            virtual std::vector<int> get_arfcns();
            virtual std::vector<int> get_timing_advances();
            virtual std::vector<std::string> get_mobile_allocations();
            extract_immediate_assignment_impl(bool print_immediate_assignments=false,
                bool ignore_gprs=false, bool unique_references=false);
            ~extract_immediate_assignment_impl();
    };
  } // namespace gsm
} // namespace gr

#endif /* INCLUDED_GSM_EXTRACT_IMMEDIATE_ASSIGNMENT_IMPL_H */
