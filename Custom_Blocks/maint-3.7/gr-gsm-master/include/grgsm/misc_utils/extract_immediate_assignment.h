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


#ifndef INCLUDED_GSM_EXTRACT_IMMEDIATE_ASSIGNMENT_H
#define INCLUDED_GSM_EXTRACT_IMMEDIATE_ASSIGNMENT_H

#include <grgsm/api.h>
#include <gnuradio/block.h>
#include <vector>

namespace gr {
  namespace gsm {
    /*!
     * \brief <+description of block+>
     * \ingroup gsm
     *
     */
    class GRGSM_API extract_immediate_assignment : virtual public gr::block
    {
     public:
      typedef boost::shared_ptr<extract_immediate_assignment> sptr;

      /*!
       * \brief Return a shared_ptr to a new instance of gsm::extract_immediate_assignment.
       *
       * To avoid accidental use of raw pointers, gsm::extract_immediate_assignment's
       * constructor is in a private implementation
       * class. gsm::extract_immediate_assignment::make is the public interface for
       * creating new instances.
       */
      static sptr make(bool print_immediate_assignments=false, bool ignore_gprs=false, bool unique_references=false);
      virtual std::vector<int> get_frame_numbers() = 0;
      virtual std::vector<std::string> get_channel_types() = 0;
      virtual std::vector<int> get_timeslots() = 0;
      virtual std::vector<int> get_subchannels() = 0;
      virtual std::vector<int> get_hopping() = 0;
      virtual std::vector<int> get_maios() = 0;
      virtual std::vector<int> get_hsns() = 0;
      virtual std::vector<int> get_arfcns() = 0;
      virtual std::vector<int> get_timing_advances() = 0;
      virtual std::vector<std::string> get_mobile_allocations() = 0;
    };
  } // namespace gsm
} // namespace gr

#endif /* INCLUDED_GSM_EXTRACT_IMMEDIATE_ASSIGNMENT_H */
