/* -*- c++ -*- */
/*
 * Copyright 2020 Free Software Foundation, Inc.
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

#ifndef INCLUDED_IRIDIUM_TAGGED_BURST_TO_PDU_IMPL_H
#define INCLUDED_IRIDIUM_TAGGED_BURST_TO_PDU_IMPL_H

#include <iridium/tagged_burst_to_pdu.h>

namespace gr {
  namespace iridium {

    struct burst_data {
        uint64_t id;
        double offset;
        float magnitude;
        float center_frequency;
        float sample_rate;
        uint64_t timestamp;
        float noise;
        size_t len;
        gr_complex * data;
        gr_complex phase_incr;
        gr_complex phase;
    };

    class tagged_burst_to_pdu_impl : public tagged_burst_to_pdu
    {
     private:
       bool d_debug;
       float d_relative_center_frequency;
       float d_relative_span;
       float d_relative_sample_rate;
       double d_sample_offset;
       int d_max_burst_size;
       int d_outstanding;
       int d_max_outstanding;
       int d_outstanding_limit;
       uint64_t d_n_dropped_bursts;
       bool d_drop_overflow;
       bool d_blocked;

       float d_lower_border;
       float d_upper_border;

       std::map<uint64_t, burst_data> d_bursts;

       void append_to_burst(burst_data &burst, const gr_complex * data, size_t n);
       void publish_burst(burst_data &burst);

       void create_new_bursts(int noutput_items,
                const gr_complex * in);
       void publish_and_remove_old_bursts(int noutput_items, const gr_complex * in);
       void update_current_bursts(int noutput_items, const gr_complex * in);

       int get_output_queue_size();
       int get_output_max_queue_size();
       void burst_handled(pmt::pmt_t msg);
     public:
      tagged_burst_to_pdu_impl(int max_burst_size, float relative_center_frequency,
                                float relative_span, float d_relative_sample_rate,
                                double sample_offset,
                                int outstanding_limit, bool drop_overflow);
      ~tagged_burst_to_pdu_impl();

      uint64_t get_n_dropped_bursts();

      // Where all the action really happens
      int work(int noutput_items,
         gr_vector_const_void_star &input_items,
         gr_vector_void_star &output_items);
    };

  } // namespace iridium
} // namespace gr

#endif /* INCLUDED_IRIDIUM_TAGGED_BURST_TO_PDU_IMPL_H */

