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

#ifndef INCLUDED_GSM_BURST_TIMESLOT_FILTER_IMPL_H
#define INCLUDED_GSM_BURST_TIMESLOT_FILTER_IMPL_H

#include <grgsm/flow_control/burst_timeslot_filter.h>

namespace gr {
  namespace gsm {

    class burst_timeslot_filter_impl : public burst_timeslot_filter
    {
     private:
      filter_policy d_filter_policy;
      unsigned int d_timeslot;
     public:
      burst_timeslot_filter_impl(unsigned int timeslot);
      ~burst_timeslot_filter_impl();
      void process_burst(pmt::pmt_t msg);

      /* External API */
      unsigned int get_tn(void);
      unsigned int set_tn(unsigned int tn);

      /* Filtering policy */
      filter_policy get_policy(void);
      filter_policy set_policy(filter_policy policy);
    };

  } // namespace gsm
} // namespace gr

#endif /* INCLUDED_GSM_BURST_TIMESLOT_FILTER_IMPL_H */

