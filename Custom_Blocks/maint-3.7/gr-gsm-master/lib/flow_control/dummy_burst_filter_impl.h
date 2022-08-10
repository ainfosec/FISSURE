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

#ifndef INCLUDED_GSM_DUMMY_BURST_FILTER_IMPL_H
#define INCLUDED_GSM_DUMMY_BURST_FILTER_IMPL_H

#define DUMMY_BURST_LEN 148

#include <grgsm/flow_control/dummy_burst_filter.h>

namespace gr {
  namespace gsm {

    class dummy_burst_filter_impl : public dummy_burst_filter
    {
     private:
      bool is_dummy_burst(int8_t *burst, size_t burst_len);
      static const int8_t d_dummy_burst[];
      filter_policy d_filter_policy;
     public:
      dummy_burst_filter_impl();
      ~dummy_burst_filter_impl();
      void process_burst(pmt::pmt_t msg);

      /* External API */
      /* Filtering policy */
      filter_policy get_policy(void);
      filter_policy set_policy(filter_policy policy);
    };

  } // namespace gsm
} // namespace gr

#endif /* INCLUDED_GSM_DUMMY_BURST_FILTER_IMPL_H */

