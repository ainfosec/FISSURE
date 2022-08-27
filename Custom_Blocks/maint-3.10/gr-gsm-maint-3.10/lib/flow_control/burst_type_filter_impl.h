/* -*- c++ -*- */
/* @file
 * @author (C) 2017 by Piotr Krysik <ptrkrysik@gmail.com>
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

#ifndef INCLUDED_GSM_BURST_TYPE_FILTER_IMPL_H
#define INCLUDED_GSM_BURST_TYPE_FILTER_IMPL_H

#define BURST_TYPE_LEN 148

#include <gsm/flow_control/burst_type_filter.h>

namespace gr {
  namespace gsm {

    class burst_type_filter_impl : public burst_type_filter
    {
     private:
      filter_policy d_filter_policy;
      std::vector<uint8_t> d_selected_burst_types;
     public:
      burst_type_filter_impl(const std::vector<uint8_t> & selected_burst_types);
      ~burst_type_filter_impl();
      void process_burst(pmt::pmt_t msg);

      /* External API */
      /* Filtering policy */
      filter_policy get_policy(void);
      filter_policy set_policy(filter_policy policy);
      
      void set_selected_burst_types(const std::vector<uint8_t> & selected_burst_types);
    };

  } // namespace gsm
} // namespace gr

#endif /* INCLUDED_GSM_BURST_TYPE_FILTER_IMPL_H */

