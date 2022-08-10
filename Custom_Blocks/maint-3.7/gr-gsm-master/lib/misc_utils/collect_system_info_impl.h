/* -*- c++ -*- */
/*
 * @file
 * @author (C) 2017 by Roman Khassraf <rkhassraf@gmail.com>
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

#ifndef INCLUDED_GSM_COLLECT_SYSTEM_INFO_IMPL_H
#define INCLUDED_GSM_COLLECT_SYSTEM_INFO_IMPL_H

#include <grgsm/misc_utils/collect_system_info.h>
#include <vector>

namespace gr {
  namespace gsm {
    class collect_system_info_impl : public collect_system_info
    {
     private:
      void process_messages(pmt::pmt_t msg);
      std::vector<int> d_framenumbers;
      std::vector<std::string> d_sit_types;
      std::vector<std::string> d_sit_data;
      std::string get_hex_string(uint8_t * msg_elements);
     public:
      virtual std::vector<int> get_framenumbers();
      virtual std::vector<std::string> get_system_information_type();
      virtual std::vector<std::string> get_data();
      collect_system_info_impl();
      ~collect_system_info_impl();
    };
  } // namespace gsm
} // namespace gr

#endif /* INCLUDED_GSM_COLLECT_SYSTEM_INFO_IMPL_H */
