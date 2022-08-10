/* -*- c++ -*- */
/*
 * @file
 * @author (C) 2016 by Roman Khassraf <rkhassraf@gmail.com>
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

#ifndef INCLUDED_GSM_EXTRACT_CMC_IMPL_H
#define INCLUDED_GSM_EXTRACT_CMC_IMPL_H

#include <grgsm/misc_utils/extract_cmc.h>
#include <vector>

namespace gr {
  namespace gsm {          
    class extract_cmc_impl : public extract_cmc
    {
     private:
      void process_messages(pmt::pmt_t msg);
      std::vector<int> d_framenumbers;
      std::vector<int> d_a5_versions;
      std::vector<int> d_start_ciphering;
     public:
      virtual std::vector<int> get_framenumbers();
      virtual std::vector<int> get_a5_versions();
      virtual std::vector<int> get_start_ciphering();
      extract_cmc_impl();
      ~extract_cmc_impl();
    };
  } // namespace gsm
} // namespace gr
#endif /* INCLUDED_GSM_EXTRACT_CMC_IMPL_H */
