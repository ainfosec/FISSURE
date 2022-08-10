/* -*- c++ -*- */
/* @file
 * @author (C) 2015 by Pieter Robyns <pieter.robyns@uhasselt.be>
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

#ifndef INCLUDED_GSM_CX_CHANNEL_HOPPER_IMPL_H
#define INCLUDED_GSM_CX_CHANNEL_HOPPER_IMPL_H

#include <grgsm/receiver/cx_channel_hopper.h>
#include <vector>

namespace gr {
  namespace gsm {

    class cx_channel_hopper_impl : public cx_channel_hopper
    {
     private:
      std::vector<int> d_ma; // Mobile Allocation list. Contains all channels that are used while channel hopping
      int d_maio; // Mobile Allocation Index Offset
      int d_hsn; // Hopping Sequence Number
      int d_narfcn; // Length of d_ma

      int calculate_ma_sfh(int maio, int hsn, int n, int fn);
      void assemble_bursts(pmt::pmt_t msg);

     public:
      cx_channel_hopper_impl(const std::vector<int> &ma, int maio, int hsn);
      ~cx_channel_hopper_impl();
    };

  } // namespace gsm
} // namespace gr

#endif /* INCLUDED_GSM_CX_CHANNEL_HOPPER_IMPL_H */

