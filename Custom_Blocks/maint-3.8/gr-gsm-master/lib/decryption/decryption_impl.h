/* -*- c++ -*- */
/*
 * @file
 * @author (C) 2014 by Piotr Krysik <ptrkrysik@gmail.com>
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

#ifndef INCLUDED_GSM_DECRYPTION_IMPL_H
#define INCLUDED_GSM_DECRYPTION_IMPL_H

#include <grgsm/decryption/decryption.h>
#include <vector>

namespace gr {
  namespace gsm {

    class decryption_impl : public decryption
    {
     private:
      std::vector<uint8_t> d_k_c;
      bool d_k_c_valid;
      uint8_t d_a5_version;
      void decrypt(pmt::pmt_t msg);
      void validate_k_c();
     public:
      decryption_impl(const std::vector<uint8_t> & k_c, unsigned int a5_version);
      ~decryption_impl();
      virtual void set_k_c(const std::vector<uint8_t> & k_c);
      virtual void set_a5_version(unsigned int a5_version);
    };
  } // namespace gsm
} // namespace gr

#endif /* INCLUDED_GSM_DECRYPTION_IMPL_H */

