/* -*- c++ -*- */
/* @file
 * @author Piotr Krysik <ptrkrysik@gmail.com>
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

#ifndef INCLUDED_GSM_GEN_TEST_AB_IMPL_H
#define INCLUDED_GSM_GEN_TEST_AB_IMPL_H

#include <gsm/transmitter/gen_test_ab.h>
#include <gsm/misc_utils/time_spec.h>
#include <gsm/misc_utils/fn_time.h>

namespace gr {
  namespace gsm {

    class gen_test_ab_impl : public gen_test_ab
    {
     private:
      void generate_ab(pmt::pmt_t burst);
      
     public:
      gen_test_ab_impl();
      ~gen_test_ab_impl();
    };

  } // namespace gsm
} // namespace gr

#endif /* INCLUDED_GSM_GEN_TEST_AB_IMPL_H */

