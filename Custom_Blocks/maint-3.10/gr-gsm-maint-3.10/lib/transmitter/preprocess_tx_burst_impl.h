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

#ifndef INCLUDED_GSM_PREPROCESS_TX_BURST_IMPL_H
#define INCLUDED_GSM_PREPROCESS_TX_BURST_IMPL_H

#include <gsm/transmitter/preprocess_tx_burst.h>
#include <gsm/misc_utils/time_spec.h>
#include <gsm/misc_utils/fn_time.h>

namespace gr {
  namespace gsm {

    class preprocess_tx_burst_impl : public preprocess_tx_burst
    {
     private:
      void process_burst(pmt::pmt_t burst);
      
     public:
      preprocess_tx_burst_impl();
      ~preprocess_tx_burst_impl();
    };

  } // namespace gsm
} // namespace gr

#endif /* INCLUDED_GSM_PREPROCESS_TX_BURST_IMPL_H */

