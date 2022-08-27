/* -*- c++ -*- */
/*
 * @file
 * @author (C) 2018 by Vasil Velichkov <vvvelichkov@gmail.com>
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

#ifndef INCLUDED_GSM_TCH_H_DECODER_IMPL_H
#define INCLUDED_GSM_TCH_H_DECODER_IMPL_H

#include <gsm/decoding/tch_h_decoder.h>
#include "tch_f_decoder_impl.h"

namespace gr {
    namespace gsm {

        class tch_h_decoder_impl : public tch_h_decoder
        {
            private:
                unsigned int d_collected_bursts_num;
                pmt::pmt_t d_bursts[8];

                enum tch_mode d_tch_mode;
                unsigned int d_sub_channel;

                std::vector<uint8_t> d_multi_rate_codes;

                bool d_boundary_check;
                bool d_boundary_decode;
                bool d_header_sent;

                uint8_t d_ft;
                uint8_t d_cmr;

                void decode(pmt::pmt_t msg);
            public:
                tch_h_decoder_impl(unsigned int sub_channel, std::string multi_rate, bool boundary_check=false);
                ~tch_h_decoder_impl();
        };

    } // namespace gsm
} // namespace gr

#endif /* INCLUDED_GSM_TCH_H_DECODER_IMPL_H */

