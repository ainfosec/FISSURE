/* -*- c++ -*- */
/*
 * @file
 * @author (C) 2018 by Andrew Artyushok <loony.developer@gmail.com>
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

#ifndef INCLUDED_GSM_TCH_H_CHANS_DEMAPPER_IMPL_H
#define INCLUDED_GSM_TCH_H_CHANS_DEMAPPER_IMPL_H

#include <gsm/demapping/tch_h_chans_demapper.h>

namespace gr {
    namespace gsm {

        class tch_h_chans_demapper_impl : public tch_h_chans_demapper
        {
            private:
                unsigned int d_timeslot;
                unsigned int d_tch_h_channel;

                // Downlink
                uint32_t d_frame_numbers_dl[3][8];       // for checking consecutive frame numbers of tch
                uint32_t d_frame_numbers_sacch_dl[4];    // for checking consecutive frame numbers of sacch
                pmt::pmt_t d_bursts_dl[3][8];            // for tch output headers+bursts
                pmt::pmt_t d_bursts_sacch_dl[4];         // for sacch output bursts

                // Uplink
                uint32_t d_frame_numbers_ul[3][8];       // for checking consecutive frame numbers of tch
                uint32_t d_frame_numbers_sacch_ul[4];    // for checking consecutive frame numbers of sacch
                pmt::pmt_t d_bursts_ul[3][8];            // for tch output headers+bursts
                pmt::pmt_t d_bursts_sacch_ul[4];         // for sacch output bursts

                void sacch_tch_demapper(uint32_t fn_mod13, u_int32_t fn_mod26, uint32_t frame_nr, pmt::pmt_t *d_bursts_sacch,
                        uint32_t *d_frame_numbers_sacch, pmt::pmt_t d_bursts[3][8],
                        uint32_t d_frame_numbers[3][8], pmt::pmt_t msg_out);

                void filter_tch_chans(pmt::pmt_t msg);

            public:
                tch_h_chans_demapper_impl(unsigned int timeslot_nr, unsigned int tch_h_channel);
                ~tch_h_chans_demapper_impl();
        };

    } // namespace gsm
} // namespace gr

#endif /* INCLUDED_GSM_TCH_H_CHANS_DEMAPPER_IMPL_H */

