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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <gnuradio/io_signature.h>
#include <grgsm/gsmtap.h>
#include <grgsm/endian.h>
#include <boost/algorithm/clamp.hpp>
#include "cx_channel_hopper_impl.h"

namespace gr {
  namespace gsm {

    cx_channel_hopper::sptr
    cx_channel_hopper::make(const std::vector<int> &ma, int maio, int hsn)
    {
        return gnuradio::get_initial_sptr
          (new cx_channel_hopper_impl(ma, maio, hsn));
    }

    /*
     * The private constructor
     */
    cx_channel_hopper_impl::cx_channel_hopper_impl(const std::vector<int> &ma, int maio, int hsn)
        : gr::block("cx_channel_hopper",
                gr::io_signature::make(0, 0, 0),
                gr::io_signature::make(0, 0, 0)),
        d_ma(ma),
        d_maio(maio),
        d_hsn(hsn)
    {
        d_narfcn = ma.size();

        // Check user input for GSM 05.02, p16 compliance
        if(d_narfcn < 1 || d_narfcn > 64) {
            std::cerr << "warning: clamping number of RFCNs in the MA (" << d_narfcn << "), which should be 1 <= N <= 64." << std::endl;
            d_narfcn = boost::algorithm::clamp(d_narfcn, 1, 64);
            d_ma.resize(d_narfcn);
        }

        if(d_maio < 0 || d_maio >= d_narfcn) {
            std::cerr << "warning: clamping MAIO (" << d_maio << "), which should be 0 <= MAIO < N." << std::endl;
            d_maio = boost::algorithm::clamp(d_maio, 0, d_narfcn - 1);
        }

        if(d_hsn < 0 || d_hsn > 63) {
            std::cerr << "warning: clamping HSN (" << d_hsn << "), which should be 0 <= HSN < 64." << std::endl;
            d_hsn = boost::algorithm::clamp(d_hsn, 0, 63);
        }

        message_port_register_in(pmt::mp("CX"));
        set_msg_handler(pmt::mp("CX"), boost::bind(&cx_channel_hopper_impl::assemble_bursts, this, _1));
        message_port_register_out(pmt::mp("bursts"));
    }

    /*
     * Our virtual destructor.
     */
    cx_channel_hopper_impl::~cx_channel_hopper_impl()
    {
    }

    /**
     * Random number table used for calculating the
     * hopping sequence. Defined in GSM 05.02.
     */
    unsigned char RNTABLE[114] = {
        48, 98, 63, 1, 36, 95, 78, 102, 94, 73, \
        0, 64, 25, 81, 76, 59, 124, 23, 104, 100, \
        101, 47, 118, 85, 18, 56, 96, 86, 54, 2, \
        80, 34, 127, 13, 6, 89, 57, 103, 12, 74, \
        55, 111, 75, 38, 109, 71, 112, 29, 11, 88, \
        87, 19, 3, 68, 110, 26, 33, 31, 8, 45, \
        82, 58, 40, 107, 32, 5, 106, 92, 62, 67, \
        77, 108, 122, 37, 60, 66, 121, 42, 51, 126, \
        117, 114, 4, 90, 43, 52, 53, 113, 120, 72, \
        16, 49, 7, 79, 119, 61, 22, 84, 9, 97, \
        91, 15, 21, 24, 46, 39, 93, 105, 65, 70, \
        125, 99, 17, 123 \
    };

    /*
     * Slow Frequency Hopping (SFH) MAI calculation based
     * on airprobe-hopping by Bogdan Diaconescu.
     */
    int cx_channel_hopper_impl::calculate_ma_sfh(int maio, int hsn, int n, int fn)
    {
        int mai = 0;
        int s = 0;
        int nbin = floor(log2(n) + 1);
        int t1 = fn / 1326;
        int t2 = fn % 26;
        int t3 = fn % 51;

        if (hsn == 0)
            mai = (fn + maio) % n;
        else {
            int t1r = t1 % 64;
            int m = t2 + RNTABLE[(hsn ^ t1r) + t3];
            int mprim = m % (1 << nbin);
            int tprim = t3 % (1 << nbin);

            if (mprim < n)
                s = mprim;
            else
                s = (mprim + tprim) % n;

            mai = (s + maio) % n;
        }

        return (mai);
    }

    /**
     * Given MA, MAIO, HSN, and FN, decide which frames
     * to forward to the demapper.
     */
    void cx_channel_hopper_impl::assemble_bursts(pmt::pmt_t msg)
    {
        pmt::pmt_t header_plus_burst = pmt::cdr(msg);
        gsmtap_hdr *header = (gsmtap_hdr *)pmt::blob_data(header_plus_burst);

        uint32_t frame_nr = be32toh(header->frame_number);
        uint16_t frame_ca = be16toh(header->arfcn) & 0x3FFF;    //change highest bits to '0'
                                                                //in order to leave only ARFCN number

        int mai = calculate_ma_sfh(d_maio, d_hsn, d_narfcn, frame_nr);

        if(d_ma[mai] == (int)frame_ca) {
            message_port_pub(pmt::mp("bursts"), msg);
        }
    }

  } /* namespace gsm */
} /* namespace gr */
