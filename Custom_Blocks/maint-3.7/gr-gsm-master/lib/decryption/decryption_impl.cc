/* -*- c++ -*- */
/*
 * @file
 * @author (C) 2014 by Piotr Krysik <ptrkrysik@gmail.com>
 * @author (C) 2015 by Roman Khassraf <rkhassraf@gmail.com>
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <gnuradio/io_signature.h>
#include <grgsm/gsmtap.h>
#include <grgsm/endian.h>
#include <numeric>
#include "decryption_impl.h"

extern "C" {
    #include <osmocom/gsm/a5.h>
}

const uint32_t BURST_SIZE=148;

namespace gr {
  namespace gsm {

    decryption::sptr
    decryption::make(const std::vector<uint8_t> & k_c, unsigned int a5_version)
    {
      return gnuradio::get_initial_sptr
        (new decryption_impl(k_c, a5_version));
    }

    /*
     * The private constructor
     */
    decryption_impl::decryption_impl(const std::vector<uint8_t> & k_c, unsigned int a5_version)
      : gr::block("decryption",
              gr::io_signature::make(0, 0, 0),
              gr::io_signature::make(0, 0, 0)),
        d_k_c_valid(false)
    {
        set_k_c(k_c);
        set_a5_version(a5_version);
        validate_k_c();

        message_port_register_in(pmt::mp("bursts"));
        set_msg_handler(pmt::mp("bursts"), boost::bind(&decryption_impl::decrypt, this, _1));
        message_port_register_out(pmt::mp("bursts"));
    }

    /*
     * Virtual destructor
     */
    decryption_impl::~decryption_impl()
    {
    }

    void decryption_impl::set_k_c(const std::vector<uint8_t> & k_c)
    {
        d_k_c = k_c;
    }

    void decryption_impl::set_a5_version(unsigned int a5_version)
    {
        d_a5_version = 1;
        if (a5_version >= 1 && a5_version <= 4)
        {
            d_a5_version = a5_version;
        }
    }

    void decryption_impl::validate_k_c()
    {
        if (d_k_c.size() == 0)
        {
            d_k_c_valid = false;
            return;
        }
        else if ((d_a5_version < 4 && d_k_c.size() != 8) || (d_a5_version == 4 && d_k_c.size() != 16))
        {
            d_k_c_valid = false;
            return;
        }
        else
        {
            for (int i=0; i<d_k_c.size(); i++)
            {
                if (d_k_c[i] != 0)
                {
                    d_k_c_valid = true;
                    return;
                }
            }
        }
    }

    void decryption_impl::decrypt(pmt::pmt_t msg)
    {
        if (!d_k_c_valid)
        {
            message_port_pub(pmt::mp("bursts"), msg);
        }
        else
        {
            uint8_t decrypted_data[BURST_SIZE];
            uint8_t keystream[114];

            pmt::pmt_t header_plus_burst = pmt::cdr(msg);
            gsmtap_hdr * header = (gsmtap_hdr *)pmt::blob_data(header_plus_burst);
            uint8_t * burst_binary = (uint8_t *)(pmt::blob_data(header_plus_burst))+sizeof(gsmtap_hdr);

            uint32_t frame_number = be32toh(header->frame_number);
            bool uplink_burst = (be16toh(header->arfcn) & 0x4000) ? true : false;

            if(uplink_burst){
                //process uplink burst
                osmo_a5(d_a5_version, &d_k_c[0], frame_number, NULL, keystream);
            } else {
                //process downlink burst
                osmo_a5(d_a5_version, &d_k_c[0], frame_number, keystream, NULL);
            }
            /* guard bits */
            for (int i = 0; i < 3; i++) {
                decrypted_data[i] = burst_binary[i];
            }
            //decrypt first part of the burst
            for (int i = 0; i < 57; i++) {
                decrypted_data[i+3] = keystream[i] ^ burst_binary[i+3];
            }
            /* stealing bits and midamble */
            for (int i = 60; i < 88; i++) {
                decrypted_data[i] = burst_binary[i];
            }
            //decrypt second part of the burst
            for (int i = 0; i < 57; i++) {
                decrypted_data[i+88] = keystream[i+57] ^ burst_binary[i+88];
            }
            /* guard bits */
            for (int i = 145; i < 148; i++) {
                decrypted_data[i] = burst_binary[i];
            }
            uint8_t new_header_plus_burst[sizeof(gsmtap_hdr)+BURST_SIZE];
            memcpy(new_header_plus_burst, header, sizeof(gsmtap_hdr));
            memcpy(new_header_plus_burst+sizeof(gsmtap_hdr), decrypted_data, BURST_SIZE);

            pmt::pmt_t msg_binary_blob = pmt::make_blob(new_header_plus_burst, sizeof(gsmtap_hdr)+BURST_SIZE);
            pmt::pmt_t msg_out = pmt::cons(pmt::PMT_NIL, msg_binary_blob);

            message_port_pub(pmt::mp("bursts"), msg_out);
        }
        return;
    }
  } /* namespace gsm */
} /* namespace gr */
