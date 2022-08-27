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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <gsm/gsmtap.h>
#include <gsm/endian.h>
#include "tch_h_decoder_impl.h"
#include <iomanip>
extern "C" {
#include "osmocom/gsm/protocol/gsm_04_08.h"
#include "osmocom/coding/gsm0503_coding.h"
}

namespace gr {
    namespace gsm {

        static int ubits2sbits(ubit_t *ubits, sbit_t *sbits, int count)
        {
            int i;

            for (i = 0; i < count; i++) {
                if (*ubits == 0x23) {
                    ubits++;
                    sbits++;
                    continue;
                }
                if ((*ubits++) & 1)
                    *sbits++ = -127;
                else
                    *sbits++ = 127;
            }

            return count;
        }


        tch_h_decoder::sptr
        tch_h_decoder::make(unsigned int sub_channel, std::string multi_rate, bool boundary_check)
        {
            return gnuradio::get_initial_sptr
                (new tch_h_decoder_impl(sub_channel, multi_rate, boundary_check));
        }

        /*
         * Constructor
         */
        tch_h_decoder_impl::tch_h_decoder_impl(unsigned int sub_channel, std::string multi_rate, bool boundary_check)
            : gr::block("tch_h_decoder",
                    gr::io_signature::make(0, 0, 0),
                    gr::io_signature::make(0, 0, 0)),
            d_collected_bursts_num(0),
            d_tch_mode(TCH_HS),
            d_sub_channel(sub_channel),
            d_boundary_check(boundary_check),
            d_boundary_decode(false),
            d_header_sent(false),
            d_ft(0),
            d_cmr(0)
        {
            //setup input/output ports
            message_port_register_in(pmt::mp("bursts"));
            set_msg_handler(pmt::mp("bursts"), boost::bind(&tch_h_decoder_impl::decode, this, boost::placeholders::_1));
            message_port_register_out(pmt::mp("msgs"));
            message_port_register_out(pmt::mp("voice"));

            if(multi_rate.length())
            {
                std::cout<<"multi_rate configuration: "<<multi_rate<<std::endl;
                if (multi_rate.length() < 4 || multi_rate.length() % 2)
                {
                    throw std::invalid_argument("Invalid multi_rate hexstring");
                }

                std::vector<uint8_t> binary;
                for (std::string::const_iterator it = multi_rate.begin();
                        it != multi_rate.end(); it += 2)
                {
                    std::string byte(it, it + 2);
                    char* end = NULL;
                    errno = 0;
                    uint8_t b = strtoul(byte.c_str(), &end, 16);
                    if (errno != 0 || *end != '\0')
                    {
                        throw std::invalid_argument("Invalid multi_rate hexstring");
                    }
                    binary.push_back(b);
                }

                if (binary.size() < 2) {
                    throw std::invalid_argument("The multi_rate is too short");
                }

                //GSM A-I/F DTAP - Assignment Command
                //    Protocol Discriminator: Radio Resources Management messages (6)
                //    DTAP Radio Resources Management Message Type: Assignment Command (0x2e)
                //    Channel Description 2 - Description of the First Channel, after time
                //    Power Command
                //    Channel Mode - Mode of the First Channel(Channel Set 1)
                //    MultiRate configuration
                //        Element ID: 0x03
                //        Length: 4
                //        001. .... = Multirate speech version: Adaptive Multirate speech version 1 (1)
                //        ...0 .... = NSCB: Noise Suppression Control Bit: Noise Suppression can be used (default) (0)
                //        .... 1... = ICMI: Initial Codec Mode Indicator: The initial codec mode is defined by the Start Mode field (1)
                //        .... ..00 = Start Mode: 0
                //        0... .... = 12,2 kbit/s codec rate: is not part of the subset
                //        .0.. .... = 10,2 kbit/s codec rate: is not part of the subset
                //        ..0. .... = 7,95 kbit/s codec rate: is not part of the subset
                //        ...1 .... = 7,40 kbit/s codec rate: is part of the subset
                //        .... 0... = 6,70 kbit/s codec rate: is not part of the subset
                //        .... .0.. = 5,90 kbit/s codec rate: is not part of the subset
                //        .... ..0. = 5,15 kbit/s codec rate: is not part of the subset
                //        .... ...1 = 4,75 kbit/s codec rate: is part of the subset
                //        ..01 1010 = AMR Threshold: 13.0 dB (26)
                //        0100 .... = AMR Hysteresis: 2.0 dB (4)

                const uint8_t first = binary[0];
                uint8_t multirate_speech_ver = (first >> 5) & 0x07;
                if (multirate_speech_ver == 1)
                {
                    d_tch_mode = TCH_AFS4_75;
                }
                else if (multirate_speech_ver == 2)
                {
                    throw std::invalid_argument("Adaptive Multirate speech version 2 is not supported");
                }
                else
                {
                    throw std::invalid_argument("Multirate speech version");
                }

                bool ncsb = (first >> 4) & 0x01;
                bool icmi = (first >> 3) & 0x01;
                uint8_t start = first & 0x03;

                const uint8_t codecs = binary[1];
                for (int i = 0; i < 8; i++)
                {
                    if ((codecs >> i) & 1)
                    {
                        d_multi_rate_codes.push_back(i);
                    }
                }

                std::cout<<"Enabled AMR Codecs:"<<std::endl;
                for(std::vector<uint8_t>::const_iterator it = d_multi_rate_codes.begin();
                        it != d_multi_rate_codes.end();
                        it ++)
                {
                    switch(*it)
                    {
                        case 0:
                            std::cout<<"4,75 kbit/s codec rate: is part of the subset"<<std::endl;
                            break;
                        case 1:
                            std::cout<<"5,15 kbit/s codec rate: is part of the subset"<<std::endl;
                            break;
                        case 2:
                            std::cout<<"5,90 kbit/s codec rate: is part of the subset"<<std::endl;
                            break;
                        case 3:
                            std::cout<<"6,70 kbit/s codec rate: is part of the subset"<<std::endl;
                            break;
                        case 4:
                            std::cout<<"7,40 kbit/s codec rate: is part of the subset"<<std::endl;
                            break;
                        case 5:
                            std::cout<<"7,95 kbit/s codec rate: is part of the subset"<<std::endl;
                            break;
                        case 6:
                            std::cout<<"12,2 kbit/s codec rate: is part of the subset"<<std::endl;
                    }
                }
                if (d_multi_rate_codes.size() > 4) {
                    throw std::invalid_argument("More then 4 multirate codes");
                }
            }
        }

        tch_h_decoder_impl::~tch_h_decoder_impl()
        {
        }

        void tch_h_decoder_impl::decode(pmt::pmt_t msg)
        {
            d_bursts[d_collected_bursts_num++] = msg;
            if (d_collected_bursts_num <= 7)
            {
                return;
            }

            gsmtap_hdr* header = (gsmtap_hdr*)(pmt::blob_data(pmt::cdr(msg)));
            uint32_t frame_nr = be32toh(header->frame_number);
            bool uplink_burst = (be16toh(header->arfcn) & 0x4000) ? true : false;

            //TODO: Check in 3gpp specs which frames could contains facch/h frames
            //and replace this ugly formula with table
            int fn_is_odd = (((frame_nr - (uplink_burst ? 10 : 15)) % 26) >> 2) & 1;

            ubit_t bursts_u[116 * 6] = {0}; //facch/h is 6 bursts

            //reorganize data
            for (int ii = 0; ii < 8; ii++)
            {
                //skip the 4th and 5th bursts
                if (ii == 4 || ii == 5) continue;

                int8_t* burst_bits = (int8_t*)(pmt::blob_data(pmt::cdr(d_bursts[ii])))+sizeof(gsmtap_hdr);

                //copy 6th and 7th burst to 4th and 5th position
                int n = ii < 6 ? ii : ii - 2;

                memcpy(&bursts_u[n*116], &burst_bits[3],58);
                memcpy(&bursts_u[n*116+58], &burst_bits[3+57+1+26],58);
            }

            //Convert to sbits
            sbit_t bursts_s[116 * 6] = {0};
            ubits2sbits(bursts_u, bursts_s, 116 * 6);

            //Prepare burst for the next iteration by shifting them by 4
            for (int ii = 0; ii < 4; ii++) {
                d_bursts[ii] = d_bursts[ii + 4];
            }
            d_collected_bursts_num = 4;

            uint8_t frameBuffer[64];
            int frameLength = -1;
            int n_errors, n_bits_total;

            if (d_tch_mode == TCH_HS)
            {
                frameLength = gsm0503_tch_hr_decode(frameBuffer, bursts_s, fn_is_odd, &n_errors, &n_bits_total);
            }
            else
            {
                frameLength = gsm0503_tch_ahs_decode(frameBuffer, bursts_s, fn_is_odd,
                        fn_is_odd, //int codec_mode_req,
                        &d_multi_rate_codes.front(), d_multi_rate_codes.size(),
                        &d_ft,
                        &d_cmr,
                        &n_errors, &n_bits_total);
            }

            if (frameLength < 12)
            {
                #if 0
                if (!d_boundary_check || d_boundary_decode) {
                    std::cerr<<"Error! frame_nr:"<<frame_nr<<" mod26:"<<frame_nr%26
                        <<" fn_is_odd:"<<fn_is_odd<<" length:"<<frameLength<<std::endl;
                }
                #endif
                return;
            }
            else if (frameLength == GSM_MACBLOCK_LEN) //FACCH/H
            {
                pmt::pmt_t first_header_plus_burst = pmt::cdr(d_bursts[0]);
                gsmtap_hdr* header = (gsmtap_hdr *)pmt::blob_data(first_header_plus_burst);
                int8_t header_plus_data[sizeof(gsmtap_hdr)+frameLength];
                memcpy(header_plus_data, header, sizeof(gsmtap_hdr));
                memcpy(header_plus_data+sizeof(gsmtap_hdr), frameBuffer, frameLength);
                ((gsmtap_hdr*)header_plus_data)->type = GSMTAP_TYPE_UM;

                pmt::pmt_t msg_binary_blob = pmt::make_blob(header_plus_data, frameLength + sizeof(gsmtap_hdr));
                pmt::pmt_t msg_out = pmt::cons(pmt::PMT_NIL, msg_binary_blob);

                message_port_pub(pmt::mp("msgs"), msg_out);

                // if d_boundary_check is enabled, we set d_boundary_decode to true, when a
                // "Connect" or "Connect Acknowledge" message is received, and
                // we set d_boundary_decode back to false, when "Release" message is received
                if (d_boundary_check)
                {
                    // check if this is a call control message
                    if ((frameBuffer[3] & 0x0f) == 0x03)
                    {
                        // Alerting
                        if ((frameBuffer[4] & 0x3f) == 0x01)
                        {
                            if ((frameBuffer[5] == 0x1e) && //element id
                                    (frameBuffer[6] == 2) && //length
                                    ((frameBuffer[8] & 0x7f) == 0x08))
                            {
                                std::cout << "(CC) Alerting with In-band information" << std::endl;
                                //.000 1000 = Progress description: In-band information or appropriate pattern now available (8)
                                d_boundary_decode = true;
                            }
                        }
                        // Progress
                        else if ((frameBuffer[4] & 0x3f) == 0x03)
                        {
                            if ((frameBuffer[5] == 2) && //length
                                    (frameBuffer[7] & 0x7f) == 0x08)
                            {
                                std::cout << "(CC) Progress with In-band information" << std::endl;
                                //.000 1000 = Progress description: In-band information or appropriate pattern now available (8)
                                d_boundary_decode = true;
                            }
                        }
                        // Connect specified in GSM 04.08, 9.3.5
                        else if ((frameBuffer[4] & 0x3f) == 0x07)
                        {
                            std::cout << "(CC) Connect" << std::endl;
                            d_boundary_decode = true;
                        }
                        // Connect Acknowledge specified in GSM 04.08, 9.3.6
                        else if ((frameBuffer[4] & 0x3f) == 0x0f)
                        {
                            std::cout << "(CC) Connect Acknowledge" << std::endl;
                            d_boundary_decode = true;
                        }
                        // Release specified in GSM 04.08, 9.3.18
                        else if ((frameBuffer[4] & 0x3f) == 0x2d)
                        {
                            std::cout << "(CC) Release" << std::endl;
                            d_boundary_decode = false;
                        }
                    }
                }
                return;
            }

            if (!d_header_sent && d_tch_mode != TCH_HS)
            {
                const unsigned char amr_nb_magic[7] = "#!AMR\n";
                message_port_pub(pmt::mp("voice"), pmt::cons(pmt::PMT_NIL, pmt::make_blob(amr_nb_magic, 6)));
                d_header_sent = true;
            }

            if (!n_errors && (!d_boundary_check || d_boundary_decode))
            {
                //std::cerr<<"Voice frame_nr:"<<frame_nr<<" mod26:"<<frame_nr%26<<" is_odd:"<<fn_is_odd
                //    <<" type:"<<(uint32_t)d_ft<<" cmr:"<<(uint32_t)d_cmr
                //    <<" errors:"<<n_errors<<std::endl;

                if (d_tch_mode != TCH_HS)
                {
                    //Move one byte to make space for the header
                    memmove(frameBuffer + 1, frameBuffer, frameLength);
                    //Add the AMR header
                    switch(frameLength)
                    {
                        case 12: frameBuffer[0] = (0 << 3); break; //TCH/AHS4.75
                        case 13: frameBuffer[0] = (1 << 3); break; //TCH/AHS5.15
                        case 15: frameBuffer[0] = (2 << 3); break; //TCH/AHS5.9
                        case 17: frameBuffer[0] = (3 << 3); break; //TCH/AHS6.7
                        case 19: frameBuffer[0] = (4 << 3); break; //TCH/AHS7.4
                        case 20: frameBuffer[0] = (5 << 3); break; //TCH/AHS7.95
                        default: std::cerr<<"Unexpected voice frame length:"<<frameLength<<std::endl; return;
                    }
                    frameLength += 1;
                }

                //std::ostringstream out;
                //out << "voice frame: ";
                //for (int i = 0; i < frameLength; i++)
                //    out << " " << (std::hex) << std::setw(2) << std::setfill('0') << (uint32_t)*(frameBuffer + i);
                //std::cerr << out.str() << std::endl;
                message_port_pub(pmt::mp("voice"), pmt::cons(pmt::PMT_NIL, pmt::make_blob(frameBuffer, frameLength)));
            }
        }
    } /* namespace gsm */
} /* namespace gr */

