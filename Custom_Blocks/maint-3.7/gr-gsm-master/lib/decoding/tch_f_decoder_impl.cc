/* -*- c++ -*- */
/*
 * @file
 * @author (C) 2015 by Roman Khassraf <rkhassraf@gmail.com>
 *         (C) 2017 by Piotr Krysik <ptrkrysik@gmail.com>
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
#include "stdio.h"
#include "tch_f_decoder_impl.h"

extern "C" {
    #include "osmocom/coding/gsm0503_coding.h"
}

#define DATA_BYTES 23

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

    tch_f_decoder::sptr
    tch_f_decoder::make(tch_mode mode, bool boundary_check)
    {
      return gnuradio::get_initial_sptr
        (new tch_f_decoder_impl(mode, boundary_check));
    }

    /*
     * Constructor
     */
    tch_f_decoder_impl::tch_f_decoder_impl(tch_mode mode, bool boundary_check)
      : gr::block("tch_f_decoder",
              gr::io_signature::make(0, 0, 0),
              gr::io_signature::make(0, 0, 0)),
      d_tch_mode(mode),
      d_collected_bursts_num(0),
      d_boundary_check(boundary_check),
      d_boundary_decode(!boundary_check),
      d_header_sent(false),
      mBlockCoder(0x10004820009ULL, 40, 224),
      mU(228),
      mP(mU.segment(184,40)),
      mD(mU.head(184)),
      mDP(mU.head(224)),
      mC(CONV_SIZE),
      mClass1_c(mC.head(378)),
      mClass2_c(mC.segment(378, 78)),
      mTCHU(189),
      mTCHD(260),
      mClass1A_d(mTCHD.head(50)),
      mTCHParity(0x0b, 3, 50)
    {
        //setup input/output ports
        message_port_register_in(pmt::mp("bursts"));
        set_msg_handler(pmt::mp("bursts"), boost::bind(&tch_f_decoder_impl::decode, this, _1));
        message_port_register_out(pmt::mp("msgs"));
        message_port_register_out(pmt::mp("voice"));    

        int j, k, B;
        for (k = 0; k < CONV_SIZE; k++)
        {
            B = k % 8;
            j = 2 * ((49 * k) % 57) + ((k % 8) / 4);
            interleave_trans[k] = B * 114 + j;
        }

        setCodingMode(mode);
    }

    tch_f_decoder_impl::~tch_f_decoder_impl()
    {
    }

    void tch_f_decoder_impl::decode(pmt::pmt_t msg)
    {
        if(!d_header_sent)
        {
            if (d_tch_mode != TCH_FS)
            {
                const unsigned char amr_nb_magic[7] = "#!AMR\n";
                message_port_pub(pmt::mp("voice"), pmt::cons(pmt::PMT_NIL, pmt::make_blob(amr_nb_magic,6)));
            }
            d_header_sent = true;
        }


        d_bursts[d_collected_bursts_num] = msg;
        d_collected_bursts_num++;
        
        bool stolen = false;

        if (d_collected_bursts_num == 8)
        {
        	ubit_t bursts_u[116 * 8];
            d_collected_bursts_num = 0;

            // reorganize data
            for (int ii = 0; ii < 8; ii++)
            {
                pmt::pmt_t header_plus_burst = pmt::cdr(d_bursts[ii]);
                int8_t * burst_bits = (int8_t *)(pmt::blob_data(header_plus_burst))+sizeof(gsmtap_hdr);

                memcpy(&bursts_u[ii*116], &burst_bits[3],58);
                memcpy(&bursts_u[ii*116+58], &burst_bits[3+57+1+26],58);

                for (int jj = 0; jj < 57; jj++)
                {
                    iBLOCK[ii*114+jj] = burst_bits[jj + 3];
                    iBLOCK[ii*114+jj+57] = burst_bits[jj + 88]; //88 = 3+57+1+26+1
                }

                if ((ii <= 3 && static_cast<int>(burst_bits[87]) == 1) || (ii >= 4 && static_cast<int>(burst_bits[60]) == 1))
                {
                    stolen = true;
                }
            }

            // deinterleave
            for (int k = 0; k < CONV_SIZE; k++)
            {
                mC[k] = iBLOCK[interleave_trans[k]];
            }

            // Decode stolen frames as FACCH/F
            if (stolen)
            {
                mVR204Coder.decode(mC, mU);
                mP.invert();

                unsigned syndrome = mBlockCoder.syndrome(mDP);

                if (syndrome == 0)
                {
                    unsigned char outmsg[28];
                    unsigned char sbuf_len=224;
                    int i, j, c, pos=0;
                    for(i = 0; i < sbuf_len; i += 8) {
                        for(j = 0, c = 0; (j < 8) && (i + j < sbuf_len); j++){
                            c |= (!!mU.bit(i + j)) << j;
                        }
                        outmsg[pos++] = c & 0xff;
                    }

                    pmt::pmt_t first_header_plus_burst = pmt::cdr(d_bursts[0]);
                    gsmtap_hdr * header = (gsmtap_hdr *)pmt::blob_data(first_header_plus_burst);
                    int8_t header_plus_data[sizeof(gsmtap_hdr)+DATA_BYTES];
                    memcpy(header_plus_data, header, sizeof(gsmtap_hdr));
                    memcpy(header_plus_data+sizeof(gsmtap_hdr), outmsg, DATA_BYTES);
                    ((gsmtap_hdr*)header_plus_data)->type = GSMTAP_TYPE_UM;

                    pmt::pmt_t msg_binary_blob = pmt::make_blob(header_plus_data,DATA_BYTES+sizeof(gsmtap_hdr));
                    pmt::pmt_t msg_out = pmt::cons(pmt::PMT_NIL, msg_binary_blob);

                    message_port_pub(pmt::mp("msgs"), msg_out);
                    
                    // if d_boundary_check is enabled, we set d_boundary_decode to true, when a 
                    // "Connect" or "Connect Acknowledge" message is received, and
                    // we set d_boundary_decode back to false, when "Release" message is received
                    if (d_boundary_check)
                    {
                        // check if this is a call control message
                        if ((outmsg[3] & 0x0f) == 0x03)
                        {
                            // Connect specified in GSM 04.08, 9.3.5
                            if ((outmsg[4] & 0x3f) == 0x07)
                            {
                                d_boundary_decode = true;
                            }
                            // Connect Acknowledge specified in GSM 04.08, 9.3.6
                            else if ((outmsg[4] & 0x3f) == 0x0f)
                            {
                                d_boundary_decode = true;
                            }
                            // Release specified in GSM 04.08, 9.3.18
                            else if ((outmsg[4] & 0x3f) == 0x2d)
                            {
                                d_boundary_decode = false;
                            }
                        }
                    }

                    // if we are in an AMR-mode and we receive a channel mode modify message,
                    // we set the mode according to the multirate configuration from the message
                    // see GSM 04.18, section 9.1.5 and 10.5.2.21aa
                    if (d_tch_mode  != TCH_FS && d_tch_mode != TCH_EFR)
                    {
                        if (outmsg[3] == 0x06 && outmsg[4] == 0x10)
                        {
                            // Verify that multirate version 1 is set
                            if ((outmsg[11] >> 5) == 1)
                            {
                                // the set of active codecs, max 4 modes
                                // active_codec_set[0] corresponds to CODEC_MODE_1 with lowest bit rate
                                // active_codec_set[3] corresponds to CODEC_MODE_4 with highest bit rate
                                tch_mode active_codec_set[4];
                                uint8_t mode_count = 0;
                                for (i = 0; i<8; i++)
                                {
                                    if (((outmsg[12] >> i) & 0x1) == 1 && mode_count < 4)
                                    {
                                        active_codec_set[mode_count++] = static_cast<tch_mode>(7-i);
                                    }
                                }

                                // check Initial Codec Mode Indicator ICMI
                                // if ICMI == 1, then use the one defined in start mode field
                                // else use implicit rule defined in GSM 05.09, section 3.4.3
                                if (((outmsg[11] >> 3) & 0x1) == 1)
                                {
                                    // from start field
                                    setCodingMode(active_codec_set[ (outmsg[11] & 0x3) ]);
                                }
                                else
                                {
                                    // implicit mode
                                    // if the set contains only 1 codec, we use that one
                                    // else if there are 2 or 3 codecs in the set, we use the one with lowest bitrate
                                    if (mode_count >= 1 && mode_count <= 3)
                                    {
                                        setCodingMode(active_codec_set[0]);
                                    }
                                    // if there are 4 codecs in the set, we use the second lowest bitrate
                                    else if (mode_count == 4)
                                    {
                                        setCodingMode(active_codec_set[1]);
                                    }
                                }
                            }
                        }
                    }
                }
            }
            
            // if voice boundary_check is enabled and d_boundary_decode is false, we are done
            if (d_boundary_check && !d_boundary_decode)
            {
                return;
            }

            // Decode voice frames and send to the output
            if (d_tch_mode == TCH_FS || d_tch_mode == TCH_EFR)
            {
                mVR204Coder.decode(mClass1_c, mTCHU);
                mClass2_c.sliced().copyToSegment(mTCHD, 182);

                // 3.1.2.1
                // copy class 1 bits u[] to d[]
                for (unsigned k = 0; k <= 90; k++) {
                  mTCHD[2*k] = mTCHU[k];
                  mTCHD[2*k+1] = mTCHU[184-k];
                }

                // 3.1.2.1
                // check parity of class 1A
                unsigned sentParity = (~mTCHU.peekField(91, 3)) & 0x07;
                unsigned calcParity = mClass1A_d.parity(mTCHParity) & 0x07;
                unsigned tail = mTCHU.peekField(185, 4);
                bool good = (sentParity == calcParity) && (tail == 0);

                if (good)
                {
                    uint8_t frameBuffer[33];
                    sbit_t bursts_s[116 * 8];
                    int n_errors, n_bits_total;
                    unsigned int  mTCHFrameLength;
                    ubits2sbits(bursts_u, bursts_s, 116 * 8);                    

                    if (d_tch_mode == TCH_FS) // GSM-FR
                    {
                        mTCHFrameLength = 33;
                        gsm0503_tch_fr_decode(frameBuffer, bursts_s, 1, 0, &n_errors, &n_bits_total);
                        //std::cout << "Errors: " << n_errors << std::endl;
                    }
                    else if (d_tch_mode == TCH_EFR) // GSM-EFR
                    {
                        unsigned char mFrameHeader = 0x3c;

                        // AMR Frame, consisting of a 8 bit frame header, plus the payload from decoding
                        BitVector amrFrame(244 + 8); // Same output length as AMR 12.2
                        BitVector payload = amrFrame.tail(8);

                        BitVector TCHW(260), EFRBits(244);

                        // write frame header
                        amrFrame.fillField(0, mFrameHeader, 8);

                        // Undo Um's EFR bit ordering.
                        mTCHD.unmap(GSM::g660BitOrder, 260, TCHW);

                        // Remove repeating bits and CRC to get raw EFR frame (244 bits)
                        for (unsigned k=0; k<71; k++)
                          EFRBits[k] = TCHW[k] & 1;

                        for (unsigned k=73; k<123; k++)
                          EFRBits[k-2] = TCHW[k] & 1;

                        for (unsigned k=125; k<178; k++)
                          EFRBits[k-4] = TCHW[k] & 1;

                        for (unsigned k=180; k<230; k++)
                          EFRBits[k-6] = TCHW[k] & 1;

                        for (unsigned k=232; k<252; k++)
                          EFRBits[k-8] = TCHW[k] & 1;

                        // Map bits as AMR 12.2k
                        EFRBits.map(GSM::gAMRBitOrderTCH_AFS12_2, 244, payload);

                        // Put the whole frame (hdr + payload)
                        mTCHFrameLength = 32;
                        amrFrame.pack(frameBuffer);
                        //when itegrating with libosmocore lines above can be removed and line below uncommented, efr decoding with libosmocore need to be tested however
                        //gsm0503_tch_fr_decode(frameBuffer, bursts_s, 1, 1, &n_errors, &n_bits_total);
                    }
                    message_port_pub(pmt::mp("voice"), pmt::cons(pmt::PMT_NIL, pmt::make_blob(frameBuffer,mTCHFrameLength)));
                }
            }
            else
            {
                // Handle inband bits, see 3.9.4.1
                // OpenBTS source takes last 8 bits as inband bits for some reason. This may be either a
                // divergence between their implementation and GSM specification, which works because
                // both their encoder and decoder do it same way, or they handle the issue at some other place
                // SoftVector cMinus8 = mC.segment(0, mC.size() - 8);
                SoftVector cMinus8 = mC.segment(8, mC.size());
                cMinus8.copyUnPunctured(mTCHUC, mPuncture, mPunctureLth);

                // 3.9.4.4
                // decode from uc[] to u[]
                mViterbi->decode(mTCHUC, mTCHU);

                // 3.9.4.3 -- class 1a bits in u[] to d[]
                for (unsigned k=0; k < mClass1ALth; k++) {
                    mTCHD[k] = mTCHU[k];
                }

                // 3.9.4.3 -- class 1b bits in u[] to d[]
                for (unsigned k=0; k < mClass1BLth; k++) {
                    mTCHD[k+mClass1ALth] = mTCHU[k+mClass1ALth+6];
                }

                // Check parity
                unsigned sentParity = (~mTCHU.peekField(mClass1ALth,6)) & 0x3f;
                BitVector class1A = mTCHU.segment(0, mClass1ALth);
                unsigned calcParity = class1A.parity(mTCHParity) & 0x3f;

                bool good = (sentParity == calcParity);

                if (good)
                {
                    unsigned char * frameBuffer = new unsigned char [mAMRFrameLth];
                    // AMR Frame, consisting of a 8 bit frame header, plus the payload from decoding
                    BitVector amrFrame(mKd + 8);
                    BitVector payload = amrFrame.tail(8);

                    // write frame header
                    amrFrame.fillField(0, mAMRFrameHeader, 8);

                    // We don't unmap here, but copy the decoded bits directly
                    // Decoder already delivers correct bit order
                    // mTCHD.unmap(mAMRBitOrder, payload.size(), payload);
                    mTCHD.copyTo(payload);
                    amrFrame.pack(frameBuffer);
                    message_port_pub(pmt::mp("voice"), pmt::cons(pmt::PMT_NIL, pmt::make_blob(frameBuffer,mAMRFrameLth)));
					delete[] frameBuffer;
                }
            }
        }
    }

    void tch_f_decoder_impl::setCodingMode(tch_mode mode)
    {
        if (mode  != TCH_FS && d_tch_mode != TCH_EFR)
        {
            d_tch_mode = mode;
            mKd = GSM::gAMRKd[d_tch_mode];
            mTCHD.resize(mKd);
            mTCHU.resize(mKd+6);
            mTCHParity = Parity(0x06f,6, GSM::gAMRClass1ALth[d_tch_mode]);
            mAMRBitOrder = GSM::gAMRBitOrder[d_tch_mode];
            mClass1ALth = GSM::gAMRClass1ALth[d_tch_mode];
            mClass1BLth = GSM::gAMRKd[d_tch_mode] - GSM::gAMRClass1ALth[d_tch_mode];
            mTCHUC.resize(GSM::gAMRTCHUCLth[d_tch_mode]);
            mPuncture = GSM::gAMRPuncture[d_tch_mode];
            mPunctureLth = GSM::gAMRPunctureLth[d_tch_mode];
            mClass1A_d.dup(mTCHD.head(mClass1ALth));

            switch (d_tch_mode)
            {
                case TCH_AFS12_2:
                    mViterbi = new ViterbiTCH_AFS12_2();
                    mAMRFrameLth = 32;
                    mAMRFrameHeader = 0x3c;
                    break;
                case TCH_AFS10_2:
                    mViterbi = new ViterbiTCH_AFS10_2();
                    mAMRFrameLth = 27;
                    mAMRFrameHeader = 0x3c;
                    break;
                case TCH_AFS7_95:
                    mViterbi = new ViterbiTCH_AFS7_95();
                    mAMRFrameLth = 21;
                    mAMRFrameHeader = 0x3c;
                    break;
                case TCH_AFS7_4:
                    mViterbi = new ViterbiTCH_AFS7_4();
                    mAMRFrameLth = 20;
                    mAMRFrameHeader = 0x3c;
                    break;
                case TCH_AFS6_7:
                    mViterbi = new ViterbiTCH_AFS6_7();
                    mAMRFrameLth = 18;
                    mAMRFrameHeader = 0x3c;
                    break;
                case TCH_AFS5_9:
                    mViterbi = new ViterbiTCH_AFS5_9();
                    mAMRFrameLth = 16;
                    mAMRFrameHeader = 0x14;
                    break;
                case TCH_AFS5_15:
                    mViterbi = new ViterbiTCH_AFS5_15();
                    mAMRFrameLth = 14;
                    mAMRFrameHeader = 0x3c;
                    break;
                case TCH_AFS4_75:
                    mViterbi = new ViterbiTCH_AFS4_75();
                    mAMRFrameLth = 13;
                    mAMRFrameHeader = 0x3c;
                    break;
                default:
                    mViterbi = new ViterbiTCH_AFS12_2();
                    mAMRFrameLth = 32;
                    mAMRFrameHeader = 0x3c;
                    break;
            }
        }
    }
  } /* namespace gsm */
} /* namespace gr */

