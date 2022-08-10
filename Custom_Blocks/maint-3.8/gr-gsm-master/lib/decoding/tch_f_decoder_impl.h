/* -*- c++ -*- */
/*
 * @file
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

#ifndef INCLUDED_GSM_TCH_F_DECODER_IMPL_H
#define INCLUDED_GSM_TCH_F_DECODER_IMPL_H

#include "openbts/AmrCoder.h"
#include "openbts/BitVector.h"
#include "openbts/GSM503Tables.h"
#include "openbts/GSM610Tables.h"
#include "openbts/GSM660Tables.h"
#include "openbts/ViterbiR204.h"
#include <grgsm/decoding/tch_f_decoder.h>


#define DATA_BLOCK_SIZE		184
#define PARITY_SIZE		    40
#define FLUSH_BITS_SIZE		4
#define PARITY_OUTPUT_SIZE (DATA_BLOCK_SIZE + PARITY_SIZE + FLUSH_BITS_SIZE)

#define CONV_INPUT_SIZE		PARITY_OUTPUT_SIZE
#define CONV_SIZE		    (2 * CONV_INPUT_SIZE)

#define BLOCKS			    8
#define iBLOCK_SIZE		    (CONV_SIZE / BLOCKS)

namespace gr {
    namespace gsm {

        class tch_f_decoder_impl : public tch_f_decoder
        {
            private:
                unsigned int d_collected_bursts_num;
                unsigned short interleave_trans[CONV_SIZE];
                pmt::pmt_t d_bursts[8];
                enum tch_mode d_tch_mode;
                bool d_boundary_check;
                bool d_boundary_decode;
                bool d_header_sent;

                BitVector mU;
                BitVector mP;
                BitVector mD;
                BitVector mDP;
                BitVector mTCHU;
                BitVector mTCHD;
                BitVector mClass1A_d;
                SoftVector mC;
                SoftVector mClass1_c;
                SoftVector mClass2_c;
                SoftVector mTCHUC;

                Parity mBlockCoder;
                Parity mTCHParity;

                ViterbiR2O4 mVR204Coder;
                ViterbiBase *mViterbi;

                unsigned char iBLOCK[2*BLOCKS*iBLOCK_SIZE];
                unsigned char mAMRFrameHeader;

                const unsigned *mAMRBitOrder;
                const unsigned *mPuncture;
                unsigned mClass1ALth;
                unsigned mClass1BLth;
                unsigned mPunctureLth;
                uint8_t mAMRFrameLth;
                uint8_t mKd;

                void decode(pmt::pmt_t msg);
                void setCodingMode(tch_mode mode);
            public:
                tch_f_decoder_impl(tch_mode mode, bool boundary_check=false);
                ~tch_f_decoder_impl();
        };

    } // namespace gsm
} // namespace gr

#endif /* INCLUDED_GSM_TCH_F_DECODER_IMPL_H */

