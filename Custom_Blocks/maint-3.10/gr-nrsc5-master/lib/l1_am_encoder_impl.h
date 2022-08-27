/* -*- c++ -*- */
/*
 * Copyright 2019 Clayton Smith.
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifndef INCLUDED_NRSC5_L1_AM_ENCODER_IMPL_H
#define INCLUDED_NRSC5_L1_AM_ENCODER_IMPL_H

#include <nrsc5/l1_am_encoder.h>

namespace gr {
namespace nrsc5 {
/* 1012s.pdf table 12-10 */
gr_complex bpsk_am[] = { { 0, -0.5 }, { 0, 0.5 } };

/* 1012s.pdf table 12-4 */
gr_complex qpsk_am[] = { { -0.5, -0.5 },
                         { 0.5, -0.5 },

                         { -0.5, 0.5 },
                         { 0.5, 0.5 } };

/* 1012s.pdf table 12-5 */
gr_complex qam16[] = { { -1.5, -1.5 }, { 1.5, -1.5 }, { -0.5, -1.5 }, { 0.5, -1.5 },

                       { -1.5, 1.5 },  { 1.5, 1.5 },  { -0.5, 1.5 },  { 0.5, 1.5 },

                       { -1.5, -0.5 }, { 1.5, -0.5 }, { -0.5, -0.5 }, { 0.5, -0.5 },

                       { -1.5, 0.5 },  { 1.5, 0.5 },  { -0.5, 0.5 },  { 0.5, 0.5 } };

/* 1012s.pdf table 12-1 */
gr_complex qam64[] = { { -3.5, -3.5 }, { 3.5, -3.5 }, { -0.5, -3.5 }, { 0.5, -3.5 },
                       { -2.5, -3.5 }, { 2.5, -3.5 }, { -1.5, -3.5 }, { 1.5, -3.5 },

                       { -3.5, 3.5 },  { 3.5, 3.5 },  { -0.5, 3.5 },  { 0.5, 3.5 },
                       { -2.5, 3.5 },  { 2.5, 3.5 },  { -1.5, 3.5 },  { 1.5, 3.5 },

                       { -3.5, -0.5 }, { 3.5, -0.5 }, { -0.5, -0.5 }, { 0.5, -0.5 },
                       { -2.5, -0.5 }, { 2.5, -0.5 }, { -1.5, -0.5 }, { 1.5, -0.5 },

                       { -3.5, 0.5 },  { 3.5, 0.5 },  { -0.5, 0.5 },  { 0.5, 0.5 },
                       { -2.5, 0.5 },  { 2.5, 0.5 },  { -1.5, 0.5 },  { 1.5, 0.5 },

                       { -3.5, -2.5 }, { 3.5, -2.5 }, { -0.5, -2.5 }, { 0.5, -2.5 },
                       { -2.5, -2.5 }, { 2.5, -2.5 }, { -1.5, -2.5 }, { 1.5, -2.5 },

                       { -3.5, 2.5 },  { 3.5, 2.5 },  { -0.5, 2.5 },  { 0.5, 2.5 },
                       { -2.5, 2.5 },  { 2.5, 2.5 },  { -1.5, 2.5 },  { 1.5, 2.5 },

                       { -3.5, -1.5 }, { 3.5, -1.5 }, { -0.5, -1.5 }, { 0.5, -1.5 },
                       { -2.5, -1.5 }, { 2.5, -1.5 }, { -1.5, -1.5 }, { 1.5, -1.5 },

                       { -3.5, 1.5 },  { 3.5, 1.5 },  { -0.5, 1.5 },  { 0.5, 1.5 },
                       { -2.5, 1.5 },  { 2.5, 1.5 },  { -1.5, 1.5 },  { 1.5, 1.5 } };

/* 1012s.pdf figure 10-4 */
int bl_delay[] = { 2, 1, 5 };
int ml_delay[] = { 11, 6, 7 };
int bu_delay[] = { 10, 8, 9 };
int mu_delay[] = { 4, 3, 0 };
int el_delay[] = { 0, 1 };
int eu_delay[] = { 2, 3, 5, 4 };

/* 1012s.pdf figure 10-5 */
int pids_il_delay[] = { 0, 1, 12, 13, 6, 5, 18, 17, 11, 7, 23, 19 };
int pids_iu_delay[] = { 2, 4, 14, 16, 3, 8, 15, 20, 9, 10, 21, 22 };

class l1_am_encoder_impl : public l1_am_encoder
{
private:
    int sm;
    int p1_bits, p1_mod;
    int p3_bits, p3_mod;

    unsigned char buf[30000];
    unsigned char pids_g[SIS_BITS * 3];
    unsigned char p1_g[72000];
    unsigned char p3_g[72000];
    unsigned char bl[18000 + DIVERSITY_DELAY], ml[18000];
    unsigned char bu[18000 + DIVERSITY_DELAY], mu[18000];
    unsigned char el[12000], eu[24000];
    unsigned char ebl[18000 + DIVERSITY_DELAY], eml[18000];
    unsigned char ebu[18000 + DIVERSITY_DELAY], emu[18000];
    unsigned char parity[512];
    unsigned char sc_symbols[AM_SYMBOLS_PER_FRAME];
    unsigned char pu_matrix[25][AM_SYMBOLS_PER_FRAME];
    unsigned char pl_matrix[25][AM_SYMBOLS_PER_FRAME];
    unsigned char s_matrix[25][AM_SYMBOLS_PER_FRAME];
    unsigned char t_matrix[25][AM_SYMBOLS_PER_FRAME];
    unsigned char pids_matrix[2][AM_SYMBOLS_PER_FRAME];
    float channel_power[AM_FFT_SIZE];

    void reverse_bytes(const unsigned char* in, unsigned char* out, int len);
    void scramble(unsigned char* buf, int len);
    void conv_enc(int mode, const unsigned char* in, unsigned char* out, int len);
    void encode_l2_pdu(int mode, const unsigned char* in, unsigned char* out, int len);
    void bit_map(unsigned char matrix[25][AM_SYMBOLS_PER_FRAME], int b, int k, int bits);
    void interleaver_ma1();
    void interleaver_ma3();
    void interleaver_pids(unsigned char* in,
                          unsigned char matrix[2][AM_SYMBOLS_PER_FRAME],
                          int block);
    void sc_data_seq(
        unsigned char* out, int pli, int hppi, int abbi, int rdbi, int bc, int smi);
    void set_channel_power();

public:
    l1_am_encoder_impl(const int sm);
    ~l1_am_encoder_impl();

    // Where all the action really happens
    void forecast(int noutput_items, gr_vector_int& ninput_items_required);

    int general_work(int noutput_items,
                     gr_vector_int& ninput_items,
                     gr_vector_const_void_star& input_items,
                     gr_vector_void_star& output_items);
};

} // namespace nrsc5
} // namespace gr

#endif /* INCLUDED_NRSC5_L1_AM_ENCODER_IMPL_H */
