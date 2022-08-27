/* -*- c++ -*- */
/*
 * Copyright 2019 Clayton Smith.
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "l1_am_encoder_impl.h"
#include <gnuradio/io_signature.h>

namespace gr {
namespace nrsc5 {

std::vector<int> get_in_sizeofs(const int sm)
{
    std::vector<int> in_sizeofs;

    switch (sm) {
    case 1:
        in_sizeofs.push_back(3750);
        in_sizeofs.push_back(24000);
        in_sizeofs.push_back(SIS_BITS);
        break;
    case 3:
        in_sizeofs.push_back(3750);
        in_sizeofs.push_back(30000);
        in_sizeofs.push_back(SIS_BITS);
        break;
    }

    return in_sizeofs;
}

l1_am_encoder::sptr l1_am_encoder::make(const int sm)
{
    return gnuradio::get_initial_sptr(new l1_am_encoder_impl(sm));
}


/*
 * The private constructor
 */
l1_am_encoder_impl::l1_am_encoder_impl(const int sm)
    : gr::block("l1_am_encoder",
                gr::io_signature::makev(3, 3, get_in_sizeofs(sm)),
                gr::io_signature::make(1, 1, sizeof(gr_complex) * AM_FFT_SIZE))
{
    set_output_multiple(AM_SYMBOLS_PER_FRAME);

    this->sm = sm;

    p1_bits = 3750;
    p1_mod = 8;
    p3_bits = 0;
    p3_mod = 1;
    switch (sm) {
    case 1:
        p3_bits = 24000;
        break;
    case 3:
        p3_bits = 30000;
        break;
    }

    for (int i = 0; i < 512; i++) {
        int tmp = i;
        parity[i] = 0;
        while (tmp != 0) {
            parity[i] ^= 1;
            tmp &= (tmp - 1);
        }
    }

    for (int bc = 0; bc < AM_BLOCKS_PER_FRAME; bc++) {
        sc_data_seq(
            sc_symbols + (bc * SYMBOLS_PER_BLOCK), 0, 0, 0, 0, bc, sm == 1 ? 1 : 2);
    }

    set_channel_power();
    memset(bl, 0, DIVERSITY_DELAY);
    memset(bu, 0, DIVERSITY_DELAY);
    memset(ebl, 0, DIVERSITY_DELAY);
    memset(ebu, 0, DIVERSITY_DELAY);
}

/*
 * Our virtual destructor.
 */
l1_am_encoder_impl::~l1_am_encoder_impl() {}

void l1_am_encoder_impl::forecast(int noutput_items, gr_vector_int& ninput_items_required)
{
    int frames = noutput_items / AM_SYMBOLS_PER_FRAME;

    ninput_items_required[0] = frames * p1_mod;
    ninput_items_required[1] = frames * p3_mod;
    ninput_items_required[2] = frames * AM_BLOCKS_PER_FRAME;
}

int l1_am_encoder_impl::general_work(int noutput_items,
                                     gr_vector_int& ninput_items,
                                     gr_vector_const_void_star& input_items,
                                     gr_vector_void_star& output_items)
{
    const unsigned char* p1 = (const unsigned char*)input_items[0];
    const unsigned char* p3 = (const unsigned char*)input_items[1];
    const unsigned char* pids = (const unsigned char*)input_items[2];
    gr_complex* out = (gr_complex*)output_items[0];

    int frames = noutput_items / AM_SYMBOLS_PER_FRAME;

    int pids_off = 0, p1_off = 0, p3_off = 0;
    int out_off = 0;
    for (int frame = 0; frame < frames; frame++) {
        for (int block = 0; block < AM_BLOCKS_PER_FRAME; block++) {
            encode_l2_pdu(CONV_E1, p1 + p1_off, p1_g + p1_off * 12 / 5, p1_bits);
            encode_l2_pdu(CONV_E3, pids + pids_off, pids_g, SIS_BITS);
            interleaver_pids(pids_g, pids_matrix, block);
            p1_off += p1_bits;
            pids_off += SIS_BITS;
        }
        switch (sm) {
        case 1:
            encode_l2_pdu(CONV_E2, p3 + p3_off, p3_g, p3_bits);
            interleaver_ma1();
            break;
        case 3:
            encode_l2_pdu(CONV_E1, p3 + p3_off, p3_g, p3_bits);
            interleaver_ma3();
            break;
        }
        p3_off += p3_bits;

        for (int symbol = 0; symbol < AM_SYMBOLS_PER_FRAME; symbol++) {
            for (int col = 0; col < 25; col++) {
                switch (sm) {
                case 1:
                    /* 1012s.pdf table 12-2 */
                    out[out_off + 128 - 57 - col] =
                        -std::conj(qam64[pl_matrix[col][symbol]]);
                    out[out_off + 128 + 57 + col] = qam64[pu_matrix[col][symbol]];

                    /* 1012s.pdf table 12-6 */
                    out[out_off + 128 + 2 + col] = qpsk_am[t_matrix[col][symbol]];
                    out[out_off + 128 + 28 + col] = qam16[s_matrix[col][symbol]];
                    out[out_off + 128 - 2 - col] =
                        -std::conj(qpsk_am[t_matrix[col][symbol]]);
                    out[out_off + 128 - 28 - col] =
                        -std::conj(qam16[s_matrix[col][symbol]]);
                    break;
                case 3:
                    /* 1012s.pdf table 12-3 */
                    out[out_off + 128 - 2 - col] =
                        -std::conj(qam64[pl_matrix[col][symbol]]);
                    out[out_off + 128 + 2 + col] = qam64[pu_matrix[col][symbol]];

                    /* 1012s.pdf table 12-8 */
                    out[out_off + 128 - 28 - col] =
                        -std::conj(qam64[t_matrix[col][symbol]]);
                    out[out_off + 128 + 28 + col] = qam64[s_matrix[col][symbol]];

                    out[out_off + 128] = 1;
                    break;
                }
            }

            gr_complex pids_point_0 = qam16[pids_matrix[0][symbol]];
            gr_complex pids_point_1 = qam16[pids_matrix[1][symbol]];
            switch (sm) {
            case 1:
                /* 1012s.pdf table 12-7 */
                out[out_off + 128 - 27] = -std::conj(pids_point_0);
                out[out_off + 128 - 53] = -std::conj(pids_point_1);
                out[out_off + 128 + 27] = pids_point_0;
                out[out_off + 128 + 53] = pids_point_1;
                break;
            case 3:
                /* 1012s.pdf table 12-9 */
                out[out_off + 128 - 27] = -std::conj(pids_point_0);
                out[out_off + 128 + 27] = pids_point_1;
                break;
            }

            /* 1012s.pdf table 12-12 */
            gr_complex sc_point = bpsk_am[sc_symbols[symbol]];
            out[out_off + 128 - 1] = sc_point;
            out[out_off + 128 + 1] = sc_point;

            for (int i = 0; i < AM_FFT_SIZE; i++) {
                out[out_off + i] *= channel_power[i];
            }

            out_off += AM_FFT_SIZE;
        }
    }

    consume(0, frames * p1_mod);
    consume(1, frames * p3_mod);
    consume(2, frames * AM_BLOCKS_PER_FRAME);

    return noutput_items;
}

void l1_am_encoder_impl::reverse_bytes(const unsigned char* in,
                                       unsigned char* out,
                                       int len)
{
    for (int off = 0; off < len; off += 8) {
        int bits = (len - off < 8) ? len - off : 8;
        for (int i = 0; i < bits; i++) {
            out[off + i] = in[off + bits - 1 - i];
        }
    }
}

/* 1012s.pdf section 8.1 */
void l1_am_encoder_impl::scramble(unsigned char* buf, int len)
{
    unsigned int reg = 0x3ff;
    for (int off = 0; off < len; off++) {
        unsigned char next_bit = ((reg >> 9) ^ reg) & 1;
        buf[off] ^= next_bit;
        reg = (reg >> 1) | (next_bit << 10);
    }
}

/* 1012s.pdf section 9.1 */
void l1_am_encoder_impl::conv_enc(int mode,
                                  const unsigned char* in,
                                  unsigned char* out,
                                  int len)
{
    unsigned int poly_e1[] = { 0561, 0657, 0711 };
    unsigned int poly_e2[] = { 0561, 0753, 0711 };
    unsigned int poly_e3[] = { 0561, 0753, 0711 };
    unsigned int* poly;

    switch (mode) {
    case CONV_E1:
        poly = poly_e1;
        break;
    case CONV_E2:
        poly = poly_e2;
        break;
    case CONV_E3:
        poly = poly_e3;
        break;
    }

    unsigned int reg = (in[len - 8] << 1) | (in[len - 7] << 2) | (in[len - 6] << 3) |
                       (in[len - 5] << 4) | (in[len - 4] << 5) | (in[len - 3] << 6) |
                       (in[len - 2] << 7) | (in[len - 1] << 8);
    int out_off = 0;
    for (int in_off = 0; in_off < len; in_off++) {
        reg = (reg >> 1) | (in[in_off] << 8);
        for (int i = 0; i < 3; i++) {
            bool use;
            switch (mode) {
            case CONV_E1:
                use = (i == 0) || (i == 2) || (in_off % 5 >= 3);
                break;
            case CONV_E2:
                use = (i == 0) || ((i == 2) && (in_off % 2 == 0));
                break;
            case CONV_E3:
                use = true;
                break;
            }
            if (use) {
                out[out_off++] = parity[reg & poly[i]];
            }
        }
    }
}

void l1_am_encoder_impl::encode_l2_pdu(int mode,
                                       const unsigned char* in,
                                       unsigned char* out,
                                       int len)
{
    reverse_bytes(in, buf, len);
    scramble(buf, len);
    conv_enc(mode, buf, out, len);
}

void l1_am_encoder_impl::bit_map(unsigned char matrix[25][AM_SYMBOLS_PER_FRAME],
                                 int b,
                                 int k,
                                 int bits)
{
    int col = (9 * k) % 25;
    int row = (11 * col + 16 * (k / 25) + 11 * (k / 50)) % 32;
    matrix[col][b * SYMBOLS_PER_BLOCK + row] |= bits;
}

void l1_am_encoder_impl::interleaver_ma1()
{
    memset(pu_matrix, 0, 25 * AM_SYMBOLS_PER_FRAME);
    memset(pl_matrix, 0, 25 * AM_SYMBOLS_PER_FRAME);
    memset(s_matrix, 0, 25 * AM_SYMBOLS_PER_FRAME);
    memset(t_matrix, 0, 25 * AM_SYMBOLS_PER_FRAME);

    for (int i = 0; i < 6000; i++) {
        for (int j = 0; j < 3; j++) {
            bl[DIVERSITY_DELAY + i * 3 + j] = p1_g[i * 12 + bl_delay[j]];
            ml[i * 3 + j] = p1_g[i * 12 + ml_delay[j]];
            bu[DIVERSITY_DELAY + i * 3 + j] = p1_g[i * 12 + bu_delay[j]];
            mu[i * 3 + j] = p1_g[i * 12 + mu_delay[j]];
        }
        for (int j = 0; j < 2; j++) {
            el[i * 2 + j] = p3_g[i * 6 + el_delay[j]];
        }
        for (int j = 0; j < 4; j++) {
            eu[i * 4 + j] = p3_g[i * 6 + eu_delay[j]];
        }
    }

    int b, k, p;
    for (int n = 0; n < 18000; n++) {
        b = n / 2250;
        k = (n + n / 750 + 1) % 750;
        p = n % 3;
        bit_map(pl_matrix, b, k, bl[n] << p);

        b = (3 * n + 3) % 8;
        k = (n + n / 3000 + 3) % 750;
        p = 3 + (n % 3);
        bit_map(pl_matrix, b, k, ml[n] << p);

        b = n / 2250;
        k = (n + n / 750) % 750;
        p = n % 3;
        bit_map(pu_matrix, b, k, bu[n] << p);

        b = (3 * n) % 8;
        k = (n + n / 3000 + 2) % 750;
        p = 3 + (n % 3);
        bit_map(pu_matrix, b, k, mu[n] << p);
    }
    for (int n = 0; n < 12000; n++) {
        b = (3 * n + n / 3000) % 8;
        k = (n + (n / 6000)) % 750;
        p = n % 2;
        bit_map(t_matrix, b, k, el[n] << p);
    }
    for (int n = 0; n < 24000; n++) {
        b = (3 * n + n / 3000 + 2 * (n / 12000)) % 8;
        k = (n + (n / 6000)) % 750;
        p = n % 4;
        bit_map(s_matrix, b, k, eu[n] << p);
    }

    /* training symbols */
    for (int block = 0; block < AM_BLOCKS_PER_FRAME; block++) {
        for (int k = 750; k < 800; k++) {
            bit_map(pu_matrix, block, k, 0b100101);
            bit_map(pl_matrix, block, k, 0b100101);
            bit_map(s_matrix, block, k, 0b1001);
            bit_map(t_matrix, block, k, 0b10);
        }
    }

    memmove(bl, bl + 18000, DIVERSITY_DELAY);
    memmove(bu, bu + 18000, DIVERSITY_DELAY);
}

void l1_am_encoder_impl::interleaver_ma3()
{
    memset(pu_matrix, 0, 25 * AM_SYMBOLS_PER_FRAME);
    memset(pl_matrix, 0, 25 * AM_SYMBOLS_PER_FRAME);
    memset(s_matrix, 0, 25 * AM_SYMBOLS_PER_FRAME);
    memset(t_matrix, 0, 25 * AM_SYMBOLS_PER_FRAME);

    for (int i = 0; i < 6000; i++) {
        for (int j = 0; j < 3; j++) {
            bl[DIVERSITY_DELAY + i * 3 + j] = p1_g[i * 12 + bl_delay[j]];
            ml[i * 3 + j] = p1_g[i * 12 + ml_delay[j]];
            bu[DIVERSITY_DELAY + i * 3 + j] = p1_g[i * 12 + bu_delay[j]];
            mu[i * 3 + j] = p1_g[i * 12 + mu_delay[j]];

            ebl[DIVERSITY_DELAY + i * 3 + j] = p3_g[i * 12 + bl_delay[j]];
            eml[i * 3 + j] = p3_g[i * 12 + ml_delay[j]];
            ebu[DIVERSITY_DELAY + i * 3 + j] = p3_g[i * 12 + bu_delay[j]];
            emu[i * 3 + j] = p3_g[i * 12 + mu_delay[j]];
        }
    }

    int b, k, p;
    for (int n = 0; n < 18000; n++) {
        b = n / 2250;
        k = (n + n / 750 + 1) % 750;
        p = n % 3;
        bit_map(pl_matrix, b, k, bl[n] << p);

        b = (3 * n + 3) % 8;
        k = (n + n / 3000 + 3) % 750;
        p = 3 + (n % 3);
        bit_map(pl_matrix, b, k, ml[n] << p);

        b = n / 2250;
        k = (n + n / 750) % 750;
        p = n % 3;
        bit_map(pu_matrix, b, k, bu[n] << p);

        b = (3 * n) % 8;
        k = (n + n / 3000 + 2) % 750;
        p = 3 + (n % 3);
        bit_map(pu_matrix, b, k, mu[n] << p);

        b = (3 * n + 3) % 8;
        k = (n + n / 3000 + 3) % 750;
        p = n % 3;
        bit_map(t_matrix, b, k, ebl[n] << p);

        b = (3 * n + 3) % 8;
        k = (n + n / 3000 + 3) % 750;
        p = 3 + (n % 3);
        bit_map(t_matrix, b, k, eml[n] << p);

        b = (3 * n) % 8;
        k = (n + n / 3000 + 2) % 750;
        p = n % 3;
        bit_map(s_matrix, b, k, ebu[n] << p);

        b = (3 * n) % 8;
        k = (n + n / 3000 + 2) % 750;
        p = 3 + (n % 3);
        bit_map(s_matrix, b, k, emu[n] << p);
    }

    /* training symbols */
    for (int block = 0; block < AM_BLOCKS_PER_FRAME; block++) {
        for (int k = 750; k < 800; k++) {
            bit_map(pu_matrix, block, k, 0b100101);
            bit_map(pl_matrix, block, k, 0b100101);
            bit_map(s_matrix, block, k, 0b100101);
            bit_map(t_matrix, block, k, 0b100101);
        }
    }

    memmove(bl, bl + 18000, DIVERSITY_DELAY);
    memmove(bu, bu + 18000, DIVERSITY_DELAY);
    memmove(ebl, ebl + 18000, DIVERSITY_DELAY);
    memmove(ebu, ebu + 18000, DIVERSITY_DELAY);
}

void l1_am_encoder_impl::interleaver_pids(unsigned char* in,
                                          unsigned char matrix[2][AM_SYMBOLS_PER_FRAME],
                                          int block)
{
    unsigned char il[120], iu[120];
    int offset = block * SYMBOLS_PER_BLOCK;

    memset(matrix[0] + offset, 0, SYMBOLS_PER_BLOCK);
    memset(matrix[1] + offset, 0, SYMBOLS_PER_BLOCK);

    /* 1012s.pdf figure 10-5 */
    for (int i = 0; i < 10; i++) {
        for (int j = 0; j < 12; j++) {
            il[i * 12 + j] = in[i * 24 + pids_il_delay[j]];
            iu[i * 12 + j] = in[i * 24 + pids_iu_delay[j]];
        }
    }
    /* 1012s.pdf section 10.4 */
    for (int n = 0; n < 120; n++) {
        int k, p, row;

        p = n % 4;

        k = (n + (n / 60) + 11) % 30;
        row = (11 * (k + (k / 15)) + 3) % 32;
        matrix[0][offset + row] |= (il[n] << p);

        k = (n + (n / 60)) % 30;
        row = (11 * (k + (k / 15)) + 3) % 32;
        matrix[1][offset + row] |= (iu[n] << p);
    }
    matrix[0][offset + 8] = 0b1001;
    matrix[0][offset + 24] = 0b1001;
    matrix[1][offset + 8] = 0b1001;
    matrix[1][offset + 24] = 0b1001;
}

/* 1012s.pdf table 11-1 */
void l1_am_encoder_impl::sc_data_seq(
    unsigned char* out, int pli, int hppi, int abbi, int rdbi, int bc, int smi)
{
    out[0] = 0; // sync
    out[1] = 1; // sync
    out[2] = 1; // sync
    out[3] = 0; // sync
    out[4] = 0; // sync
    out[5] = 1; // sync
    out[6] = 0; // sync

    out[7] = pli;    // power level indicator
    out[8] = out[7]; // parity

    out[9] = 1; // sync

    out[10] = 0;                           // reserved
    out[11] = hppi;                        // high power pids indicator
    out[12] = abbi;                        // analog audio bandwidth indicator
    out[13] = out[10] ^ out[11] ^ out[12]; // parity

    out[14] = 0; // sync

    out[15] = rdbi; // reduced digital bandwidth indicator
    out[16] = 0;    // reserved
    out[17] = (bc & 0x4) >> 2;
    out[18] = (bc & 0x2) >> 1;
    out[19] = (bc & 0x1);
    out[20] = out[15] ^ out[16] ^ out[17] ^ out[18] ^ out[19]; // parity

    out[21] = 1; // sync
    out[22] = 1; // sync

    out[23] = 0; // reserved
    out[24] = 0; // reserved
    out[25] = 0; // reserved
    out[26] = (smi & 0x10) >> 4;
    out[27] = (smi & 0x08) >> 3;
    out[28] = (smi & 0x04) >> 2;
    out[29] = (smi & 0x02) >> 1;
    out[30] = (smi & 0x01);
    out[31] = out[23] ^ out[24] ^ out[25] ^ out[26] ^ out[27] ^ out[28] ^ out[29] ^
              out[30]; // parity
}

void l1_am_encoder_impl::set_channel_power()
{
    for (int i = 0; i < AM_FFT_SIZE; i++) {
        channel_power[i] = -INFINITY;
    }

    // Table 4-6 from 1082s.pdf
    switch (sm) {
    case 1:
        for (int col = 0; col < 25; col++) {
            channel_power[128 + 57 + col] = -30 - 10;
            channel_power[128 - 57 - col] = -30 - 10;

            channel_power[128 + 28 + col] = -43 - 4;
            channel_power[128 - 28 - col] = -43 - 4;

            channel_power[128 + 2 + col] = (col < 12 ? (-44 - 0.5 * col) : -50) + 3;
            channel_power[128 - 2 - col] = (col < 12 ? (-44 - 0.5 * col) : -50) + 3;
        }

        channel_power[128 + 1] = -26 + 6;
        channel_power[128 - 1] = -26 + 6;

        channel_power[128 + 27] = -43 - 4;
        channel_power[128 - 27] = -43 - 4;
        channel_power[128 + 53] = -43 - 4;
        channel_power[128 - 53] = -43 - 4;
        break;
    case 3:
        for (int col = 0; col < 25; col++) {
            channel_power[128 + 2 + col] = -15 - 10;
            channel_power[128 - 2 - col] = -15 - 10;

            channel_power[128 + 28 + col] = -30 - 10;
            channel_power[128 - 28 - col] = -30 - 10;
        }

        channel_power[128 + 1] = -15 + 6;
        channel_power[128 - 1] = -15 + 6;

        channel_power[128 + 27] = -30 - 4;
        channel_power[128 - 27] = -30 - 4;

        channel_power[128] = 0;
        break;
    }

    for (int i = 0; i < AM_FFT_SIZE; i++) {
        channel_power[i] = pow(10, channel_power[i] / 20);
    }
}

} /* namespace nrsc5 */
} /* namespace gr */
