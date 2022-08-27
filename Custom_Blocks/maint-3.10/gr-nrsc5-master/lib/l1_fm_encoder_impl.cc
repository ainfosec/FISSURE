/* -*- c++ -*- */
/*
 * Copyright 2017 Clayton Smith.
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "l1_fm_encoder_impl.h"
#include <gnuradio/io_signature.h>

namespace gr {
namespace nrsc5 {

std::vector<int> get_in_sizeofs(const int psm, const int ssm)
{
    std::vector<int> in_sizeofs;

    switch (psm) {
    case 1:
        in_sizeofs.push_back(146176);
        in_sizeofs.push_back(SIS_BITS);
        break;
    case 2:
        in_sizeofs.push_back(146176);
        in_sizeofs.push_back(2304);
        in_sizeofs.push_back(SIS_BITS);
        break;
    case 3:
        in_sizeofs.push_back(146176);
        in_sizeofs.push_back(4608);
        in_sizeofs.push_back(SIS_BITS);
        break;
    case 11:
        in_sizeofs.push_back(146176);
        in_sizeofs.push_back(4608);
        in_sizeofs.push_back(4608);
        in_sizeofs.push_back(SIS_BITS);
        break;
    case 5:
        in_sizeofs.push_back(4608);
        in_sizeofs.push_back(109312);
        in_sizeofs.push_back(4608);
        in_sizeofs.push_back(SIS_BITS);
        break;
    case 6:
        in_sizeofs.push_back(9216);
        in_sizeofs.push_back(72448);
        in_sizeofs.push_back(SIS_BITS);
        break;
    }

    switch (ssm) {
    case 1:
        in_sizeofs.push_back(18272);
        in_sizeofs.push_back(512);
        in_sizeofs.push_back(SIS_BITS);
        break;
    case 2:
        in_sizeofs.push_back(4608);
        in_sizeofs.push_back(109312);
        in_sizeofs.push_back(4608);
        in_sizeofs.push_back(512);
        in_sizeofs.push_back(SIS_BITS);
        break;
    case 3:
        in_sizeofs.push_back(9216);
        in_sizeofs.push_back(72448);
        in_sizeofs.push_back(512);
        in_sizeofs.push_back(SIS_BITS);
        break;
    case 4:
        in_sizeofs.push_back(4608);
        in_sizeofs.push_back(146176);
        in_sizeofs.push_back(4608);
        in_sizeofs.push_back(512);
        in_sizeofs.push_back(SIS_BITS);
        break;
    }

    return in_sizeofs;
}

l1_fm_encoder::sptr l1_fm_encoder::make(const int psm, const int ssm)
{
    return gnuradio::get_initial_sptr(new l1_fm_encoder_impl(psm, ssm));
}


/*
 * The private constructor
 */
l1_fm_encoder_impl::l1_fm_encoder_impl(const int psm, const int ssm)
    : gr::block("l1_fm_encoder",
                gr::io_signature::makev(2, 9, get_in_sizeofs(psm, ssm)),
                gr::io_signature::make(1, 1, sizeof(gr_complex) * FM_FFT_SIZE))
{
    set_output_multiple(FM_SYMBOLS_PER_FRAME);

    this->psm = psm;
    this->ssm = ssm;

    p1_bits = 0;
    p2_bits = 0;
    p3_bits = 0;
    p4_bits = 0;
    p1_mod = 1;
    p2_mod = 1;
    p3_mod = 8;
    p4_mod = 8;
    switch (psm) {
    case 1:
        p1_bits = 146176;
        break;
    case 2:
        p1_bits = 146176;
        p3_bits = 2304;
        break;
    case 3:
        p1_bits = 146176;
        p3_bits = 4608;
        break;
    case 11:
        p1_bits = 146176;
        p3_bits = 4608;
        p4_bits = 4608;
        break;
    case 5:
        p1_bits = 4608;
        p1_mod = 8;
        p2_bits = 109312;
        p3_bits = 4608;
        break;
    case 6:
        p1_bits = 9216;
        p1_mod = 8;
        p2_bits = 72448;
        break;
    }

    s1_bits = 0;
    s2_bits = 0;
    s3_bits = 0;
    s4_bits = 0;
    s5_bits = 0;
    s1_mod = 8;
    s2_mod = 1;
    s3_mod = 8;
    s4_mod = 8;
    s5_mod = 16;
    switch (ssm) {
    case 1:
        s4_bits = 18272;
        s5_bits = 512;
        break;
    case 2:
        s1_bits = 4608;
        s2_bits = 109312;
        s3_bits = 4608;
        s5_bits = 512;
        break;
    case 3:
        s1_bits = 9216;
        s2_bits = 72448;
        s5_bits = 512;
        break;
    case 4:
        s1_bits = 4608;
        s2_bits = 146176;
        s3_bits = 4608;
        s5_bits = 512;
        break;
    }

    if (p1_mod == 8) {
        p1_prime_off = 0;
        p1_prime = (unsigned char*)malloc(p1_bits * p1_mod * 3);
        p1_prime_g = (unsigned char*)malloc(p1_bits * 2 * p1_mod);
        px2_matrix = (unsigned char*)malloc(p1_bits * 2 * p1_mod);
    }
    if (p3_bits) {
        p3_p4_g = (unsigned char*)malloc(p3_bits * 2 * p3_mod);
        px1_matrix = (unsigned char*)malloc(p3_bits * 2 * p3_mod);
        px1_internal = (unsigned char*)malloc(p3_bits * 2 * p3_mod * 2);
    }
    if (p4_bits) {
        px2_matrix = (unsigned char*)malloc(p4_bits * 2 * p4_mod);
        px2_internal = (unsigned char*)malloc(p4_bits * 2 * p4_mod * 2);
    }
    internal_half = 0;

    if (ssm) {
        sids_g = (unsigned char*)malloc(SIS_BITS * 7 / 2 * FM_BLOCKS_PER_FRAME);
    }
    if (s4_bits) {
        s4_g = (unsigned char*)malloc(s4_bits * 7 / 2 * s4_mod);
        sb_matrix = (unsigned char*)malloc((63952 + 560) * s4_mod);
    }
    if (s5_bits) {
        s5_g = (unsigned char*)malloc(s5_bits * 3 * s5_mod);
        sp_matrix = (unsigned char*)malloc(1536 * s5_mod);
    }

    for (int i = 0; i < 128; i++) {
        int tmp = i;
        parity[i] = 0;
        while (tmp != 0) {
            parity[i] ^= 1;
            tmp &= (tmp - 1);
        }
    }

    for (int scid = 0; scid < 4; scid++) {
        for (int bc = 0; bc < FM_BLOCKS_PER_FRAME; bc++) {
            primary_sc_data_seq(primary_sc_symbols[scid] + (bc * SYMBOLS_PER_BLOCK),
                                scid,
                                ssm ? 1 : 0,
                                bc,
                                psm);
            secondary_sc_data_seq(
                secondary_sc_symbols[scid] + (bc * SYMBOLS_PER_BLOCK), scid, bc, ssm);
        }
    }
}

/*
 * Our virtual destructor.
 */
l1_fm_encoder_impl::~l1_fm_encoder_impl()
{
    if (p1_mod == 8) {
        free(p1_prime);
        free(p1_prime_g);
        free(px2_matrix);
    }
    if (p3_bits) {
        free(p3_p4_g);
        free(px1_matrix);
        free(px1_internal);
    }
    if (p4_bits) {
        free(px2_matrix);
        free(px2_internal);
    }

    if (ssm) {
        free(sids_g);
    }
    if (s4_bits) {
        free(s4_g);
        free(sb_matrix);
    }
    if (s5_bits) {
        free(s5_g);
        free(sp_matrix);
    }
}

void l1_fm_encoder_impl::forecast(int noutput_items, gr_vector_int& ninput_items_required)
{
    int frames = noutput_items / FM_SYMBOLS_PER_FRAME;
    int port = 0;

    if (p1_bits)
        ninput_items_required[port++] = frames * p1_mod;
    if (p2_bits)
        ninput_items_required[port++] = frames * p2_mod;
    if (p3_bits)
        ninput_items_required[port++] = frames * p3_mod;
    if (p4_bits)
        ninput_items_required[port++] = frames * p4_mod;
    if (psm)
        ninput_items_required[port++] = frames * FM_BLOCKS_PER_FRAME;
    if (s1_bits)
        ninput_items_required[port++] = frames * s1_mod;
    if (s2_bits)
        ninput_items_required[port++] = frames * s2_mod;
    if (s3_bits)
        ninput_items_required[port++] = frames * s3_mod;
    if (s4_bits)
        ninput_items_required[port++] = frames * s4_mod;
    if (s5_bits)
        ninput_items_required[port++] = frames * s5_mod;
    if (ssm)
        ninput_items_required[port++] = frames * FM_BLOCKS_PER_FRAME;
}

int l1_fm_encoder_impl::general_work(int noutput_items,
                                     gr_vector_int& ninput_items,
                                     gr_vector_const_void_star& input_items,
                                     gr_vector_void_star& output_items)
{
    int port = 0;
    const unsigned char *pids = NULL, *p1 = NULL, *p2 = NULL, *p3 = NULL, *p4 = NULL;
    const unsigned char *sids = NULL, *s1 = NULL, *s2 = NULL, *s3 = NULL, *s4 = NULL,
                        *s5 = NULL;

    if (p1_bits)
        p1 = (const unsigned char*)input_items[port++];
    if (p2_bits)
        p2 = (const unsigned char*)input_items[port++];
    if (p3_bits)
        p3 = (const unsigned char*)input_items[port++];
    if (p4_bits)
        p4 = (const unsigned char*)input_items[port++];
    if (psm)
        pids = (const unsigned char*)input_items[port++];
    if (s1_bits)
        s1 = (const unsigned char*)input_items[port++];
    if (s2_bits)
        s2 = (const unsigned char*)input_items[port++];
    if (s3_bits)
        s3 = (const unsigned char*)input_items[port++];
    if (s4_bits)
        s4 = (const unsigned char*)input_items[port++];
    if (s5_bits)
        s5 = (const unsigned char*)input_items[port++];
    if (ssm)
        sids = (const unsigned char*)input_items[port++];

    gr_complex* out = (gr_complex*)output_items[0];

    int frames = noutput_items / FM_SYMBOLS_PER_FRAME;

    int pids_off = 0, p1_off = 0, p2_off = 0, p3_off = 0, p4_off = 0;
    int sids_off = 0, s1_off = 0, s2_off = 0, s3_off = 0, s4_off = 0, s5_off = 0;
    int out_off = 0;
    for (int frame = 0; frame < frames; frame++) {
        for (int i = 0; i < FM_BLOCKS_PER_FRAME; i++) {
            encode_l2_pdu(
                CONV_2_5, pids + pids_off, pids_g + (SIS_BITS * 5 / 2 * i), SIS_BITS);
            pids_off += SIS_BITS;
        }

        if (p1_mod == 1) {
            encode_l2_pdu(CONV_2_5, p1 + p1_off, p1_g, p1_bits);
            p1_off += p1_bits;
        } else {
            for (int i = 0; i < p1_mod; i++) {
                encode_l2_pdu(
                    CONV_2_5, p1 + p1_off, p1_g + (p1_bits * 5 / 2 * i), p1_bits);
                encode_l2_pdu(CONV_1_2,
                              p1_prime + p1_prime_off,
                              p1_prime_g + (p1_bits * 2 * i),
                              p1_bits);

                if (psm == 5) {
                    interleaver_i(p1_prime_g + (p1_bits * 2 * i),
                                  px2_matrix + (p1_bits * 2 * i),
                                  4,
                                  2,
                                  36,
                                  2,
                                  V_PX2_MP5,
                                  9216);
                } else {
                    interleaver_i(p1_prime_g + (p1_bits * 2 * i),
                                  px2_matrix + (p1_bits * 2 * i),
                                  8,
                                  2,
                                  36,
                                  1,
                                  V_PX2_MP6,
                                  18432);
                }

                memcpy(p1_prime + p1_prime_off, p1 + p1_off, p1_bits);
                p1_off += p1_bits;
                p1_prime_off = (p1_prime_off + p1_bits) % (p1_bits * p1_mod * 3);
            }
            encode_l2_pdu(
                CONV_2_5, p2 + p2_off, p1_g + (p1_bits * 5 / 2 * p1_mod), p2_bits);
            p2_off += p2_bits;
        }
        interleaver_i(p1_g, pm_matrix, 20, 16, 36, 1, V_PM, 365440);
        interleaver_ii(pids_g, pm_matrix, 20, 16, 36, 1, V_PM, 200, 365440, 3200);

        if (p3_bits) {
            for (int i = 0; i < p3_mod; i++) {
                encode_l2_pdu(
                    CONV_1_2, p3 + p3_off, p3_p4_g + (p3_bits * 2 * i), p3_bits);
                p3_off += p3_bits;
            }
            interleaver_iv(px1_matrix, px1_internal, internal_half);
        }
        if (p4_bits) {
            for (int i = 0; i < p4_mod; i++) {
                encode_l2_pdu(
                    CONV_1_2, p4 + p4_off, p3_p4_g + (p4_bits * 2 * i), p4_bits);
                p4_off += p4_bits;
            }
            interleaver_iv(px2_matrix, px2_internal, internal_half);
        }
        internal_half ^= 1;

        if (ssm) {
            for (int i = 0; i < FM_BLOCKS_PER_FRAME; i++) {
                encode_l2_pdu(
                    CONV_2_7, sids + sids_off, sids_g + (SIS_BITS * 7 / 2 * i), SIS_BITS);
                sids_off += SIS_BITS;
            }
        }
        if (s4_bits) {
            for (int i = 0; i < s4_mod; i++) {
                encode_l2_pdu(
                    CONV_2_7, s4 + s4_off, s4_g + (s4_bits * 7 / 2 * i), s4_bits);
                interleaver_i(s4_g + (s4_bits * 7 / 2 * i),
                              sb_matrix + ((63952 + 560) * i),
                              28,
                              2,
                              36,
                              1,
                              V_SB,
                              63952);
                interleaver_ii(sids_g + (2 * SIS_BITS * 7 / 2 * i),
                               sb_matrix + ((63952 + 560) * i),
                               28,
                               2,
                               36,
                               1,
                               V_SB,
                               280,
                               63952,
                               560);
                s4_off += s4_bits;
            }
        }
        if (s5_bits) {
            for (int i = 0; i < s5_mod; i++) {
                encode_l2_pdu(CONV_1_3, s5 + s5_off, s5_g + (s5_bits * 3 * i), s5_bits);
                interleaver_iii(s5_g + (s5_bits * 3 * i),
                                sp_matrix + (1536 * i),
                                2,
                                1,
                                24,
                                6,
                                V_SP,
                                1536);
                s5_off += s5_bits;
            }
        }

        for (int symbol = 0; symbol < FM_SYMBOLS_PER_FRAME; symbol++) {
            for (int i = 0; i < FM_FFT_SIZE; i++) {
                out[out_off + i] = 0;
            }

            for (int chan = 0; chan < 61; chan++) {
                out[out_off + REF_SC_CHAN[chan]] =
                    bpsk_fm[primary_sc_symbols[REF_SC_ID[chan]][symbol]];
                if (chan == partitions_per_band())
                    chan = 61 - partitions_per_band() - 2;
            }

            int pm_channels[] = { 0,  1,  2,  3,  4,  5,  6,  7,  8,  9,
                                  50, 51, 52, 53, 54, 55, 56, 57, 58, 59 };
            write_symbol(pm_matrix + (symbol * 20 * 36), out + out_off, pm_channels, 20);

            if (psm == 2) {
                int px1_channels[] = { 10, 49 };
                write_symbol(
                    px1_matrix + (symbol * 2 * 36), out + out_off, px1_channels, 2);
            }
            if (psm == 3 || psm == 11 || psm == 5) {
                int px1_channels[] = { 10, 11, 48, 49 };
                write_symbol(
                    px1_matrix + (symbol * 4 * 36), out + out_off, px1_channels, 4);
            }
            if (psm == 11 || psm == 5) {
                int px2_channels[] = { 12, 13, 46, 47 };
                write_symbol(
                    px2_matrix + (symbol * 4 * 36), out + out_off, px2_channels, 4);
            }
            if (psm == 6) {
                int px2_channels[] = { 10, 11, 12, 13, 46, 47, 48, 49 };
                write_symbol(
                    px2_matrix + (symbol * 8 * 36), out + out_off, px2_channels, 8);
            }

            if (ssm) {
                for (int chan = 15; chan < 46; chan++) {
                    out[out_off + REF_SC_CHAN[chan]] =
                        bpsk_fm[secondary_sc_symbols[REF_SC_ID[chan]][symbol]];
                }

                if (ssm == 1) {
                    int sb_channels[] = { 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
                                          26, 27, 28, 29, 30, 31, 32, 33, 34, 35,
                                          36, 37, 38, 39, 40, 41, 42, 43 };
                    write_symbol(
                        sb_matrix + (symbol * 28 * 36), out + out_off, sb_channels, 28);
                }

                int sp_channels[] = { 15, 44 };
                write_symbol(
                    sp_matrix + (symbol * 2 * 24), out + out_off, sp_channels, 2);

                float secondary_scale_factor = pow(10, -5 / 20);
                for (int i = REF_SC_CHAN[15]; i <= REF_SC_CHAN[45]; i++) {
                    out[out_off + i] *= secondary_scale_factor;
                }
            }

            out_off += FM_FFT_SIZE;
        }
    }

    port = 0;
    if (p1_bits)
        consume(port++, frames * p1_mod);
    if (p2_bits)
        consume(port++, frames * p2_mod);
    if (p3_bits)
        consume(port++, frames * p3_mod);
    if (p4_bits)
        consume(port++, frames * p4_mod);
    if (psm)
        consume(port++, frames * FM_BLOCKS_PER_FRAME);
    if (s1_bits)
        consume(port++, frames * s1_mod);
    if (s2_bits)
        consume(port++, frames * s2_mod);
    if (s3_bits)
        consume(port++, frames * s3_mod);
    if (s4_bits)
        consume(port++, frames * s4_mod);
    if (s5_bits)
        consume(port++, frames * s5_mod);
    if (ssm)
        consume(port++, frames * FM_BLOCKS_PER_FRAME);

    return noutput_items;
}

void l1_fm_encoder_impl::reverse_bytes(const unsigned char* in,
                                       unsigned char* out,
                                       int len)
{
    for (int off = 0; off < len; off += 8) {
        for (int i = 0; i < 8; i++) {
            out[off + i] = in[off + 7 - i];
        }
    }
}

/* 1011s.pdf section 8.2 */
void l1_fm_encoder_impl::scramble(unsigned char* buf, int len)
{
    unsigned int reg = 0x3ff;
    for (int off = 0; off < len; off++) {
        unsigned char next_bit = ((reg >> 9) ^ reg) & 1;
        buf[off] ^= next_bit;
        reg = (reg >> 1) | (next_bit << 10);
    }
}

/* 1011s.pdf section 9.3 */
void l1_fm_encoder_impl::conv_enc(int mode,
                                  const unsigned char* in,
                                  unsigned char* out,
                                  int len)
{
    unsigned char poly_1_3[] = { 3, 3, 0133, 0171, 0165 };
    unsigned char poly_2_5[] = { 3, 2, 0133, 0171, 0165 };
    unsigned char poly_1_2[] = { 2, 2, 0133, 0165 };
    unsigned char poly_2_7[] = { 4, 3, 0133, 0171, 0165, 0165 };
    unsigned char* poly;

    switch (mode) {
    case CONV_1_3:
        poly = poly_1_3;
        break;
    case CONV_2_5:
        poly = poly_2_5;
        break;
    case CONV_1_2:
        poly = poly_1_2;
        break;
    case CONV_2_7:
        poly = poly_2_7;
        break;
    }

    unsigned char reg = (in[len - 6] << 1) | (in[len - 5] << 2) | (in[len - 4] << 3) |
                        (in[len - 3] << 4) | (in[len - 2] << 5) | (in[len - 1] << 6);
    int out_off = 0;
    for (int in_off = 0; in_off < len; in_off++) {
        reg = (reg >> 1) | (in[in_off] << 6);
        for (int i = 0; i < poly[in_off & 1]; i++) {
            out[out_off++] = parity[reg & poly[i + 2]];
        }
    }
}

void l1_fm_encoder_impl::encode_l2_pdu(int mode,
                                       const unsigned char* in,
                                       unsigned char* out,
                                       int len)
{
    reverse_bytes(in, buf, len);
    scramble(buf, len);
    conv_enc(mode, buf, out, len);
}

/* 1011s.pdf sections 10.2.3 */
void l1_fm_encoder_impl::interleaver_i(unsigned char* in,
                                       unsigned char* matrix,
                                       int J,
                                       int B,
                                       int C,
                                       int M,
                                       unsigned char* V,
                                       int N)
{
    for (int i = 0; i < N; i++) {
        int partition = V[((i + 2 * (M / 4)) / M) % J];
        int block;
        if (M == 1)
            block = ((i / J) + (partition * 7)) % B;
        else
            block = (i + (i / (J * B))) % B;
        int ki = i / (J * B);
        int row = (ki * 11) % 32;
        int col = ((ki * 11) + (ki / (32 * 9))) % C;
        matrix[((block * 32) + row) * (J * C) + (partition * C) + col] = in[i];
    }
}

/* 1011s.pdf sections 10.2.4 */
void l1_fm_encoder_impl::interleaver_ii(unsigned char* in,
                                        unsigned char* matrix,
                                        int J,
                                        int B,
                                        int C,
                                        int M,
                                        unsigned char* V,
                                        int b,
                                        int I0,
                                        int N)
{
    for (int i = 0; i < N; i++) {
        int partition = V[i % J];
        int block = i / b;
        int ki = ((i / J) % (b / J)) + (I0 / (J * B));
        int row = (ki * 11) % 32;
        int col = ((ki * 11) + (ki / (32 * 9))) % C;
        matrix[((block * 32) + row) * (J * C) + (partition * C) + col] = in[i];
    }
}

/* 1011s.pdf sections 10.2.5 */
void l1_fm_encoder_impl::interleaver_iii(unsigned char* in,
                                         unsigned char* matrix,
                                         int J,
                                         int B,
                                         int C,
                                         int M,
                                         unsigned char* V,
                                         int N)
{
    for (int i = 0; i < N; i++) {
        int partition = V[(i + (i / M)) % J];
        int ki = i / J;
        int row = (ki * 11) % 32;
        int col = ((ki * 11) + (ki / 32)) % C;
        matrix[row * (J * C) + (partition * C) + col] = in[i];
    }
}

/* 1011s.pdf sections 10.2.6 */
void l1_fm_encoder_impl::interleaver_iv(unsigned char* matrix,
                                        unsigned char* internal,
                                        int half)
{
    int J = psm == 2 ? 2 : 4; // number of partitions
    int B = 32;               // blocks
    int C = 36;               // columns per partition
    int M = psm == 2 ? 4 : 2; // factor: 1, 2 or 4
    int N = psm == 2 ? 73728 : 147456;

    int bk_bits = 32 * C;
    int bk_adj = 32 * C - 1;

    int internal_off = half * (N / 2);
    int pt[4];
    for (int i = 0; i < J; i++) {
        pt[i] = internal_off / J;
    }

    for (int i = 0; i < N / 2; i++) {
        int partition = ((i + 2 * (M / 4)) / M) % J;
        unsigned int pti = pt[partition]++;
        int block = (pti + (partition * 7) - (bk_adj * (pti / bk_bits))) % B;
        int row = ((11 * pti) % bk_bits) / C;
        int column = (pti * 11) % C;
        internal[(block * 32 + row) * (J * C) + partition * C + column] = p3_p4_g[i];
        matrix[i] = internal[internal_off++];
    }
}

void l1_fm_encoder_impl::write_symbol(unsigned char* matrix_row,
                                      gr_complex* out_row,
                                      int* channels,
                                      int num_channels)
{
    for (int i = 0; i < num_channels; i++) {
        int width = (channels[i] == 15 || channels[i] == 44) ? 12 : 18;
        for (int j = 0; j < width; j++) {
            unsigned char ii = matrix_row[(i * width * 2) + (j * 2)];
            unsigned char qq = matrix_row[(i * width * 2) + (j * 2) + 1];
            unsigned char symbol = (ii << 1) | qq;
            int carrier = REF_SC_CHAN[channels[i]] + 1 + j;
            out_row[carrier] = qpsk_fm[symbol];
        }
    }
}

/* 1011s.pdf table 11-1 */
void l1_fm_encoder_impl::primary_sc_data_seq(
    unsigned char* out, int scid, int sci, int bc, int psmi)
{
    out[0] = 0; // sync
    out[1] = 1; // sync
    out[2] = 1; // sync
    out[3] = 0; // sync
    out[4] = 0; // sync
    out[5] = 1; // sync
    out[6] = 0; // sync

    out[7] = 0;      // reserved
    out[8] = out[7]; // parity

    out[9] = 1; // sync

    out[10] = (scid & 0x2) >> 1;
    out[11] = (scid & 0x1);
    out[12] = sci;
    out[13] = out[10] ^ out[11] ^ out[12]; // parity

    out[14] = 0; // sync

    out[15] = 0; // reserved
    out[16] = (bc & 0x8) >> 3;
    out[17] = (bc & 0x4) >> 2;
    out[18] = (bc & 0x2) >> 1;
    out[19] = (bc & 0x1);
    out[20] = out[15] ^ out[16] ^ out[17] ^ out[18] ^ out[19]; // parity

    out[21] = 1; // sync
    out[22] = 1; // sync

    out[23] = 1; // P3ISI
    out[24] = 0; // reserved
    out[25] = (psmi & 0x20) >> 5;
    out[26] = (psmi & 0x10) >> 4;
    out[27] = (psmi & 0x08) >> 3;
    out[28] = (psmi & 0x04) >> 2;
    out[29] = (psmi & 0x02) >> 1;
    out[30] = (psmi & 0x01);
    out[31] = out[23] ^ out[24] ^ out[25] ^ out[26] ^ out[27] ^ out[28] ^ out[29] ^
              out[30]; // parity

    differential_encode(out);
}

/* 1011s.pdf table 11-2 */
void l1_fm_encoder_impl::secondary_sc_data_seq(unsigned char* out,
                                               int scid,
                                               int bc,
                                               int ssmi)
{
    out[0] = 0; // sync
    out[1] = 1; // sync
    out[2] = 1; // sync
    out[3] = 0; // sync
    out[4] = 0; // sync
    out[5] = 1; // sync
    out[6] = 0; // sync

    out[7] = 0;      // reserved
    out[8] = out[7]; // parity

    out[9] = 1; // sync

    out[10] = (scid & 0x2) >> 1;
    out[11] = (scid & 0x1);
    out[12] = 0;                           // reserved
    out[13] = out[10] ^ out[11] ^ out[12]; // parity

    out[14] = 0; // sync

    out[15] = 0; // reserved
    out[16] = (bc & 0x8) >> 3;
    out[17] = (bc & 0x4) >> 2;
    out[18] = (bc & 0x2) >> 1;
    out[19] = (bc & 0x1);
    out[20] = out[15] ^ out[16] ^ out[17] ^ out[18] ^ out[19]; // parity

    out[21] = 1; // sync
    out[22] = 1; // sync

    out[23] = 0; // reserved
    out[24] = 0; // reserved
    out[25] = 0; // reserved
    out[26] = (ssmi & 0x10) >> 4;
    out[27] = (ssmi & 0x08) >> 3;
    out[28] = (ssmi & 0x04) >> 2;
    out[29] = (ssmi & 0x02) >> 1;
    out[30] = (ssmi & 0x01);
    out[31] = out[23] ^ out[24] ^ out[25] ^ out[26] ^ out[27] ^ out[28] ^ out[29] ^
              out[30]; // parity

    differential_encode(out);
}

void l1_fm_encoder_impl::differential_encode(unsigned char* buf)
{
    unsigned char last_symbol = 0;
    for (int i = 0; i < SYMBOLS_PER_BLOCK; i++) {
        if (buf[i]) {
            last_symbol ^= 1;
        }
        buf[i] = last_symbol;
    }
}

int l1_fm_encoder_impl::partitions_per_band()
{
    switch (psm) {
    case 2:
        return 11;
    case 3:
        return 12;
    case 5:
    case 6:
    case 11:
        return 14;
    default:
        return 10;
    }
}

} /* namespace nrsc5 */
} /* namespace gr */
