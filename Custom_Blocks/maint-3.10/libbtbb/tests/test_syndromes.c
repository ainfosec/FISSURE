/* -*- c -*- */
/*
 * Copyright 2007 - 2011 Dominic Spill, Michael Ossmann                                                                                            
 * 
 * This file is part of libbtbb
 * 
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with libbtbb; see the file COPYING.  If not, write to
 * the Free Software Foundation, Inc., 51 Franklin Street,
 * Boston, MA 02110-1301, USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "../bluetooth_packet.h"
#include <stdio.h>

int test_syndromes() {
    int ret, i;
    uint64_t syndrome, syncword;
    ret = 0;

    printf("Testing syndromes\n");
    printf("-----------------\n");

    uint64_t syndrome_input[2] = {
        /* No errors */
        0xcc7b7268ff614e1b,
        /* Errors */
        0xcc7d7268ff614e1b
    };

    uint64_t syndrome_output[2] = {
        /* No errors */
        0,
        /* Errors */
        0x0000000299c6f9b5
    };

    for(i = 0; i < 2; i++) {
        syndrome = gen_syndrome(syndrome_input[i]);
        if (syndrome == syndrome_output[i]) {
            printf(".");
        } else {
            printf("F");
            ret++;
        }
    }

    uint64_t syncword_input[2] = {
        /* No errors */
        0xcc7b7268ff614e1b,
        /* Errors */
        0xcc7b7268ff514e1b
    };

    uint64_t syncword_output[2] = {
        /* No errors */
        0x4ffffffe44ad1ae7,
        /* Errors */
        0x4ffffffe44ad1ae7
    };

    gen_syndrome_map();
    for(i = 0; i < 2; i++) {
        syncword = decode_syncword(syncword_input[i] ^ pn);
        if (syncword == syncword_output[i]) {
            printf(".");
        } else {
            printf("F");
            ret++;
        }
    }

	if (ret > 0)
		printf("%d errors\n", ret);
    printf("\n-----------------\n");
    printf("Done testing syndrome generation\n");
    return ret;
}

int main(int argc, char** argv) {
    int ret = 0;

    ret += test_syndromes();

    exit(ret);
}
