/* -*- c -*- */
/*
 * Copyright 2012 Dominic Spill
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
/*
UAP Data HEC  Header (octal)
----------------------------------
00  123  e1   770007 007070 000777
47  123  06   770007 007007 700000
00  124  32   007007 007007 007700
47  124  d5   007007 007070 707077
00  125  5a   707007 007007 077070
47  125  bd   707007 007070 777707
00  126  e2   077007 007007 000777
47  126  05   077007 007070 700000
00  127  8a   777007 007007 070007
47  127  6d   777007 007070 770770
00  11b  9e   770770 007007 777007
47  11b  79   770770 007070 077770
00  11c  4d   007770 007070 770070
47  11c  aa   007770 007007 070707
00  11d  25   707770 007070 700700
47  11d  c2   707770 007007 000077
00  11e  9d   077770 007070 777007
47  11e  7a   077770 007007 077770
00  11f  f5   777770 007070 707777
47  11f  12   777770 007007 007000
*/

#include "../bluetooth_packet_tx.h"
#include <stdio.h>

int test_gen_packet_header() {
    char *optr;
    int i, j, ret, err;
    ret = 0;

    printf("Testing header\n");
    printf("---------------\n");

	/* lt_addr, type, flow, arqn, seqn, UAP, HEC */
    uint8_t data[20][7] = {
        {},
        {},
        {},
        {},
        {},
        {},
        {},
        {},
        {},
        {}
		UAP Data HE
		-----------
		00  123  e1
		47  123  06
		00  124  32
		47  124  d5
		00  125  5a
		47  125  bd
		00  126  e2
		47  126  05
		00  127  8a
		47  127  6d
		00  11b  9e
		47  11b  79
		00  11c  4d
		47  11c  aa
		00  11d  25
		47  11d  c2
		00  11e  9d
		47  11e  7a
		00  11f  f5
		47  11f  12

    };

    for(i = 0; i < 20; i++) {
		gen_packet_header(uint8_t lt_addr, uint8_t type, uint8_t flow, uint8_t arqn, uint8_t seqn)
        if (uap == 1) {
            printf("E");
            ret++;
        }
        else
            printf(".");
    }

	if (ret > 0)
		printf("%d errors\n", ret);
    printf("\n--------------------\n");
    printf("Done testing unfec23\n");
    return ret;
}

int main(int argc, char** argv) {
    int ret = 0;

    ret += test_unfec23();

    exit(ret);
}
