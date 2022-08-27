/* -*- c++ -*- */
/*
 * @file
 * @author (C) 2014 by Piotr Krysik <ptrkrysik@gmail.com>
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

#include <string.h>
#include <gsm/gsm_constants.h>

#include <stdbool.h>
#include <osmocom/coding/gsm0503_coding.h>
#include <osmocom/core/utils.h>

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

int decode_sch(const unsigned char *buf, int * t1_o, int * t2_o, int * t3_o, int * ncc_o, int * bcc_o)
{

  int t1, t2, t3p, t3, ncc, bcc;

  uint8_t result[4];
  ubit_t bursts_u[SCH_DATA_LEN*2];
  sbit_t bursts_s[SCH_DATA_LEN*2];

  // extract encoded data from synchronization burst
  /* buf, 39 bit */
  /* buf + 39 + 64 = 103, 39 */
  memcpy(bursts_u, buf, SCH_DATA_LEN);
  memcpy(bursts_u + SCH_DATA_LEN, buf + SCH_DATA_LEN + N_SYNC_BITS, SCH_DATA_LEN);

  ubits2sbits(bursts_u, bursts_s, SCH_DATA_LEN*2);
  if(gsm0503_sch_decode(result, bursts_s)==-1){
    return 1;
  }
  
  // Synchronization channel information, 44.018 page 171. (V7.2.0)
  uint8_t decoded_data[25];
  osmo_pbit2ubit_ext(decoded_data, 0, result, 0, 25, 1);
  ncc =
    (decoded_data[ 7] << 2)  |
    (decoded_data[ 6] << 1)  |
    (decoded_data[ 5] << 0);
  bcc = 
    (decoded_data[ 4] << 2)  |
    (decoded_data[ 3] << 1)  |
    (decoded_data[ 2] << 0);
  t1 =
    (decoded_data[ 1] << 10) |
    (decoded_data[ 0] << 9)  |
    (decoded_data[15] << 8)  |
    (decoded_data[14] << 7)  |
    (decoded_data[13] << 6)  |
    (decoded_data[12] << 5)  |
    (decoded_data[11] << 4)  |
    (decoded_data[10] << 3)  |
    (decoded_data[ 9] << 2)  |
    (decoded_data[ 8] << 1)  |
    (decoded_data[23] << 0);
  t2 =
    (decoded_data[22] << 4)  |
    (decoded_data[21] << 3)  |
    (decoded_data[20] << 2)  |
    (decoded_data[19] << 1)  |
    (decoded_data[18] << 0);
  t3p =
    (decoded_data[17] << 2)  |
    (decoded_data[16] << 1)  |
    (decoded_data[24] << 0);

  t3 = 10 * t3p + 1;

  // modulo arithmetic t3 - t2 mod 26
//  tt = ((t3 + 26) - t2) % 26;

//  fn = (51 * 26 * t1) + (51 * tt) + t3;

  /*
   * BSIC: Base Station Identification Code
   *  BCC: Base station Color Code
   *  NCC: Network Color Code
   *
   * FN: Frame Number
   */

//  printf("bsic: %x (bcc: %u; ncc: %u)\tFN: %u\n", bsic, bsic & 7,
//          (bsic >> 3) & 7, fn);

//   if (fn_o)
//     *fn_o = fn;
//   if (bsic_o)
  if (t1_o && t2_o && t3_o && ncc_o && bcc_o) {
    *t1_o = t1;
    *t2_o = t2;
    *t3_o = t3;
    *bcc_o = bcc;
    *ncc_o = ncc;
  }

  return 0;
}
