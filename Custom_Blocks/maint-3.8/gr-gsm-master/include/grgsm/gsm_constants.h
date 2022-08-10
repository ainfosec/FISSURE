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
 
#ifndef INCLUDED_GSM_CONSTANTS_H
#define INCLUDED_GSM_CONSTANTS_H

#define GSM_SYMBOL_RATE  (1625000.0/6.0) //symbols per second
#define GSM_SYMBOL_PERIOD (1.0/GSM_SYMBOL_RATE) //seconds per symbol

//Burst timing
#define TAIL_BITS         3
#define GUARD_BITS        8
#define GUARD_FRACTIONAL  0.25 //fractional part of guard period
#define GUARD_PERIOD      GUARD_BITS + GUARD_FRACTIONAL
#define DATA_BITS         57   //size of 1 data block in normal burst
#define STEALING_BIT      1
#define N_TRAIN_BITS      26
#define N_SYNC_BITS       64
#define USEFUL_BITS       142  //(2*(DATA_BITS+STEALING_BIT) + N_TRAIN_BITS )
#define FCCH_BITS         USEFUL_BITS
#define BURST_SIZE        (USEFUL_BITS+2*TAIL_BITS)
#define ACCESS_BURST_SIZE 88
#define PROCESSED_CHUNK   BURST_SIZE+2*GUARD_PERIOD

#define SCH_DATA_LEN      39
#define TS_BITS           (TAIL_BITS+USEFUL_BITS+TAIL_BITS+GUARD_BITS)  //a full TS (156 bits)
#define TS_PER_FRAME      8
#define FRAME_BITS        (TS_PER_FRAME * TS_BITS + 2) // 156.25 * 8
#define FCCH_POS          TAIL_BITS
#define SYNC_POS          39
#define TRAIN_POS         ( TAIL_BITS + (DATA_BITS+STEALING_BIT) + 5) //first 5 bits of a training sequence
                                                       //aren't used for channel impulse response estimation
#define TRAIN_BEGINNING   5
#define SAFETY_MARGIN     6   //

#define FCCH_HITS_NEEDED        (USEFUL_BITS - 4)
#define FCCH_MAX_MISSES         1
#define FCCH_MAX_FREQ_OFFSET    100

#define CHAN_IMP_RESP_LENGTH  5

#define MAX_SCH_ERRORS    10  //maximum number of subsequent sch errors after which gsm receiver goes to find_next_fcch state

typedef enum {empty, fcch_burst, sch_burst, normal_burst, rach_burst, dummy, dummy_or_normal, normal_or_noise} burst_type;
typedef enum {unknown, multiframe_26, multiframe_51} multiframe_type;

static const unsigned char SYNC_BITS[] = {
  1, 0, 1, 1, 1, 0, 0, 1, 0, 1, 1, 0, 0, 0, 1, 0,
  0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1,
  0, 0, 1, 0, 1, 1, 0, 1, 0, 1, 0, 0, 0, 1, 0, 1,
  0, 1, 1, 1, 0, 1, 1, 0, 0, 0, 0, 1, 1, 0, 1, 1
};

const unsigned FCCH_FRAMES[] = {0, 10, 20, 30, 40};
const unsigned SCH_FRAMES[] = {1, 11, 21, 31, 41};

const unsigned BCCH_FRAMES[] = {2, 3, 4, 5};          //!!the receiver shouldn't care about logical
                                                      //!!channels so this will be removed from this header
const unsigned TEST_CCH_FRAMES[] = {2, 3, 4, 5, 6, 7, 8, 9, 12, 13, 14, 15, 16, 17, 18, 19, 22, 23, 24, 25, 26, 27, 28, 29, 32, 33, 34, 35, 36, 37, 38, 39, 42, 43, 44, 45, 46, 47, 48, 49};
const unsigned TRAFFIC_CHANNEL_F[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24};
const unsigned TEST51[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50};


#define TSC0  0
#define TSC1  1
#define TSC2  2
#define TSC3  3
#define TSC4  4
#define TSC5  5
#define TSC6  6
#define TSC7  7
#define TS_DUMMY 8

#define TRAIN_SEQ_NUM 9

#define TIMESLOT0  0
#define TIMESLOT1  1
#define TIMESLOT2  2
#define TIMESLOT3  3
#define TIMESLOT4  4
#define TIMESLOT5  5
#define TIMESLOT6  6
#define TIMESLOT7  7


static const unsigned char train_seq[TRAIN_SEQ_NUM][N_TRAIN_BITS] = {
  {0, 0, 1, 0, 0, 1, 0, 1, 1, 1, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 1, 1, 1},
  {0, 0, 1, 0, 1, 1, 0, 1, 1, 1, 0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1, 0, 1, 1, 1},
  {0, 1, 0, 0, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 1, 0, 0, 1, 0, 0, 0, 0, 1, 1, 1, 0},
  {0, 1, 0, 0, 0, 1, 1, 1, 1, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 1, 1, 1, 0},
  {0, 0, 0, 1, 1, 0, 1, 0, 1, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 1, 1},
  {0, 1, 0, 0, 1, 1, 1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 1, 1, 1, 0, 1, 0},
  {1, 0, 1, 0, 0, 1, 1, 1, 1, 1, 0, 1, 1, 0, 0, 0, 1, 0, 1, 0, 0, 1, 1, 1, 1, 1},
  {1, 1, 1, 0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1, 0, 1, 1, 1, 0, 1, 1, 1, 1, 0, 0},
  {0, 1, 1, 1, 0, 0, 0, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1} // DUMMY
};


//Dummy burst 0xFB 76 0A 4E 09 10 1F 1C 5C 5C 57 4A 33 39 E9 F1 2F A8
static const unsigned char dummy_burst[] = {
  0, 0, 0, 
  1, 1, 1, 1, 1, 0, 1, 1, 0, 1,
  1, 1, 0, 1, 1, 0, 0, 0, 0, 0,
  1, 0, 1, 0, 0, 1, 0, 0, 1, 1,
  1, 0, 0, 0, 0, 0, 1, 0, 0, 1,
  0, 0, 0, 1, 0, 0, 0, 0, 0, 0,
  0, 1, 1, 1, 1, 1, 0, 0,

  0, 1, 1, 1, 0, 0, 0, 1, 0, 1,
  1, 1, 0, 0, 0, 1, 0, 1, 1, 1,
  0, 0, 0, 1, 0, 1,

  0, 1, 1, 1, 0, 1, 0, 0, 1, 0,
  1, 0, 0, 0, 1, 1, 0, 0, 1, 1,
  0, 0, 1, 1, 1, 0, 0, 1, 1, 1,
  1, 0, 1, 0, 0, 1, 1, 1, 1, 1,
  0, 0, 0, 1, 0, 0, 1, 0, 1, 1,
  1, 1, 1, 0, 1, 0, 1, 0,
  0, 0, 0
};


/*
 * The frequency correction burst is used for frequency synchronization
 * of the mobile.  This is broadcast in TS0 together with the SCH and
 * BCCH.
 *
 * Modulating the bits below causes a spike at 62.5kHz above (below for
 * COMPACT) the center frequency.  One can use this spike with a narrow
 * band filter to accurately determine the center of the channel.
 */
static const unsigned char fc_fb[] = {
  0, 0, 0,                                           //I don't use this tables,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,    //I copied this here from burst_types.h because
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,    //the description is very informative - p.krysik
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0
};

static const unsigned char fc_compact_fb[] = {
  1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0,
  1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0,
  1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0,
  1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0,
  1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0,
  1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0,
  1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0,
  1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0,
  1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0
};


#endif /* INCLUDED_GSM_CONSTANTS_H */
