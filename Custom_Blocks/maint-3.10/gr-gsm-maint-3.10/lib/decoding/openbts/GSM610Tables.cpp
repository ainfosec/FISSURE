/*
 * Copyright 2008 Free Software Foundation, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * This use of this software may be subject to additional restrictions.
 * See the LEGAL file in the main directory for details.
 */

#include "GSM610Tables.h"


/*
RFC 3551                    RTP A/V Profile                    July 2003


   Octet  Bit 0   Bit 1   Bit 2   Bit 3   Bit 4   Bit 5   Bit 6   Bit 7
   _____________________________________________________________________
       0    1       1       0       1    LARc0.0 LARc0.1 LARc0.2 LARc0.3
       1 LARc0.4 LARc0.5 LARc1.0 LARc1.1 LARc1.2 LARc1.3 LARc1.4 LARc1.5
       2 LARc2.0 LARc2.1 LARc2.2 LARc2.3 LARc2.4 LARc3.0 LARc3.1 LARc3.2
       3 LARc3.3 LARc3.4 LARc4.0 LARc4.1 LARc4.2 LARc4.3 LARc5.0 LARc5.1
       4 LARc5.2 LARc5.3 LARc6.0 LARc6.1 LARc6.2 LARc7.0 LARc7.1 LARc7.2
       5  Nc0.0   Nc0.1   Nc0.2   Nc0.3   Nc0.4   Nc0.5   Nc0.6  bc0.0
       6  bc0.1   Mc0.0   Mc0.1  xmaxc00 xmaxc01 xmaxc02 xmaxc03 xmaxc04
       7 xmaxc05 xmc0.0  xmc0.1  xmc0.2  xmc1.0  xmc1.1  xmc1.2  xmc2.0
       8 xmc2.1  xmc2.2  xmc3.0  xmc3.1  xmc3.2  xmc4.0  xmc4.1  xmc4.2
       9 xmc5.0  xmc5.1  xmc5.2  xmc6.0  xmc6.1  xmc6.2  xmc7.0  xmc7.1
      10 xmc7.2  xmc8.0  xmc8.1  xmc8.2  xmc9.0  xmc9.1  xmc9.2  xmc10.0
      11 xmc10.1 xmc10.2 xmc11.0 xmc11.1 xmc11.2 xmc12.0 xmc12.1 xcm12.2
      12  Nc1.0   Nc1.1   Nc1.2   Nc1.3   Nc1.4   Nc1.5   Nc1.6   bc1.0
      13  bc1.1   Mc1.0   Mc1.1  xmaxc10 xmaxc11 xmaxc12 xmaxc13 xmaxc14
      14 xmax15  xmc13.0 xmc13.1 xmc13.2 xmc14.0 xmc14.1 xmc14.2 xmc15.0
      15 xmc15.1 xmc15.2 xmc16.0 xmc16.1 xmc16.2 xmc17.0 xmc17.1 xmc17.2
      16 xmc18.0 xmc18.1 xmc18.2 xmc19.0 xmc19.1 xmc19.2 xmc20.0 xmc20.1
      17 xmc20.2 xmc21.0 xmc21.1 xmc21.2 xmc22.0 xmc22.1 xmc22.2 xmc23.0
      18 xmc23.1 xmc23.2 xmc24.0 xmc24.1 xmc24.2 xmc25.0 xmc25.1 xmc25.2
      19  Nc2.0   Nc2.1   Nc2.2   Nc2.3   Nc2.4   Nc2.5   Nc2.6   bc2.0
      20  bc2.1   Mc2.0   Mc2.1  xmaxc20 xmaxc21 xmaxc22 xmaxc23 xmaxc24
      21 xmaxc25 xmc26.0 xmc26.1 xmc26.2 xmc27.0 xmc27.1 xmc27.2 xmc28.0
      22 xmc28.1 xmc28.2 xmc29.0 xmc29.1 xmc29.2 xmc30.0 xmc30.1 xmc30.2
      23 xmc31.0 xmc31.1 xmc31.2 xmc32.0 xmc32.1 xmc32.2 xmc33.0 xmc33.1
      24 xmc33.2 xmc34.0 xmc34.1 xmc34.2 xmc35.0 xmc35.1 xmc35.2 xmc36.0
      25 Xmc36.1 xmc36.2 xmc37.0 xmc37.1 xmc37.2 xmc38.0 xmc38.1 xmc38.2
      26  Nc3.0   Nc3.1   Nc3.2   Nc3.3   Nc3.4   Nc3.5   Nc3.6   bc3.0
      27  bc3.1   Mc3.0   Mc3.1  xmaxc30 xmaxc31 xmaxc32 xmaxc33 xmaxc34
      28 xmaxc35 xmc39.0 xmc39.1 xmc39.2 xmc40.0 xmc40.1 xmc40.2 xmc41.0
      29 xmc41.1 xmc41.2 xmc42.0 xmc42.1 xmc42.2 xmc43.0 xmc43.1 xmc43.2
      30 xmc44.0 xmc44.1 xmc44.2 xmc45.0 xmc45.1 xmc45.2 xmc46.0 xmc46.1
      31 xmc46.2 xmc47.0 xmc47.1 xmc47.2 xmc48.0 xmc48.1 xmc48.2 xmc49.0
      32 xmc49.1 xmc49.2 xmc50.0 xmc50.1 xmc50.2 xmc51.0 xmc51.1 xmc51.2

                        Table 3: GSM payload format
*/


/*
	This file encodes a mapping between
	GSM 05.03 Table 2 and RFC-3551 Table 3.
*/

/*
	Naming convention:
	xxx_p	position (bit index)
	xxx_l	length (bit field length)
	LAR	log area ratio
	N	LTP lag
	b	LTP gain
	M	grid
	Xmax	block amplitude
	x	RPE pulses
*/


/**@name Lengths of GSM 06.10 fields */
//@{
const unsigned int LAR1_l=6;	///< log area ratio
const unsigned int LAR2_l=6;	///< log area ratio
const unsigned int LAR3_l=5;	///< log area ratio
const unsigned int LAR4_l=5;	///< log area ratio
const unsigned int LAR5_l=4;	///< log area ratio
const unsigned int LAR6_l=4;	///< log area ratio
const unsigned int LAR7_l=3;	///< log area ratio
const unsigned int LAR8_l=3;	///< log area ratio
const unsigned int N_l=7;	///< LTP lag
const unsigned int b_l=2;	///< LTP gain
const unsigned int M_l=2;	///< grid position
const unsigned int Xmax_l=6;	///< block amplitude
const unsigned int x_l=3;	///< RPE pulses
//@}



/*@name Indecies of GSM 06.10 fields as they appear in RFC-3551 Table 3. */
//@{

/**@name Log area ratios, apply to whole frame. */
//@{
const unsigned int LAR1_p = 0;
const unsigned int LAR2_p = LAR1_p + LAR1_l;
const unsigned int LAR3_p = LAR2_p + LAR2_l;
const unsigned int LAR4_p = LAR3_p + LAR3_l;
const unsigned int LAR5_p = LAR4_p + LAR4_l;
const unsigned int LAR6_p = LAR5_p + LAR5_l;
const unsigned int LAR7_p = LAR6_p + LAR6_l;
const unsigned int LAR8_p = LAR7_p + LAR7_l;
//@}
/**@name Subframe 1 */
//@{
const unsigned int N1_p = LAR8_p + LAR8_l;
const unsigned int b1_p = N1_p + N_l;
const unsigned int M1_p = b1_p + b_l;
const unsigned int Xmax1_p = M1_p + M_l;
const unsigned int x1_0_p = Xmax1_p + Xmax_l;
const unsigned int x1_1_p = x1_0_p + x_l;
const unsigned int x1_2_p = x1_1_p + x_l;
const unsigned int x1_3_p = x1_2_p + x_l;
const unsigned int x1_4_p = x1_3_p + x_l;
const unsigned int x1_5_p = x1_4_p + x_l;
const unsigned int x1_6_p = x1_5_p + x_l;
const unsigned int x1_7_p = x1_6_p + x_l;
const unsigned int x1_8_p = x1_7_p + x_l;
const unsigned int x1_9_p = x1_8_p + x_l;
const unsigned int x1_10_p = x1_9_p + x_l;
const unsigned int x1_11_p = x1_10_p + x_l;
const unsigned int x1_12_p = x1_11_p + x_l;
//@}
/**@name Subframe 2 */
//@{
const unsigned int N2_p = x1_12_p + x_l;
const unsigned int b2_p = N2_p + N_l;
const unsigned int M2_p = b2_p + b_l;
const unsigned int Xmax2_p = M2_p + M_l;
const unsigned int x2_0_p = Xmax2_p + Xmax_l;
const unsigned int x2_1_p = x2_0_p + x_l;
const unsigned int x2_2_p = x2_1_p + x_l;
const unsigned int x2_3_p = x2_2_p + x_l;
const unsigned int x2_4_p = x2_3_p + x_l;
const unsigned int x2_5_p = x2_4_p + x_l;
const unsigned int x2_6_p = x2_5_p + x_l;
const unsigned int x2_7_p = x2_6_p + x_l;
const unsigned int x2_8_p = x2_7_p + x_l;
const unsigned int x2_9_p = x2_8_p + x_l;
const unsigned int x2_10_p = x2_9_p + x_l;
const unsigned int x2_11_p = x2_10_p + x_l;
const unsigned int x2_12_p = x2_11_p + x_l;
//@}
/**@mame Subframe 3 */
//@{
const unsigned int N3_p = x2_12_p + x_l;
const unsigned int b3_p = N3_p + N_l;
const unsigned int M3_p = b3_p + b_l;
const unsigned int Xmax3_p = M3_p + M_l;
const unsigned int x3_0_p = Xmax3_p + Xmax_l;
const unsigned int x3_1_p = x3_0_p + x_l;
const unsigned int x3_2_p = x3_1_p + x_l;
const unsigned int x3_3_p = x3_2_p + x_l;
const unsigned int x3_4_p = x3_3_p + x_l;
const unsigned int x3_5_p = x3_4_p + x_l;
const unsigned int x3_6_p = x3_5_p + x_l;
const unsigned int x3_7_p = x3_6_p + x_l;
const unsigned int x3_8_p = x3_7_p + x_l;
const unsigned int x3_9_p = x3_8_p + x_l;
const unsigned int x3_10_p = x3_9_p + x_l;
const unsigned int x3_11_p = x3_10_p + x_l;
const unsigned int x3_12_p = x3_11_p + x_l;
//@}
/**@name Subframe 4 */
//@{
const unsigned int N4_p = x3_12_p + x_l;
const unsigned int b4_p = N4_p + N_l;
const unsigned int M4_p = b4_p + b_l;
const unsigned int Xmax4_p = M4_p + M_l;
const unsigned int x4_0_p = Xmax4_p + Xmax_l;
const unsigned int x4_1_p = x4_0_p + x_l;
const unsigned int x4_2_p = x4_1_p + x_l;
const unsigned int x4_3_p = x4_2_p + x_l;
const unsigned int x4_4_p = x4_3_p + x_l;
const unsigned int x4_5_p = x4_4_p + x_l;
const unsigned int x4_6_p = x4_5_p + x_l;
const unsigned int x4_7_p = x4_6_p + x_l;
const unsigned int x4_8_p = x4_7_p + x_l;
const unsigned int x4_9_p = x4_8_p + x_l;
const unsigned int x4_10_p = x4_9_p + x_l;
const unsigned int x4_11_p = x4_10_p + x_l;
const unsigned int x4_12_p = x4_11_p + x_l;
//@}
//@}


/*
	This array encodes GSM 05.03 Table 2.
	It's also GSM 06.10 Table A2.1a.
	This is the order of bits as they appear in
	the d[] bits of the GSM TCH/F.
	RTP[4+g610BitOrder[i]] <=> GSM[i]
*/
unsigned int GSM::g610BitOrder[260] = {
/**@name importance class 1 */
//@{
/** LAR1:5 */	LAR1_p+LAR1_l-1-5, 		/* bit 0 */
/** Xmax1:5 */	Xmax1_p+Xmax_l-1-5,
/** Xmax2:5 */	Xmax2_p+Xmax_l-1-5,
/** Xmax3:5 */	Xmax3_p+Xmax_l-1-5,
/** Xmax4:5 */	Xmax4_p+Xmax_l-1-5,
//@}
/**@name importance class 2 */
//@{
/** LAR1:4 */	LAR1_p+LAR1_l-1-4,
/** LAR2:5 */	LAR2_p+LAR2_l-1-5,
/** LAR3:4 */	LAR3_p+LAR3_l-1-4,
//@}
/**@name importance class 3 */
//@{
/** LAR1:3 */	LAR1_p+LAR1_l-1-3,
/** LAR2:4 */	LAR2_p+LAR2_l-1-4,
/** LAR3:3 */	LAR3_p+LAR3_l-1-3,		/* bit 10 */
/** LAR4:4 */	LAR4_p+LAR4_l-1-4,
/** N1:6 */	N1_p+N_l-1-6,
/** N2:6 */	N2_p+N_l-1-6,
/** N3:6 */	N3_p+N_l-1-6,
/** N4:6 */	N4_p+N_l-1-6,
/** Xmax1:4 */	Xmax1_p+Xmax_l-1-4,
/** Xmax2:4 */	Xmax2_p+Xmax_l-1-4,
/** Xmax3:4 */	Xmax3_p+Xmax_l-1-4,
/** Xmax4:4 */	Xmax4_p+Xmax_l-1-4,
/** LAR2:3 */	LAR2_p+LAR2_l-1-3,		/* bit 20 */
/** LAR5:3 */	LAR5_p+LAR5_l-1-3,
/** LAR6:3 */	LAR6_p+LAR6_l-1-3,
/** N1:5 */	N1_p+N_l-1-5,
/** N2:5 */	N2_p+N_l-1-5,
/** N3:5 */	N3_p+N_l-1-5,
/** N4:5 */	N4_p+N_l-1-5,
/** N1:4 */	N1_p+N_l-1-4,
/** N2:4 */	N2_p+N_l-1-4,
/** N3:4 */	N3_p+N_l-1-4,
/** N4:4 */	N4_p+N_l-1-4,			/* bit 30 */
/** N1:3 */	N1_p+N_l-1-3,
/** N2:3 */	N2_p+N_l-1-3,
/** N3:3 */	N3_p+N_l-1-3,
/** N4:3 */	N4_p+N_l-1-3,
/** N1:2 */	N1_p+N_l-1-2,
/** N2:2 */	N2_p+N_l-1-2,
/** N3:2 */	N3_p+N_l-1-2,
/** N4:2 */	N4_p+N_l-1-2,
//@}
/**@name importance class 4 */
//@{
/** Xmax1:3 */	Xmax1_p+Xmax_l-1-3,
/** Xmax2:3 */	Xmax2_p+Xmax_l-1-3,		/* bit 40 */
/** Xmax3:3 */	Xmax3_p+Xmax_l-1-3,
/** Xmax4:3 */	Xmax4_p+Xmax_l-1-3,
/** LAR1:2 */	LAR1_p+LAR1_l-1-2,
/** LAR4:3 */	LAR4_p+LAR4_l-1-3,
/** LAR7:2 */	LAR7_p+LAR7_l-1-2,
/** N1:1 */	N1_p+N_l-1-1,
/** N2:1 */	N2_p+N_l-1-1,
/** N3:1 */	N3_p+N_l-1-1,
/** N4:1 */	N4_p+N_l-1-1,
/** LAR5:2 */	LAR5_p+LAR5_l-1-2,		/* bit 50 */
/** LAR6:2 */	LAR6_p+LAR6_l-1-2,
/** b1:1 */	b1_p+b_l-1-1,
/** b2:1 */	b2_p+b_l-1-1,
/** b3:1 */	b3_p+b_l-1-1,
/** b4:1 */	b4_p+b_l-1-1,
/** N1:0 */	N1_p+N_l-1-0,
/** N2:0 */	N2_p+N_l-1-0,
/** N3:0 */	N3_p+N_l-1-0,
/** N4:0 */	N4_p+N_l-1-0,
/** M1:1 */	M1_p+M_l-1-1,			/* bit 60 */
/** M2:1 */	M2_p+M_l-1-1,
/** M3:1 */	M3_p+M_l-1-1,
/** M4:1 */	M4_p+M_l-1-1,
//@}
/**@name importance class 5 */
//@{
/** LAR1:1 */	LAR1_p+LAR1_l-1-1,
/** LAR2:2 */	LAR2_p+LAR2_l-1-2,
/** LAR3:2 */	LAR3_p+LAR3_l-1-2,
/** LAR8:2 */	LAR8_p+LAR8_l-1-2,
/** LAR4:2 */	LAR4_p+LAR4_l-1-2,
/** LAR5:1 */	LAR5_p+LAR5_l-1-1,
/** LAR7:1 */	LAR7_p+LAR7_l-1-1,		/* bit 70 */
/** b1:0 */	b1_p+b_l-1-0,
/** b2:0 */	b2_p+b_l-1-0,
/** b3:0 */	b3_p+b_l-1-0,
/** b4:0 */	b4_p+b_l-1-0,
/** Xmax1:2 */	Xmax1_p+Xmax_l-1-2,
/** Xmax2:2 */	Xmax2_p+Xmax_l-1-2,
/** Xmax3:2 */	Xmax3_p+Xmax_l-1-2,
/** Xmax4:2 */	Xmax4_p+Xmax_l-1-2,
/** x1_0:2 */	x1_0_p+x_l-1-2,
/** x1_1:2 */	x1_1_p+x_l-1-2,		/* bit 80 */
/** x1_2:2 */	x1_2_p+x_l-1-2,
/** x1_3:2 */	x1_3_p+x_l-1-2,
/** x1_4:2 */	x1_4_p+x_l-1-2,
/** x1_5:2 */	x1_5_p+x_l-1-2,
/** x1_6:2 */	x1_6_p+x_l-1-2,
/** x1_7:2 */	x1_7_p+x_l-1-2,
/** x1_8:2 */	x1_8_p+x_l-1-2,
/** x1_9:2 */	x1_9_p+x_l-1-2,
/** x1_10:2 */	x1_10_p+x_l-1-2,
/** x1_11:2 */	x1_11_p+x_l-1-2,		/* bit 90 */
/** x1_12:2 */	x1_12_p+x_l-1-2,
/** x2_0:2 */	x2_0_p+x_l-1-2,
/** x2_1:2 */	x2_1_p+x_l-1-2,
/** x2_2:2 */	x2_2_p+x_l-1-2,
/** x2_3:2 */	x2_3_p+x_l-1-2,
/** x2_4:2 */	x2_4_p+x_l-1-2,
/** x2_5:2 */	x2_5_p+x_l-1-2,
/** x2_6:2 */	x2_6_p+x_l-1-2,
/** x2_7:2 */	x2_7_p+x_l-1-2,
/** x2_8:2 */	x2_8_p+x_l-1-2,		/* bit 100 */
/** x2_9:2 */	x2_9_p+x_l-1-2,
/** x2_10:2 */	x2_10_p+x_l-1-2,
/** x2_11:2 */	x2_11_p+x_l-1-2,
/** x2_12:2 */	x2_12_p+x_l-1-2,
/** x3_0:2 */	x3_0_p+x_l-1-2,
/** x3_1:2 */	x3_1_p+x_l-1-2,
/** x3_2:2 */	x3_2_p+x_l-1-2,
/** x3_3:2 */	x3_3_p+x_l-1-2,
/** x3_4:2 */	x3_4_p+x_l-1-2,
/** x3_5:2 */	x3_5_p+x_l-1-2,		/* bit 110 */
/** x3_6:2 */	x3_6_p+x_l-1-2,
/** x3_7:2 */	x3_7_p+x_l-1-2,
/** x3_8:2 */	x3_8_p+x_l-1-2,
/** x3_9:2 */	x3_9_p+x_l-1-2,
/** x3_10:2 */	x3_10_p+x_l-1-2,
/** x3_11:2 */	x3_11_p+x_l-1-2,
/** x3_12:2 */	x3_12_p+x_l-1-2,
/** x4_0:2 */	x4_0_p+x_l-1-2,
/** x4_1:2 */	x4_1_p+x_l-1-2,
/** x4_2:2 */	x4_2_p+x_l-1-2,		/* bit 120 */
/** x4_3:2 */	x4_3_p+x_l-1-2,
/** x4_4:2 */	x4_4_p+x_l-1-2,
/** x4_5:2 */	x4_5_p+x_l-1-2,
/** x4_6:2 */	x4_6_p+x_l-1-2,
/** x4_7:2 */	x4_7_p+x_l-1-2,
/** x4_8:2 */	x4_8_p+x_l-1-2,
/** x4_9:2 */	x4_9_p+x_l-1-2,
/** x4_10:2 */	x4_10_p+x_l-1-2,
/** x4_11:2 */	x4_11_p+x_l-1-2,
/** x4_12:2 */	x4_12_p+x_l-1-2,		/* bit 130 */
/** M1:0 */	M1_p+M_l-1-0,
/** M2:0 */	M2_p+M_l-1-0,
/** M3:0 */	M3_p+M_l-1-0,
/** M4:0 */	M4_p+M_l-1-0,
/** Xmax1:1 */	Xmax1_p+Xmax_l-1-1,
/** Xmax2:1 */	Xmax2_p+Xmax_l-1-1,
/** Xmax3:1 */	Xmax3_p+Xmax_l-1-1,
/** Xmax4:1 */	Xmax4_p+Xmax_l-1-1,
/** x1_0:1 */	x1_0_p+x_l-1-1,
/** x1_1:1 */	x1_1_p+x_l-1-1,		/* bit 140 */
/** x1_2:1 */	x1_2_p+x_l-1-1,
/** x1_3:1 */	x1_3_p+x_l-1-1,
/** x1_4:1 */	x1_4_p+x_l-1-1,
/** x1_5:1 */	x1_5_p+x_l-1-1,
/** x1_6:1 */	x1_6_p+x_l-1-1,
/** x1_7:1 */	x1_7_p+x_l-1-1,
/** x1_8:1 */	x1_8_p+x_l-1-1,
/** x1_9:1 */	x1_9_p+x_l-1-1,
/** x1_10:1 */	x1_10_p+x_l-1-1,
/** x1_11:1 */	x1_11_p+x_l-1-1,		/* bit 150 */
/** x1_12:1 */	x1_12_p+x_l-1-1,
/** x2_0:1 */	x2_0_p+x_l-1-1,
/** x2_1:1 */	x2_1_p+x_l-1-1,
/** x2_2:1 */	x2_2_p+x_l-1-1,
/** x2_3:1 */	x2_3_p+x_l-1-1,
/** x2_4:1 */	x2_4_p+x_l-1-1,
/** x2_5:1 */	x2_5_p+x_l-1-1,
/** x2_6:1 */	x2_6_p+x_l-1-1,
/** x2_7:1 */	x2_7_p+x_l-1-1,
/** x2_8:1 */	x2_8_p+x_l-1-1,		/* bit 160 */
/** x2_9:1 */	x2_9_p+x_l-1-1,
/** x2_10:1 */	x2_10_p+x_l-1-1,
/** x2_11:1 */	x2_11_p+x_l-1-1,
/** x2_12:1 */	x2_12_p+x_l-1-1,
/** x3_0:1 */	x3_0_p+x_l-1-1,
/** x3_1:1 */	x3_1_p+x_l-1-1,
/** x3_2:1 */	x3_2_p+x_l-1-1,
/** x3_3:1 */	x3_3_p+x_l-1-1,
/** x3_4:1 */	x3_4_p+x_l-1-1,
/** x3_5:1 */	x3_5_p+x_l-1-1,		/* bit 170 */
/** x3_6:1 */	x3_6_p+x_l-1-1,
/** x3_7:1 */	x3_7_p+x_l-1-1,
/** x3_8:1 */	x3_8_p+x_l-1-1,
/** x3_9:1 */	x3_9_p+x_l-1-1,
/** x3_10:1 */	x3_10_p+x_l-1-1,
/** x3_11:1 */	x3_11_p+x_l-1-1,
/** x3_12:1 */	x3_12_p+x_l-1-1,
/** x4_0:1 */	x4_0_p+x_l-1-1,
/** x4_1:1 */	x4_1_p+x_l-1-1,
/** x4_2:1 */	x4_2_p+x_l-1-1,		/* bit 180 */
/** x4_3:1 */	x4_3_p+x_l-1-1,
//@}
/**@name importance class 6 */
//@{
/** x4_4:1 */	x4_4_p+x_l-1-1,
/** x4_5:1 */	x4_5_p+x_l-1-1,
/** x4_6:1 */	x4_6_p+x_l-1-1,
/** x4_7:1 */	x4_7_p+x_l-1-1,
/** x4_8:1 */	x4_8_p+x_l-1-1,
/** x4_9:1 */	x4_9_p+x_l-1-1,
/** x4_10:1 */	x4_10_p+x_l-1-1,
/** x4_11:1 */	x4_11_p+x_l-1-1,
/** x4_12:1 */	x4_12_p+x_l-1-1,		/* bit 190 */
/** LAR1:0 */	LAR1_p+LAR1_l-1-0,
/** LAR2:1 */	LAR2_p+LAR2_l-1-1,
/** LAR3:1 */	LAR3_p+LAR3_l-1-1,
/** LAR6:1 */	LAR6_p+LAR6_l-1-1,
/** LAR7:0 */	LAR7_p+LAR7_l-1-0,
/** LAR8:1 */	LAR8_p+LAR8_l-1-1,
/** LAR8:0 */	LAR8_p+LAR8_l-1-0,
/** LAR3:0 */	LAR3_p+LAR3_l-1-0,
/** LAR4:1 */	LAR4_p+LAR4_l-1-1,
/** LAR4:0 */	LAR4_p+LAR4_l-1-0,
/** LAR5:0 */	LAR5_p+LAR5_l-1-0,
/** Xmax1:0 */	Xmax1_p+Xmax_l-1-0,
/** Xmax2:0 */	Xmax2_p+Xmax_l-1-0,
/** Xmax3:0 */	Xmax3_p+Xmax_l-1-0,
/** Xmax4:0 */	Xmax4_p+Xmax_l-1-0,
/** x1_0:0 */	x1_0_p+x_l-1-0,
/** x1_1:0 */	x1_1_p+x_l-1-0,
/** x1_2:0 */	x1_2_p+x_l-1-0,
/** x1_3:0 */	x1_3_p+x_l-1-0,
/** x1_4:0 */	x1_4_p+x_l-1-0,
/** x1_5:0 */	x1_5_p+x_l-1-0,
/** x1_6:0 */	x1_6_p+x_l-1-0,
/** x1_7:0 */	x1_7_p+x_l-1-0,
/** x1_8:0 */	x1_8_p+x_l-1-0,
/** x1_9:0 */	x1_9_p+x_l-1-0,
/** x1_10:0 */	x1_10_p+x_l-1-0,
/** x1_11:0 */	x1_11_p+x_l-1-0,
/** x1_12:0 */	x1_12_p+x_l-1-0,
/** x2_0:0 */	x2_0_p+x_l-1-0,
/** x2_1:0 */	x2_1_p+x_l-1-0,
/** x2_2:0 */	x2_2_p+x_l-1-0,
/** x2_3:0 */	x2_3_p+x_l-1-0,
/** x2_4:0 */	x2_4_p+x_l-1-0,
/** x2_5:0 */	x2_5_p+x_l-1-0,
/** x2_6:0 */	x2_6_p+x_l-1-0,
/** x2_7:0 */	x2_7_p+x_l-1-0,
/** x2_8:0 */	x2_8_p+x_l-1-0,
/** x2_9:0 */	x2_9_p+x_l-1-0,
/** x2_10:0 */	x2_10_p+x_l-1-0,
/** x2_11:0 */	x2_11_p+x_l-1-0,
/** x2_12:0 */	x2_12_p+x_l-1-0,
/** x3_0:0 */	x3_0_p+x_l-1-0,
/** x3_1:0 */	x3_1_p+x_l-1-0,
/** x3_2:0 */	x3_2_p+x_l-1-0,
/** x3_3:0 */	x3_3_p+x_l-1-0,
/** x3_4:0 */	x3_4_p+x_l-1-0,
/** x3_5:0 */	x3_5_p+x_l-1-0,
/** x3_6:0 */	x3_6_p+x_l-1-0,
/** x3_7:0 */	x3_7_p+x_l-1-0,
/** x3_8:0 */	x3_8_p+x_l-1-0,
/** x3_9:0 */	x3_9_p+x_l-1-0,
/** x3_10:0 */	x3_10_p+x_l-1-0,
/** x3_11:0 */	x3_11_p+x_l-1-0,
/** x3_12:0 */	x3_12_p+x_l-1-0,
/** x4_0:0 */	x4_0_p+x_l-1-0,
/** x4_1:0 */	x4_1_p+x_l-1-0,
/** x4_2:0 */	x4_2_p+x_l-1-0,
/** x4_3:0 */	x4_3_p+x_l-1-0,
/** x4_4:0 */	x4_4_p+x_l-1-0,
/** x4_5:0 */	x4_5_p+x_l-1-0,
/** x4_6:0 */	x4_6_p+x_l-1-0,
/** x4_7:0 */	x4_7_p+x_l-1-0,
/** x4_8:0 */	x4_8_p+x_l-1-0,
/** x4_9:0 */	x4_9_p+x_l-1-0,
/** x4_10:0 */	x4_10_p+x_l-1-0,
/** x4_11:0 */	x4_11_p+x_l-1-0,
/** x4_12:0 */	x4_12_p+x_l-1-0,
/** LAR2:0 */	LAR2_p+LAR2_l-1-0,
/** LAR6:0 */	LAR6_p+LAR6_l-1-0
//@}
};

