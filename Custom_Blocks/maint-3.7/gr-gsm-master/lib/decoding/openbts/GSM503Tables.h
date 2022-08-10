/*
 * Copyright 2012, 2014 Range Networks, Inc.
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

#ifndef GSM503TABLES_H
#define GSM503TABLES_H



namespace GSM {

// don't change the positions in this enum
// (pat) The first 8 values are used as indicies into numerous tables.
// (pat) Encoder/decoder mode includes 8 modes for AMR + TCH_FS makes 9.
// TODO: Add AFS_SID type.  And why is it not type 8?
enum AMRMode {TCH_AFS12_2, TCH_AFS10_2, TCH_AFS7_95, TCH_AFS7_4, TCH_AFS6_7, TCH_AFS5_9, TCH_AFS5_15, TCH_AFS4_75, TCH_FS};

/** Tables #7-14 from GSM 05.03 */
extern const unsigned int gAMRBitOrderTCH_AFS12_2[244];
extern const unsigned int gAMRBitOrderTCH_AFS10_2[204];
extern const unsigned int gAMRBitOrderTCH_AFS7_95[159];
extern const unsigned int gAMRBitOrderTCH_AFS7_4[148];
extern const unsigned int gAMRBitOrderTCH_AFS6_7[134];
extern const unsigned int gAMRBitOrderTCH_AFS5_9[118];
extern const unsigned int gAMRBitOrderTCH_AFS5_15[103];
extern const unsigned int gAMRBitOrderTCH_AFS4_75[95];

/** GSM 05.03 3.9.4.4 */
extern const unsigned int gAMRPuncturedTCH_AFS12_2[60];
extern const unsigned int gAMRPuncturedTCH_AFS10_2[194];
extern const unsigned int gAMRPuncturedTCH_AFS7_95[65];
extern const unsigned int gAMRPuncturedTCH_AFS7_4[26];
extern const unsigned int gAMRPuncturedTCH_AFS6_7[128];
extern const unsigned int gAMRPuncturedTCH_AFS5_9[72];
extern const unsigned int gAMRPuncturedTCH_AFS5_15[117];
extern const unsigned int gAMRPuncturedTCH_AFS4_75[87];

/* GSM 05.03 Tables 7-14 */
extern const unsigned *gAMRBitOrder[8];

/* GSM 05.03 3.9.4.2 */
extern const unsigned gAMRKd[9];

/* GSM 05.03 3.9.4.2 */
extern const unsigned gAMRClass1ALth[8];

/* GSM 05.03 3.9.4.4 */
extern const unsigned gAMRTCHUCLth[8];

/* GSM 05.03 3.9.4.2 */
extern const unsigned gAMRPunctureLth[8];

/* GSM 05.03 3.9.4.4 */
extern const unsigned *gAMRPuncture[8];

}


#endif
