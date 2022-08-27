/*
 * Copyright 2013, 2014 Range Networks, Inc.
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


#ifndef _VITERBI_H_
#define _VITERBI_H_ 1

// (pat) Virtual base class for Viterbi and Turbo coder/decoders.
class ViterbiBase {
	public:
	virtual void encode(const BitVector &in, BitVector& target) const = 0;
	virtual void decode(const SoftVector &in, BitVector& target) = 0;
	// (pat) Return error count from most recent decoder run.
	// If you get -1 from this, the method is not defined in the Viterbi class.
	virtual int getBEC() { return -1; }
	//virtual ~ViterbiBase();   Currently None of these have destructors.

	// These functions are logically part of the Viterbi functionality, even though they do not use any class variables.
	unsigned applyPoly(uint64_t val, uint64_t poly);
	unsigned applyPoly(uint64_t val, uint64_t poly, unsigned order);
};
#endif
