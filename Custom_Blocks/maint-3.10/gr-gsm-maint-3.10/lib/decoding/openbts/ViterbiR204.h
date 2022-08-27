/*
 * Copyright 2008, 2009, 2014 Free Software Foundation, Inc.
 * Copyright 2014 Range Networks, Inc.
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

#ifndef _VITERBIR204_H_
#define _VITERBIR204_H_ 1

#include "Viterbi.h"


/**
	Class to represent convolutional coders/decoders of rate 1/2, memory length 4.
	This is the "workhorse" coder for most GSM channels.
*/
class ViterbiR2O4 : public ViterbiBase {

	private:
		/**name Lots of precomputed elements so the compiler can optimize like hell. */
		//@{
		/**@name Core values. */
		//@{
		static const unsigned mIRate = 2;	///< reciprocal of rate
		static const unsigned mOrder = 4;	///< memory length of generators
		//@}
		/**@name Derived values. */
		//@{
		static const unsigned mIStates = 0x01 << mOrder;	///< (16) number of states, number of survivors
		static const uint32_t mSMask = mIStates-1;			///< survivor mask
		static const uint32_t mCMask = (mSMask<<1) | 0x01;	///< candidate mask
		static const uint32_t mOMask = (0x01<<mIRate)-1;	///< ouput mask, all iRate low bits set
		static const unsigned mNumCands = mIStates*2;		///< number of candidates to generate during branching
		static const unsigned mDeferral = 6*mOrder;			///< deferral to be used
		//@}
		//@}

		/** Precomputed tables. */
		//@{
		uint32_t mCoeffs[mIRate];					///< polynomial for each generator
		// (pat) There are 16 states, each of which has two possible output states.
		// These are stored in these two tables in consecutive locations.
		uint32_t mStateTable[mIRate][2*mIStates];	///< precomputed generator output tables
		// mGeneratorTable is the encoder output state for a given input state and encoder input bit.
		uint32_t mGeneratorTable[2*mIStates];		///< precomputed coder output table
		//@}
		int mBitErrorCnt;
	
	public:

		/**
		  A candidate sequence in a Viterbi decoder.
		  The 32-bit state register can support a deferral of 6 with a 4th-order coder.
		 */
		typedef struct candStruct {
			uint32_t iState;	///< encoder input associated with this candidate
			uint32_t oState;	///< encoder output associated with this candidate
			float cost;			///< cost (metric value), float to support soft inputs
			int bitErrorCnt;	///< number of bit errors in the encoded vector being decoded.
		} vCand;

		/** Clear a structure. */
		void vitClear(vCand& v)
		{
			v.iState=0;
			v.oState=0;
			v.cost=0;
			v.bitErrorCnt = 0;
		}
		

	private:

		/**@name Survivors and candidates. */
		//@{
		vCand mSurvivors[mIStates];			///< current survivor pool
		vCand mCandidates[2*mIStates];		///< current candidate pool
		//@}

	public:

		unsigned iRate() const { return mIRate; }
		uint32_t cMask() const { return mCMask; }
		uint32_t stateTable(unsigned g, unsigned i) const { return mStateTable[g][i]; }
		unsigned deferral() const { return mDeferral; }
		

		ViterbiR2O4();

		/** Set all cost metrics to zero. */
		void initializeStates();

		/**
			Full cycle of the Viterbi algorithm: branch, metrics, prune, select.
			@return reference to minimum-cost candidate.
		*/
		const vCand* vstep(uint32_t inSample, const float *probs, const float *iprobs, bool isNotTailBits);

	private:

		/** Branch survivors into new candidates. */
		void branchCandidates();

		/** Compute cost metrics for soft-inputs. */
		void getSoftCostMetrics(uint32_t inSample, const float *probs, const float *iprobs);

		/** Select survivors from the candidate set. */
		void pruneCandidates();

		/** Find the minimum cost survivor. */
		const vCand& minCost() const;

		/**
			Precompute the state tables.
			@param g Generator index 0..((1/rate)-1)
		*/
		void computeStateTables(unsigned g);

		/**
			Precompute the generator outputs.
			mCoeffs must be defined first.
		*/
		void computeGeneratorTable();

	public:
		void encode(const BitVector &in, BitVector& target) const;
		void decode(const SoftVector &in, BitVector& target);
		int getBEC() { return mBitErrorCnt; }
};
#endif
