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




#include "BitVector.h"
#include "ViterbiR204.h"
#include <iostream>
#include <stdio.h>
#include <sstream>
#include <string.h>
#include <cstdlib>

using namespace std;


/**
  Apply a Galois polymonial to a binary seqeunce.
  @param val The input sequence.
  @param poly The polynomial.
  @param order The order of the polynomial.
  @return Single-bit result.
*/
unsigned ViterbiBase::applyPoly(uint64_t val, uint64_t poly, unsigned order)
{
	uint64_t prod = val & poly;
	unsigned sum = prod;
	for (unsigned i=1; i<order; i++) sum ^= prod>>i;
	return sum & 0x01;
}

unsigned ViterbiBase::applyPoly(uint64_t val, uint64_t poly)
{
	uint64_t prod = val & poly;
	prod = (prod ^ (prod >> 32));
	prod = (prod ^ (prod >> 16));
	prod = (prod ^ (prod >> 8));
	prod = (prod ^ (prod >> 4));
	prod = (prod ^ (prod >> 2));
	prod = (prod ^ (prod >> 1));
	return prod & 0x01;
}



//void BitVector::encode(const ViterbiR2O4& coder, BitVector& target)
void ViterbiR2O4::encode(const BitVector& in, BitVector& target) const
{
	const ViterbiR2O4& coder = *this;
	size_t sz = in.size();

	assert(sz*coder.iRate() == target.size());

	// Build a "history" array where each element contains the full history.
	uint32_t * history = (uint32_t *) malloc(sizeof(uint32_t)*sz);
	uint32_t accum = 0;
	for (size_t i=0; i<sz; i++) {
		accum = (accum<<1) | in.bit(i);
		history[i] = accum;
	}

	// Look up histories in the pre-generated state table.
	char *op = target.begin();
	for (size_t i=0; i<sz; i++) {
		unsigned index = coder.cMask() & history[i];
		for (unsigned g=0; g<coder.iRate(); g++) {
			*op++ = coder.stateTable(g,index);
		}
	}
	free(history);
}


ViterbiR2O4::ViterbiR2O4()
{
	assert(mDeferral < 32);
	// (pat) The generator polynomials are: G0 = 1 + D**3 + D**4; and G1 = 1 + D + D**3 + D**4
	mCoeffs[0] = 0x019;     // G0 = D**4 + D**3 + 1; represented as binary 11001,
	mCoeffs[1] = 0x01b;     // G1 = + D**4 + D**3 + D + 1; represented as binary 11011
	computeStateTables(0);
	computeStateTables(1);
	computeGeneratorTable();
}


void ViterbiR2O4::initializeStates()
{
	for (unsigned i=0; i<mIStates; i++) vitClear(mSurvivors[i]);
	for (unsigned i=0; i<mNumCands; i++) vitClear(mCandidates[i]);
}



// (pat) The state machine has 16 states.
// Each state has two possible next states corresponding to 0 or 1 inputs to original encoder.
// which are saved in mStateTable in consecutive locations.
// In other words the mStateTable second index is ((current_state <<1) + encoder_bit)
// g is 0 or 1 for the first or second bit of the encoded stream, ie, the one we are decoding.
void ViterbiR2O4::computeStateTables(unsigned g)
{
	assert(g<mIRate);
	for (unsigned state=0; state<mIStates; state++) {
		// 0 input
		uint32_t inputVal = state<<1;
		mStateTable[g][inputVal] = applyPoly(inputVal, mCoeffs[g], mOrder+1);
		// 1 input
		inputVal |= 1;
		mStateTable[g][inputVal] = applyPoly(inputVal, mCoeffs[g], mOrder+1);
	}
}

void ViterbiR2O4::computeGeneratorTable()
{
	for (unsigned index=0; index<mIStates*2; index++) {
		mGeneratorTable[index] = (mStateTable[0][index]<<1) | mStateTable[1][index];
	}
}


void ViterbiR2O4::branchCandidates()
{
	// Branch to generate new input states.
	const vCand *sp = mSurvivors;
	for (unsigned i=0; i<mNumCands; i+=2) {
		// extend and suffix
		const uint32_t iState0 = (sp->iState) << 1;				// input state for 0
		const uint32_t iState1 = iState0 | 0x01;				// input state for 1
		const uint32_t oStateShifted = (sp->oState) << mIRate;	// shifted output (by 2)
		const float cost = sp->cost;
		int bec = sp->bitErrorCnt;
		sp++;
		// 0 input extension
		mCandidates[i].cost = cost;
		// mCMask is the low 5 bits, ie, full width of mGeneratorTable.
		mCandidates[i].oState = oStateShifted | mGeneratorTable[iState0 & mCMask];
		mCandidates[i].iState = iState0;
		mCandidates[i].bitErrorCnt = bec;
		// 1 input extension
		mCandidates[i+1].cost = cost;
		mCandidates[i+1].oState = oStateShifted | mGeneratorTable[iState1 & mCMask];
		mCandidates[i+1].iState = iState1;
		mCandidates[i+1].bitErrorCnt = bec;
	}
}


void ViterbiR2O4::getSoftCostMetrics(const uint32_t inSample, const float *matchCost, const float *mismatchCost)
{
	const float *cTab[2] = {matchCost,mismatchCost};
	for (unsigned i=0; i<mNumCands; i++) {
		vCand& thisCand = mCandidates[i];
		// We examine input bits 2 at a time for a rate 1/2 coder.
		// (pat) mismatched will end up with bits in it for previous transitions,
		// but we only use the bottom two bits of mismatched so it is ok.
		const unsigned mismatched = inSample ^ (thisCand.oState);
		// (pat) TODO: Are these two tests swapped?
		thisCand.cost += cTab[mismatched&0x01][1] + cTab[(mismatched>>1)&0x01][0];
		if (mismatched & 1) { thisCand.bitErrorCnt++; }
		if (mismatched & 2) { thisCand.bitErrorCnt++; }
	}
}


void ViterbiR2O4::pruneCandidates()
{
	const vCand* c1 = mCandidates;					// 0-prefix
	const vCand* c2 = mCandidates + mIStates;		// 1-prefix
	for (unsigned i=0; i<mIStates; i++) {
		if (c1[i].cost < c2[i].cost) mSurvivors[i] = c1[i];
		else mSurvivors[i] = c2[i];
	}
}


const ViterbiR2O4::vCand& ViterbiR2O4::minCost() const
{
	int minIndex = 0;
	float minCost = mSurvivors[0].cost;
	for (unsigned i=1; i<mIStates; i++) {
		const float thisCost = mSurvivors[i].cost;
		if (thisCost>=minCost) continue;
		minCost = thisCost;
		minIndex=i;
	}
	return mSurvivors[minIndex];
}


const ViterbiR2O4::vCand* ViterbiR2O4::vstep(uint32_t inSample, const float *probs, const float *iprobs, bool isNotTailBits)
{
	branchCandidates();
	// (pat) tail bits do not affect cost or error bit count of any branch.
	if (isNotTailBits) getSoftCostMetrics(inSample,probs,iprobs);
	pruneCandidates();
	return &minCost();
}


void ViterbiR2O4::decode(const SoftVector &in, BitVector& target)
{
	ViterbiR2O4& decoder = *this;
	const size_t sz = in.size();
	const unsigned oSize = in.size() / decoder.iRate();
	const unsigned deferral = decoder.deferral();
	const size_t ctsz = sz + deferral*decoder.iRate();
	assert(sz <= decoder.iRate()*target.size());

	// Build a "history" array where each element contains the full history.
	// (pat) We only use every other history element, so why are we setting them?
	uint32_t * history = (uint32_t *)malloc(sizeof(uint32_t)*ctsz);
	{
		BitVector bits = in.sliced();
		uint32_t accum = 0;
		for (size_t i=0; i<sz; i++) {
			accum = (accum<<1) | bits.bit(i);
			history[i] = accum;
		}
		// Repeat last bit at the end.
		// (pat) TODO: really?  Does this matter?
		for (size_t i=sz; i<ctsz; i++) {
			accum = (accum<<1) | (accum & 0x01);
			history[i] = accum;
		}
	}

	// Precompute metric tables.
	float * matchCostTable = (float *)malloc(sizeof(float)*ctsz);
	float * mismatchCostTable = (float *)malloc(sizeof(float)*ctsz);
	{
		const float *dp = in.begin();
		for (size_t i=0; i<sz; i++) {
			// pVal is the probability that a bit is correct.
			// ipVal is the probability that a bit is incorrect.
			float pVal = dp[i];
			if (pVal>0.5F) pVal = 1.0F-pVal;
			float ipVal = 1.0F-pVal;
			// This is a cheap approximation to an ideal cost function.
			if (pVal<0.01F) pVal = 0.01;
			if (ipVal<0.01F) ipVal = 0.01;
			matchCostTable[i] = 0.25F/ipVal;
			mismatchCostTable[i] = 0.25F/pVal;
		}
	
		// pad end of table with unknowns
		// Note that these bits should not contribute to Bit Error Count.
		for (size_t i=sz; i<ctsz; i++) {
			matchCostTable[i] = 0.5F;
			mismatchCostTable[i] = 0.5F;
		}
	}

	{
		decoder.initializeStates();
		// Each sample of history[] carries its history.
		// So we only have to process every iRate-th sample.
		const unsigned step = decoder.iRate();
		// input pointer
		const uint32_t *ip = history + step - 1;
		// output pointers
		char *op = target.begin();
		const char *const opt = target.end();	// (pat) Not right if target is larger than needed; should be: op + sz/2;
		// table pointers
		const float* match = matchCostTable;
		const float* mismatch = mismatchCostTable;
		size_t oCount = 0;
		const ViterbiR2O4::vCand *minCost = NULL;
		while (op<opt) {
			// Viterbi algorithm
			assert(match - matchCostTable < ctsz - 1);
			assert(mismatch - mismatchCostTable < ctsz - 1);
			minCost = decoder.vstep(*ip, match, mismatch, oCount < oSize);
			ip += step;
			match += step;
			mismatch += step;
			// output
			if (oCount>=deferral) *op++ = (minCost->iState >> deferral)&0x01;
			oCount++;
		}
		// Dont think minCost == NULL can happen.
		mBitErrorCnt = minCost ? minCost->bitErrorCnt : 0;
	}
	free(history);
	free(matchCostTable);
	free(mismatchCostTable);
}

// vim: ts=4 sw=4
