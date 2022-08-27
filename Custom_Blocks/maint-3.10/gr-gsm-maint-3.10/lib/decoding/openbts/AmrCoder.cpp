/*
 * Copyright 2013, 2014 Range Networks, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.

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
#include "AmrCoder.h"
#include <iostream>
#include <stdio.h>
#include <sstream>
#include <cstdlib>

using namespace std;

ViterbiTCH_AFS12_2::ViterbiTCH_AFS12_2()
{
	assert(mDeferral < 32);
	mCoeffs[0] = 0x019;
	mCoeffsFB[0] = 0x019;
	mCoeffs[1] = 0x01b;
	mCoeffsFB[1] = 0x019;
	for (unsigned i = 0; i < mIRate; i++) {
		computeStateTables(i);
	}
	computeGeneratorTable();
}


//void BitVector::encode(const ViterbiTCH_AFS12_2& coder, BitVector& target) const
void ViterbiTCH_AFS12_2::encode(const BitVector& in, BitVector& target) const
{
	assert(in.size() == 250);
	assert(target.size() == 508);
	const char *u = in.begin();
	char *C = target.begin();
	const unsigned H = 4;
	BitVector r(254+H);
	for (int k = -H; k <= -1; k++) r[k+H] = 0;
	for (unsigned k = 0; k <= 249; k++) {
		r[k+H] = u[k] ^ r[k-3+H] ^ r[k-4+H];
		C[2*k] = u[k];
		C[2*k+1] = r[k+H] ^ r[k-1+H] ^ r[k-3+H] ^ r[k-4+H];
	}
	// termination
	for (unsigned k = 250; k <= 253; k++) {
		r[k+H] = 0;
		C[2*k] = r[k-3+H] ^ r[k-4+H];
		C[2*k+1] = r[k+H] ^ r[k-1+H] ^ r[k-3+H] ^ r[k-4+H];
	}
}



//void BitVector::encode(const ViterbiTCH_AFS10_2& coder, BitVector& target)
void ViterbiTCH_AFS10_2::encode(const BitVector& in, BitVector& target) const
{
	assert(in.size() == 210);
	assert(target.size() == 642);
	const char *u = in.begin();
	char *C = target.begin();
	const unsigned H = 4;
	BitVector r(214+H);
	for (int k = -H; k <= -1; k++) r[k+H] = 0;
	for (unsigned k = 0; k <= 209; k++) {
		r[k+H] = u[k] ^ r[k-1+H] ^ r[k-2+H] ^ r[k-3+H] ^ r[k-4+H];
		C[3*k] = r[k+H] ^ r[k-1+H] ^ r[k-3+H] ^ r[k-4+H];
		C[3*k+1] = r[k+H] ^ r[k-2+H] ^ r[k-4+H];
		C[3*k+2] = u[k];
	}
	// termination
	for (unsigned k = 210; k <= 213; k++) {
		r[k+H] = 0;
		C[3*k] = r[k+H] ^ r[k-1+H] ^ r[k-3+H] ^ r[k-4+H];
		C[3*k+1] = r[k+H] ^ r[k-2+H] ^ r[k-4+H];
		C[3*k+2] = r[k-1+H] ^ r[k-2+H] ^ r[k-3+H] ^ r[k-4+H];
	}
}



//void BitVector::encode(const ViterbiTCH_AFS7_95& coder, BitVector& target)
void ViterbiTCH_AFS7_95::encode(const BitVector& in, BitVector& target) const
{
	assert(in.size() == 165);
	assert(target.size() == 513);
	const char *u = in.begin();
	char *C = target.begin();
	const unsigned H = 6;
	BitVector r(171+H);
	for (int k = -H; k <= -1; k++) r[k+H] = 0;
	for (unsigned k = 0; k <= 164; k++) {
		r[k+H] = u[k] ^ r[k-2+H] ^ r[k-3+H] ^ r[k-5+H] ^ r[k-6+H];
		C[3*k] = u[k];
		C[3*k+1] = r[k+H] ^ r[k-1+H] ^ r[k-4+H] ^ r[k-6+H];
		C[3*k+2] = r[k+H] ^ r[k-1+H] ^ r[k-2+H] ^ r[k-3+H] ^ r[k-4+H] ^ r[k-6+H];
	}
	// termination
	for (unsigned k = 165; k <= 170; k++) {
		r[k+H] = 0;
		C[3*k] = r[k-2+H] ^ r[k-3+H] ^ r[k-5+H] ^ r[k-6+H];
		C[3*k+1] = r[k+H] ^ r[k-1+H] ^ r[k-4+H] ^ r[k-6+H];
		C[3*k+2] = r[k+H] ^ r[k-1+H] ^ r[k-2+H] ^ r[k-3+H] ^ r[k-4+H] ^ r[k-6+H];
	}
}



void ViterbiTCH_AFS7_4::encode(const BitVector& in, BitVector& target) const
{
	assert(in.size() == 154);
	assert(target.size() == 474);
	const char *u = in.begin();
	char *C = target.begin();
	const unsigned H = 4;
	BitVector r(158+H);
	for (int k = -H; k <= -1; k++) r[k+H] = 0;
	for (unsigned k = 0; k <= 153; k++) {
		r[k+H] = u[k] ^ r[k-1+H] ^ r[k-2+H] ^ r[k-3+H] ^ r[k-4+H];
		C[3*k] = r[k+H] ^ r[k-1+H] ^ r[k-3+H] ^ r[k-4+H];
		C[3*k+1] = r[k+H] ^ r[k-2+H] ^ r[k-4+H];
		C[3*k+2] = u[k];
	}
	// termination
	for (unsigned k = 154; k <= 157; k++) {
		r[k+H] = 0;
		C[3*k] = r[k+H] ^ r[k-1+H] ^ r[k-3+H] ^ r[k-4+H];
		C[3*k+1] = r[k+H] ^ r[k-2+H] ^ r[k-4+H];
		C[3*k+2] = r[k-1+H] ^ r[k-2+H] ^ r[k-3+H] ^ r[k-4+H];
	}
}



void ViterbiTCH_AFS6_7::encode(const BitVector& in, BitVector& target) const
{
	assert(in.size() == 140);
	assert(target.size() == 576);
	const char *u = in.begin();
	char *C = target.begin();
	const unsigned H = 4;
	BitVector r(144+H);
	for (int k = -H; k <= -1; k++) r[k+H] = 0;
	for (unsigned k = 0; k <= 139; k++) {
		r[k+H] = u[k] ^ r[k-1+H] ^ r[k-2+H] ^ r[k-3+H] ^ r[k-4+H];
		C[4*k] = r[k+H] ^ r[k-1+H] ^ r[k-3+H] ^ r[k-4+H];
		C[4*k+1] = r[k+H] ^ r[k-2+H] ^ r[k-4+H];
		C[4*k+2] = u[k];
		C[4*k+3] = u[k];
	}
	// termination
	for (unsigned k = 140; k <= 143; k++) {
		r[k+H] = 0;
		C[4*k] = r[k+H] ^ r[k-1+H] ^ r[k-3+H] ^ r[k-4+H];
		C[4*k+1] = r[k+H] ^ r[k-2+H] ^ r[k-4+H];
		C[4*k+2] = r[k-1+H] ^ r[k-2+H] ^ r[k-3+H] ^ r[k-4+H];
		C[4*k+3] = r[k-1+H] ^ r[k-2+H] ^ r[k-3+H] ^ r[k-4+H];
	}
}



void ViterbiTCH_AFS5_9::encode(const BitVector& in, BitVector& target) const
{
	assert(in.size() == 124);
	assert(target.size() == 520);
	const char *u = in.begin();
	char *C = target.begin();
	const unsigned H = 6;
	BitVector r(130+H);
	for (int k = -H; k <= -1; k++) r[k+H] = 0;
	for (unsigned k = 0; k <= 123; k++) {
		r[k+H] = u[k] ^ r[k-1+H] ^ r[k-2+H] ^ r[k-3+H] ^ r[k-4+H] ^ r[k-6+H];
		C[4*k] = r[k+H] ^ r[k-2+H] ^ r[k-3+H] ^ r[k-5+H] ^ r[k-6+H];
		C[4*k+1] = r[k+H] ^ r[k-1+H] ^ r[k-4+H] ^ r[k-6+H];
		C[4*k+2] = u[k];
		C[4*k+3] = u[k];
	}
	// termination
	for (unsigned k = 124; k <= 129; k++) {
		r[k+H] = 0;
		C[4*k] = r[k+H] ^ r[k-2+H] ^ r[k-3+H] ^ r[k-5+H] ^ r[k-6+H];
		C[4*k+1] = r[k+H] ^ r[k-1+H] ^ r[k-4+H] ^ r[k-6+H];
		C[4*k+2] = r[k-1+H] ^ r[k-2+H] ^ r[k-3+H] ^ r[k-4+H] ^ r[k-6+H];
		C[4*k+3] = r[k-1+H] ^ r[k-2+H] ^ r[k-3+H] ^ r[k-4+H] ^ r[k-6+H];
	}
}



void ViterbiTCH_AFS5_15::encode(const BitVector& in, BitVector& target) const
{
	assert(in.size() == 109);
	assert(target.size() == 565);
	const char *u = in.begin();
	char *C = target.begin();
	const unsigned H = 4;
	BitVector r(113+H);
	for (int k = -H; k <= -1; k++) r[k+H] = 0;
	for (unsigned k = 0; k <= 108; k++) {
		r[k+H] = u[k] ^ r[k-1+H] ^ r[k-2+H] ^ r[k-3+H] ^ r[k-4+H];
		C[5*k] = r[k+H] ^ r[k-1+H] ^ r[k-3+H] ^ r[k-4+H];
		C[5*k+1] = r[k+H] ^ r[k-1+H] ^ r[k-3+H] ^ r[k-4+H];
		C[5*k+2] = r[k+H] ^ r[k-2+H] ^ r[k-4+H];
		C[5*k+3] = u[k];
		C[5*k+4] = u[k];
	}
	// termination
	for (unsigned k = 109; k <= 112; k++) {
		r[k+H] = 0;
		C[5*k] = r[k+H] ^ r[k-1+H] ^ r[k-3+H] ^ r[k-4+H];
		C[5*k+1] = r[k+H] ^ r[k-1+H] ^ r[k-3+H] ^ r[k-4+H];
		C[5*k+2] = r[k+H] ^ r[k-2+H] ^ r[k-4+H];
		C[5*k+3] = r[k-1+H] ^ r[k-2+H] ^ r[k-3+H] ^ r[k-4+H];
		C[5*k+4] = r[k-1+H] ^ r[k-2+H] ^ r[k-3+H] ^ r[k-4+H];
	}
}



void ViterbiTCH_AFS4_75::encode(const BitVector& in, BitVector& target) const
{
	assert(in.size() == 101);
	assert(target.size() == 535);
	const char *u = in.begin();
	char *C = target.begin();
	const unsigned H = 6;
	BitVector r(107+H);
	for (int k = -H; k <= -1; k++) r[k+H] = 0;
	for (unsigned k = 0; k <= 100; k++) {
		r[k+H] = u[k] ^ r[k-1+H] ^ r[k-2+H] ^ r[k-3+H] ^ r[k-4+H] ^ r[k-6+H];
		C[5*k] = r[k+H] ^ r[k-2+H] ^ r[k-3+H] ^ r[k-5+H] ^ r[k-6+H];
		C[5*k+1] = r[k+H] ^ r[k-2+H] ^ r[k-3+H] ^ r[k-5+H] ^ r[k-6+H];
		C[5*k+2] = r[k+H] ^ r[k-1+H] ^ r[k-4+H] ^ r[k-6+H];
		C[5*k+3] = u[k];
		C[5*k+4] = u[k];
	}
	// termination
	for (unsigned k = 101; k <= 106; k++) {
		r[k+H] = 0;
		C[5*k] = r[k+H] ^ r[k-2+H] ^ r[k-3+H] ^ r[k-5+H] ^ r[k-6+H];
		C[5*k+1] = r[k+H] ^ r[k-2+H] ^ r[k-3+H] ^ r[k-5+H] ^ r[k-6+H];
		C[5*k+2] = r[k+H] ^ r[k-1+H] ^ r[k-4+H] ^ r[k-6+H];
		C[5*k+3] = r[k+H] ^ r[k-2+H] ^ r[k-3+H] ^ r[k-4+H] ^ r[k-6+H];
		C[5*k+4] = r[k-1+H] ^ r[k-2+H] ^ r[k-3+H] ^ r[k-4+H] ^ r[k-6+H];
	}
}


void ViterbiTCH_AFS12_2::initializeStates()
{
	for (unsigned i=0; i<mIStates; i++) vitClear(mSurvivors[i]);
	for (unsigned i=0; i<mNumCands; i++) vitClear(mCandidates[i]);
}



void ViterbiTCH_AFS12_2::computeStateTables(unsigned g)
{
	assert(g<mIRate);
	for (unsigned state=0; state<mIStates; state++) {
		for (unsigned in = 0; in <= 1; in++) {
			uint32_t inputVal = (state<<1) | in;
			mStateTable[g][inputVal] = applyPoly(inputVal, mCoeffs[g] ^ mCoeffsFB[g], mOrder+1) ^ in;
		}
	}
}

void ViterbiTCH_AFS12_2::computeGeneratorTable()
{
	for (unsigned index=0; index<mIStates*2; index++) {
		uint32_t t = 0;
		for (unsigned i = 0; i < mIRate; i++) {
			t = (t << 1) | mStateTable[i][index];
		}
		mGeneratorTable[index] = t;
	}
}






void ViterbiTCH_AFS12_2::branchCandidates()
{
	// Branch to generate new input states.
	const vCand *sp = mSurvivors;
	for (unsigned cand=0; cand<mNumCands; cand+=2) {
		uint32_t oStateShifted = (sp->oState) << mIRate;
		for (unsigned in = 0; in <= 1; in++) {
			mCandidates[cand+in].iState = ((sp->iState) << 1) | in;
			mCandidates[cand+in].cost = sp->cost;
			uint32_t outputs = oStateShifted;
			for (unsigned out = 0; out < mIRate; out++) {
				char feedback = applyPoly(sp->rState[out], mCoeffsFB[out] ^ 1, mOrder+1);
				char rState = (((sp->rState[out]) ^ feedback) << 1) | in;
				mCandidates[cand+in].rState[out] = rState;
				outputs |= (mGeneratorTable[rState & mCMask] & (1 << (mIRate - out - 1)));
			}
			mCandidates[cand+in].oState = outputs;
		}
		sp++;
	}
}


void ViterbiTCH_AFS12_2::getSoftCostMetrics(const uint32_t inSample, const float *matchCost, const float *mismatchCost)
{
	const float *cTab[2] = {matchCost,mismatchCost};
	for (unsigned i=0; i<mNumCands; i++) {
		vCand& thisCand = mCandidates[i];
		const unsigned mismatched = inSample ^ (thisCand.oState);
		for (unsigned i = 0; i < mIRate; i++) {
			thisCand.cost += cTab[(mismatched>>i)&0x01][mIRate-i-1];
		}
	}
}


void ViterbiTCH_AFS12_2::pruneCandidates()
{
	const vCand* c1 = mCandidates;					// 0-prefix
	const vCand* c2 = mCandidates + mIStates;		// 1-prefix
	for (unsigned i=0; i<mIStates; i++) {
		if (c1[i].cost < c2[i].cost) mSurvivors[i] = c1[i];
		else mSurvivors[i] = c2[i];
	}
}


const ViterbiTCH_AFS12_2::vCand& ViterbiTCH_AFS12_2::minCost() const
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


const ViterbiTCH_AFS12_2::vCand& ViterbiTCH_AFS12_2::step(uint32_t inSample, const float *probs, const float *iprobs)
{
	branchCandidates();
	getSoftCostMetrics(inSample,probs,iprobs);
	pruneCandidates();
	return minCost();
}



void ViterbiTCH_AFS12_2::decode(const SoftVector &in, BitVector& target)
{
	ViterbiTCH_AFS12_2 &decoder = *this;
	const size_t sz = in.size() - 8;
	const unsigned deferral = decoder.deferral();
	const size_t ctsz = sz + deferral*decoder.iRate();
	assert(sz == decoder.iRate()*target.size());

	// Build a "history" array where each element contains the full history.
	uint32_t * history = (uint32_t *)malloc(sizeof(uint32_t)*ctsz);
	{
		BitVector bits = in.sliced();
		uint32_t accum = 0;
		for (size_t i=0; i<sz; i++) {
			accum = (accum<<1) | bits.bit(i);
			history[i] = accum;
		}
		// Repeat last bit at the end.
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
		const char *const opt = target.end();
		// table pointers
		const float* match = matchCostTable;
		const float* mismatch = mismatchCostTable;
		size_t oCount = 0;
		while (op<opt) {
			// Viterbi algorithm
			assert(match-matchCostTable<(int)(sizeof(matchCostTable)/sizeof(matchCostTable[0])-1));
			assert(mismatch-mismatchCostTable<(int)(sizeof(mismatchCostTable)/sizeof(mismatchCostTable[0])-1));
			const ViterbiTCH_AFS12_2::vCand &minCost = decoder.step(*ip, match, mismatch);
			ip += step;
			match += step;
			mismatch += step;
			// output
			if (oCount>=deferral) *op++ = (minCost.iState >> deferral)&0x01;
			oCount++;
		}
	}
	free(history);
	free(matchCostTable);
	free(mismatchCostTable);
}



ViterbiTCH_AFS10_2::ViterbiTCH_AFS10_2()
{
	assert(mDeferral < 32);
	mCoeffs[0] = 0x01b;
	mCoeffsFB[0] = 0x01f;
	mCoeffs[1] = 0x015;
	mCoeffsFB[1] = 0x01f;
	mCoeffs[2] = 0x01f;
	mCoeffsFB[2] = 0x01f;
	for (unsigned i = 0; i < mIRate; i++) {
		computeStateTables(i);
	}
	computeGeneratorTable();
}




void ViterbiTCH_AFS10_2::initializeStates()
{
	for (unsigned i=0; i<mIStates; i++) vitClear(mSurvivors[i]);
	for (unsigned i=0; i<mNumCands; i++) vitClear(mCandidates[i]);
}



void ViterbiTCH_AFS10_2::computeStateTables(unsigned g)
{
	assert(g<mIRate);
	for (unsigned state=0; state<mIStates; state++) {
		for (unsigned in = 0; in <= 1; in++) {
			uint32_t inputVal = (state<<1) | in;
			mStateTable[g][inputVal] = applyPoly(inputVal, mCoeffs[g] ^ mCoeffsFB[g], mOrder+1) ^ in;
		}
	}
}

void ViterbiTCH_AFS10_2::computeGeneratorTable()
{
	for (unsigned index=0; index<mIStates*2; index++) {
		uint32_t t = 0;
		for (unsigned i = 0; i < mIRate; i++) {
			t = (t << 1) | mStateTable[i][index];
		}
		mGeneratorTable[index] = t;
	}
}






void ViterbiTCH_AFS10_2::branchCandidates()
{
	// Branch to generate new input states.
	const vCand *sp = mSurvivors;
	for (unsigned cand=0; cand<mNumCands; cand+=2) {
		uint32_t oStateShifted = (sp->oState) << mIRate;
		for (unsigned in = 0; in <= 1; in++) {
			mCandidates[cand+in].iState = ((sp->iState) << 1) | in;
			mCandidates[cand+in].cost = sp->cost;
			uint32_t outputs = oStateShifted;
			for (unsigned out = 0; out < mIRate; out++) {
				char feedback = applyPoly(sp->rState[out], mCoeffsFB[out] ^ 1, mOrder+1);
				char rState = (((sp->rState[out]) ^ feedback) << 1) | in;
				mCandidates[cand+in].rState[out] = rState;
				outputs |= (mGeneratorTable[rState & mCMask] & (1 << (mIRate - out - 1)));
			}
			mCandidates[cand+in].oState = outputs;
		}
		sp++;
	}
}


void ViterbiTCH_AFS10_2::getSoftCostMetrics(const uint32_t inSample, const float *matchCost, const float *mismatchCost)
{
	const float *cTab[2] = {matchCost,mismatchCost};
	for (unsigned i=0; i<mNumCands; i++) {
		vCand& thisCand = mCandidates[i];
		const unsigned mismatched = inSample ^ (thisCand.oState);
		for (unsigned i = 0; i < mIRate; i++) {
			thisCand.cost += cTab[(mismatched>>i)&0x01][mIRate-i-1];
		}
	}
}


void ViterbiTCH_AFS10_2::pruneCandidates()
{
	const vCand* c1 = mCandidates;					// 0-prefix
	const vCand* c2 = mCandidates + mIStates;		// 1-prefix
	for (unsigned i=0; i<mIStates; i++) {
		if (c1[i].cost < c2[i].cost) mSurvivors[i] = c1[i];
		else mSurvivors[i] = c2[i];
	}
}


const ViterbiTCH_AFS10_2::vCand& ViterbiTCH_AFS10_2::minCost() const
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


const ViterbiTCH_AFS10_2::vCand& ViterbiTCH_AFS10_2::step(uint32_t inSample, const float *probs, const float *iprobs)
{
	branchCandidates();
	getSoftCostMetrics(inSample,probs,iprobs);
	pruneCandidates();
	return minCost();
}



void ViterbiTCH_AFS10_2::decode(const SoftVector &in, BitVector& target)
{
	ViterbiTCH_AFS10_2 &decoder = *this;
	const size_t sz = in.size() - 12;
	const unsigned deferral = decoder.deferral();
	const size_t ctsz = sz + deferral*decoder.iRate();
	assert(sz == decoder.iRate()*target.size());

	// Build a "history" array where each element contains the full history.
	uint32_t * history = (uint32_t *)malloc(sizeof(uint32_t)*ctsz);
	{
		BitVector bits = in.sliced();
		uint32_t accum = 0;
		for (size_t i=0; i<sz; i++) {
			accum = (accum<<1) | bits.bit(i);
			history[i] = accum;
		}
		// Repeat last bit at the end.
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
		const char *const opt = target.end();
		// table pointers
		const float* match = matchCostTable;
		const float* mismatch = mismatchCostTable;
		size_t oCount = 0;
		while (op<opt) {
			// Viterbi algorithm
			assert(match-matchCostTable<(int)(sizeof(matchCostTable)/sizeof(matchCostTable[0])-1));
			assert(mismatch-mismatchCostTable<(int)(sizeof(mismatchCostTable)/sizeof(mismatchCostTable[0])-1));
			const ViterbiTCH_AFS10_2::vCand &minCost = decoder.step(*ip, match, mismatch);
			ip += step;
			match += step;
			mismatch += step;
			// output
			if (oCount>=deferral) *op++ = (minCost.iState >> deferral)&0x01;
			oCount++;
		}
	}
	free(history);
	free(matchCostTable);
	free(mismatchCostTable);
}



ViterbiTCH_AFS7_95::ViterbiTCH_AFS7_95()
{
	assert(mDeferral < 32);
	mCoeffs[0] = 0x06d;
	mCoeffsFB[0] = 0x06d;
	mCoeffs[1] = 0x053;
	mCoeffsFB[1] = 0x06d;
	mCoeffs[2] = 0x05f;
	mCoeffsFB[2] = 0x06d;
	for (unsigned i = 0; i < mIRate; i++) {
		computeStateTables(i);
	}
	computeGeneratorTable();
}




void ViterbiTCH_AFS7_95::initializeStates()
{
	for (unsigned i=0; i<mIStates; i++) vitClear(mSurvivors[i]);
	for (unsigned i=0; i<mNumCands; i++) vitClear(mCandidates[i]);
}



void ViterbiTCH_AFS7_95::computeStateTables(unsigned g)
{
	assert(g<mIRate);
	for (unsigned state=0; state<mIStates; state++) {
		for (unsigned in = 0; in <= 1; in++) {
			uint32_t inputVal = (state<<1) | in;
			mStateTable[g][inputVal] = applyPoly(inputVal, mCoeffs[g] ^ mCoeffsFB[g], mOrder+1) ^ in;
		}
	}
}

void ViterbiTCH_AFS7_95::computeGeneratorTable()
{
	for (unsigned index=0; index<mIStates*2; index++) {
		uint32_t t = 0;
		for (unsigned i = 0; i < mIRate; i++) {
			t = (t << 1) | mStateTable[i][index];
		}
		mGeneratorTable[index] = t;
	}
}






void ViterbiTCH_AFS7_95::branchCandidates()
{
	// Branch to generate new input states.
	const vCand *sp = mSurvivors;
	for (unsigned cand=0; cand<mNumCands; cand+=2) {
		uint32_t oStateShifted = (sp->oState) << mIRate;
		for (unsigned in = 0; in <= 1; in++) {
			mCandidates[cand+in].iState = ((sp->iState) << 1) | in;
			mCandidates[cand+in].cost = sp->cost;
			uint32_t outputs = oStateShifted;
			for (unsigned out = 0; out < mIRate; out++) {
				char feedback = applyPoly(sp->rState[out], mCoeffsFB[out] ^ 1, mOrder+1);
				char rState = (((sp->rState[out]) ^ feedback) << 1) | in;
				mCandidates[cand+in].rState[out] = rState;
				outputs |= (mGeneratorTable[rState & mCMask] & (1 << (mIRate - out - 1)));
			}
			mCandidates[cand+in].oState = outputs;
		}
		sp++;
	}
}


void ViterbiTCH_AFS7_95::getSoftCostMetrics(const uint32_t inSample, const float *matchCost, const float *mismatchCost)
{
	const float *cTab[2] = {matchCost,mismatchCost};
	for (unsigned i=0; i<mNumCands; i++) {
		vCand& thisCand = mCandidates[i];
		const unsigned mismatched = inSample ^ (thisCand.oState);
		for (unsigned i = 0; i < mIRate; i++) {
			thisCand.cost += cTab[(mismatched>>i)&0x01][mIRate-i-1];
		}
	}
}


void ViterbiTCH_AFS7_95::pruneCandidates()
{
	const vCand* c1 = mCandidates;					// 0-prefix
	const vCand* c2 = mCandidates + mIStates;		// 1-prefix
	for (unsigned i=0; i<mIStates; i++) {
		if (c1[i].cost < c2[i].cost) mSurvivors[i] = c1[i];
		else mSurvivors[i] = c2[i];
	}
}


const ViterbiTCH_AFS7_95::vCand& ViterbiTCH_AFS7_95::minCost() const
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


const ViterbiTCH_AFS7_95::vCand& ViterbiTCH_AFS7_95::step(uint32_t inSample, const float *probs, const float *iprobs)
{
	branchCandidates();
	getSoftCostMetrics(inSample,probs,iprobs);
	pruneCandidates();
	return minCost();
}



void ViterbiTCH_AFS7_95::decode(const SoftVector &in, BitVector& target)
{
	ViterbiTCH_AFS7_95 &decoder = *this;
	const size_t sz = in.size() - 18;
	const unsigned deferral = decoder.deferral();
	const size_t ctsz = sz + deferral*decoder.iRate();
	assert(sz == decoder.iRate()*target.size());

	// Build a "history" array where each element contains the full history.
	uint32_t * history = (uint32_t *)malloc(sizeof(uint32_t)*ctsz);
	{
		BitVector bits = in.sliced();
		uint32_t accum = 0;
		for (size_t i=0; i<sz; i++) {
			accum = (accum<<1) | bits.bit(i);
			history[i] = accum;
		}
		// Repeat last bit at the end.
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
		const char *const opt = target.end();
		// table pointers
		const float* match = matchCostTable;
		const float* mismatch = mismatchCostTable;
		size_t oCount = 0;
		while (op<opt) {
			// Viterbi algorithm
			assert(match-matchCostTable<(int)(sizeof(matchCostTable)/sizeof(matchCostTable[0])-1));
			assert(mismatch-mismatchCostTable<(int)(sizeof(mismatchCostTable)/sizeof(mismatchCostTable[0])-1));
			const ViterbiTCH_AFS7_95::vCand &minCost = decoder.step(*ip, match, mismatch);
			ip += step;
			match += step;
			mismatch += step;
			// output
			if (oCount>=deferral) *op++ = (minCost.iState >> deferral)&0x01;
			oCount++;
		}
	}
	free(history);
	free(matchCostTable);
	free(mismatchCostTable);
}



ViterbiTCH_AFS7_4::ViterbiTCH_AFS7_4()
{
	assert(mDeferral < 32);
	mCoeffs[0] = 0x01b;
	mCoeffsFB[0] = 0x01f;
	mCoeffs[1] = 0x015;
	mCoeffsFB[1] = 0x01f;
	mCoeffs[2] = 0x01f;
	mCoeffsFB[2] = 0x01f;
	for (unsigned i = 0; i < mIRate; i++) {
		computeStateTables(i);
	}
	computeGeneratorTable();
}




void ViterbiTCH_AFS7_4::initializeStates()
{
	for (unsigned i=0; i<mIStates; i++) vitClear(mSurvivors[i]);
	for (unsigned i=0; i<mNumCands; i++) vitClear(mCandidates[i]);
}



void ViterbiTCH_AFS7_4::computeStateTables(unsigned g)
{
	assert(g<mIRate);
	for (unsigned state=0; state<mIStates; state++) {
		for (unsigned in = 0; in <= 1; in++) {
			uint32_t inputVal = (state<<1) | in;
			mStateTable[g][inputVal] = applyPoly(inputVal, mCoeffs[g] ^ mCoeffsFB[g], mOrder+1) ^ in;
		}
	}
}

void ViterbiTCH_AFS7_4::computeGeneratorTable()
{
	for (unsigned index=0; index<mIStates*2; index++) {
		uint32_t t = 0;
		for (unsigned i = 0; i < mIRate; i++) {
			t = (t << 1) | mStateTable[i][index];
		}
		mGeneratorTable[index] = t;
	}
}






void ViterbiTCH_AFS7_4::branchCandidates()
{
	// Branch to generate new input states.
	const vCand *sp = mSurvivors;
	for (unsigned cand=0; cand<mNumCands; cand+=2) {
		uint32_t oStateShifted = (sp->oState) << mIRate;
		for (unsigned in = 0; in <= 1; in++) {
			mCandidates[cand+in].iState = ((sp->iState) << 1) | in;
			mCandidates[cand+in].cost = sp->cost;
			uint32_t outputs = oStateShifted;
			for (unsigned out = 0; out < mIRate; out++) {
				char feedback = applyPoly(sp->rState[out], mCoeffsFB[out] ^ 1, mOrder+1);
				char rState = (((sp->rState[out]) ^ feedback) << 1) | in;
				mCandidates[cand+in].rState[out] = rState;
				outputs |= (mGeneratorTable[rState & mCMask] & (1 << (mIRate - out - 1)));
			}
			mCandidates[cand+in].oState = outputs;
		}
		sp++;
	}
}


void ViterbiTCH_AFS7_4::getSoftCostMetrics(const uint32_t inSample, const float *matchCost, const float *mismatchCost)
{
	const float *cTab[2] = {matchCost,mismatchCost};
	for (unsigned i=0; i<mNumCands; i++) {
		vCand& thisCand = mCandidates[i];
		const unsigned mismatched = inSample ^ (thisCand.oState);
		for (unsigned i = 0; i < mIRate; i++) {
			thisCand.cost += cTab[(mismatched>>i)&0x01][mIRate-i-1];
		}
	}
}


void ViterbiTCH_AFS7_4::pruneCandidates()
{
	const vCand* c1 = mCandidates;					// 0-prefix
	const vCand* c2 = mCandidates + mIStates;		// 1-prefix
	for (unsigned i=0; i<mIStates; i++) {
		if (c1[i].cost < c2[i].cost) mSurvivors[i] = c1[i];
		else mSurvivors[i] = c2[i];
	}
}


const ViterbiTCH_AFS7_4::vCand& ViterbiTCH_AFS7_4::minCost() const
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


const ViterbiTCH_AFS7_4::vCand& ViterbiTCH_AFS7_4::step(uint32_t inSample, const float *probs, const float *iprobs)
{
	branchCandidates();
	getSoftCostMetrics(inSample,probs,iprobs);
	pruneCandidates();
	return minCost();
}



void ViterbiTCH_AFS7_4::decode(const SoftVector &in, BitVector& target)
{
	ViterbiTCH_AFS7_4 &decoder = *this;
	const size_t sz = in.size() - 12;
	const unsigned deferral = decoder.deferral();
	const size_t ctsz = sz + deferral*decoder.iRate();
	assert(sz == decoder.iRate()*target.size());

	// Build a "history" array where each element contains the full history.
	uint32_t * history = (uint32_t *)malloc(sizeof(uint32_t)*ctsz);
	{
		BitVector bits = in.sliced();
		uint32_t accum = 0;
		for (size_t i=0; i<sz; i++) {
			accum = (accum<<1) | bits.bit(i);
			history[i] = accum;
		}
		// Repeat last bit at the end.
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
		const char *const opt = target.end();
		// table pointers
		const float* match = matchCostTable;
		const float* mismatch = mismatchCostTable;
		size_t oCount = 0;
		while (op<opt) {
			// Viterbi algorithm
			assert(match-matchCostTable<(int)(sizeof(matchCostTable)/sizeof(matchCostTable[0])-1));
			assert(mismatch-mismatchCostTable<(int)(sizeof(mismatchCostTable)/sizeof(mismatchCostTable[0])-1));
			const ViterbiTCH_AFS7_4::vCand &minCost = decoder.step(*ip, match, mismatch);
			ip += step;
			match += step;
			mismatch += step;
			// output
			if (oCount>=deferral) *op++ = (minCost.iState >> deferral)&0x01;
			oCount++;
		}
	}
	free(history);
	free(matchCostTable);
	free(mismatchCostTable);
}



ViterbiTCH_AFS6_7::ViterbiTCH_AFS6_7()
{
	assert(mDeferral < 32);
	mCoeffs[0] = 0x01b;
	mCoeffsFB[0] = 0x01f;
	mCoeffs[1] = 0x015;
	mCoeffsFB[1] = 0x01f;
	mCoeffs[2] = 0x01f;
	mCoeffsFB[2] = 0x01f;
	mCoeffs[3] = 0x01f;
	mCoeffsFB[3] = 0x01f;
	for (unsigned i = 0; i < mIRate; i++) {
		computeStateTables(i);
	}
	computeGeneratorTable();
}




void ViterbiTCH_AFS6_7::initializeStates()
{
	for (unsigned i=0; i<mIStates; i++) vitClear(mSurvivors[i]);
	for (unsigned i=0; i<mNumCands; i++) vitClear(mCandidates[i]);
}



void ViterbiTCH_AFS6_7::computeStateTables(unsigned g)
{
	assert(g<mIRate);
	for (unsigned state=0; state<mIStates; state++) {
		for (unsigned in = 0; in <= 1; in++) {
			uint32_t inputVal = (state<<1) | in;
			mStateTable[g][inputVal] = applyPoly(inputVal, mCoeffs[g] ^ mCoeffsFB[g], mOrder+1) ^ in;
		}
	}
}

void ViterbiTCH_AFS6_7::computeGeneratorTable()
{
	for (unsigned index=0; index<mIStates*2; index++) {
		uint32_t t = 0;
		for (unsigned i = 0; i < mIRate; i++) {
			t = (t << 1) | mStateTable[i][index];
		}
		mGeneratorTable[index] = t;
	}
}






void ViterbiTCH_AFS6_7::branchCandidates()
{
	// Branch to generate new input states.
	const vCand *sp = mSurvivors;
	for (unsigned cand=0; cand<mNumCands; cand+=2) {
		uint32_t oStateShifted = (sp->oState) << mIRate;
		for (unsigned in = 0; in <= 1; in++) {
			mCandidates[cand+in].iState = ((sp->iState) << 1) | in;
			mCandidates[cand+in].cost = sp->cost;
			uint32_t outputs = oStateShifted;
			for (unsigned out = 0; out < mIRate; out++) {
				char feedback = applyPoly(sp->rState[out], mCoeffsFB[out] ^ 1, mOrder+1);
				char rState = (((sp->rState[out]) ^ feedback) << 1) | in;
				mCandidates[cand+in].rState[out] = rState;
				outputs |= (mGeneratorTable[rState & mCMask] & (1 << (mIRate - out - 1)));
			}
			mCandidates[cand+in].oState = outputs;
		}
		sp++;
	}
}


void ViterbiTCH_AFS6_7::getSoftCostMetrics(const uint32_t inSample, const float *matchCost, const float *mismatchCost)
{
	const float *cTab[2] = {matchCost,mismatchCost};
	for (unsigned i=0; i<mNumCands; i++) {
		vCand& thisCand = mCandidates[i];
		const unsigned mismatched = inSample ^ (thisCand.oState);
		for (unsigned i = 0; i < mIRate; i++) {
			thisCand.cost += cTab[(mismatched>>i)&0x01][mIRate-i-1];
		}
	}
}


void ViterbiTCH_AFS6_7::pruneCandidates()
{
	const vCand* c1 = mCandidates;					// 0-prefix
	const vCand* c2 = mCandidates + mIStates;		// 1-prefix
	for (unsigned i=0; i<mIStates; i++) {
		if (c1[i].cost < c2[i].cost) mSurvivors[i] = c1[i];
		else mSurvivors[i] = c2[i];
	}
}


const ViterbiTCH_AFS6_7::vCand& ViterbiTCH_AFS6_7::minCost() const
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


const ViterbiTCH_AFS6_7::vCand& ViterbiTCH_AFS6_7::step(uint32_t inSample, const float *probs, const float *iprobs)
{
	branchCandidates();
	getSoftCostMetrics(inSample,probs,iprobs);
	pruneCandidates();
	return minCost();
}



void ViterbiTCH_AFS6_7::decode(const SoftVector &in, BitVector& target)
{
	ViterbiTCH_AFS6_7 &decoder = *this;
	const size_t sz = in.size() - 16;
	const unsigned deferral = decoder.deferral();
	const size_t ctsz = sz + deferral*decoder.iRate();
	assert(sz == decoder.iRate()*target.size());

	// Build a "history" array where each element contains the full history.
	uint32_t * history = (uint32_t *)malloc(sizeof(uint32_t)*ctsz);
	{
		BitVector bits = in.sliced();
		uint32_t accum = 0;
		for (size_t i=0; i<sz; i++) {
			accum = (accum<<1) | bits.bit(i);
			history[i] = accum;
		}
		// Repeat last bit at the end.
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
		const char *const opt = target.end();
		// table pointers
		const float* match = matchCostTable;
		const float* mismatch = mismatchCostTable;
		size_t oCount = 0;
		while (op<opt) {
			// Viterbi algorithm
			assert(match-matchCostTable<(int)(sizeof(matchCostTable)/sizeof(matchCostTable[0])-1));
			assert(mismatch-mismatchCostTable<(int)(sizeof(mismatchCostTable)/sizeof(mismatchCostTable[0])-1));
			const ViterbiTCH_AFS6_7::vCand &minCost = decoder.step(*ip, match, mismatch);
			ip += step;
			match += step;
			mismatch += step;
			// output
			if (oCount>=deferral) *op++ = (minCost.iState >> deferral)&0x01;
			oCount++;
		}
	}
	free(history);
	free(matchCostTable);
	free(mismatchCostTable);
}



ViterbiTCH_AFS5_9::ViterbiTCH_AFS5_9()
{
	assert(mDeferral < 32);
	mCoeffs[0] = 0x06d;
	mCoeffsFB[0] = 0x05f;
	mCoeffs[1] = 0x053;
	mCoeffsFB[1] = 0x05f;
	mCoeffs[2] = 0x05f;
	mCoeffsFB[2] = 0x05f;
	mCoeffs[3] = 0x05f;
	mCoeffsFB[3] = 0x05f;
	for (unsigned i = 0; i < mIRate; i++) {
		computeStateTables(i);
	}
	computeGeneratorTable();
}




void ViterbiTCH_AFS5_9::initializeStates()
{
	for (unsigned i=0; i<mIStates; i++) vitClear(mSurvivors[i]);
	for (unsigned i=0; i<mNumCands; i++) vitClear(mCandidates[i]);
}



void ViterbiTCH_AFS5_9::computeStateTables(unsigned g)
{
	assert(g<mIRate);
	for (unsigned state=0; state<mIStates; state++) {
		for (unsigned in = 0; in <= 1; in++) {
			uint32_t inputVal = (state<<1) | in;
			mStateTable[g][inputVal] = applyPoly(inputVal, mCoeffs[g] ^ mCoeffsFB[g], mOrder+1) ^ in;
		}
	}
}

void ViterbiTCH_AFS5_9::computeGeneratorTable()
{
	for (unsigned index=0; index<mIStates*2; index++) {
		uint32_t t = 0;
		for (unsigned i = 0; i < mIRate; i++) {
			t = (t << 1) | mStateTable[i][index];
		}
		mGeneratorTable[index] = t;
	}
}






void ViterbiTCH_AFS5_9::branchCandidates()
{
	// Branch to generate new input states.
	const vCand *sp = mSurvivors;
	for (unsigned cand=0; cand<mNumCands; cand+=2) {
		uint32_t oStateShifted = (sp->oState) << mIRate;
		for (unsigned in = 0; in <= 1; in++) {
			mCandidates[cand+in].iState = ((sp->iState) << 1) | in;
			mCandidates[cand+in].cost = sp->cost;
			uint32_t outputs = oStateShifted;
			for (unsigned out = 0; out < mIRate; out++) {
				char feedback = applyPoly(sp->rState[out], mCoeffsFB[out] ^ 1, mOrder+1);
				char rState = (((sp->rState[out]) ^ feedback) << 1) | in;
				mCandidates[cand+in].rState[out] = rState;
				outputs |= (mGeneratorTable[rState & mCMask] & (1 << (mIRate - out - 1)));
			}
			mCandidates[cand+in].oState = outputs;
		}
		sp++;
	}
}


void ViterbiTCH_AFS5_9::getSoftCostMetrics(const uint32_t inSample, const float *matchCost, const float *mismatchCost)
{
	const float *cTab[2] = {matchCost,mismatchCost};
	for (unsigned i=0; i<mNumCands; i++) {
		vCand& thisCand = mCandidates[i];
		const unsigned mismatched = inSample ^ (thisCand.oState);
		for (unsigned i = 0; i < mIRate; i++) {
			thisCand.cost += cTab[(mismatched>>i)&0x01][mIRate-i-1];
		}
	}
}


void ViterbiTCH_AFS5_9::pruneCandidates()
{
	const vCand* c1 = mCandidates;					// 0-prefix
	const vCand* c2 = mCandidates + mIStates;		// 1-prefix
	for (unsigned i=0; i<mIStates; i++) {
		if (c1[i].cost < c2[i].cost) mSurvivors[i] = c1[i];
		else mSurvivors[i] = c2[i];
	}
}


const ViterbiTCH_AFS5_9::vCand& ViterbiTCH_AFS5_9::minCost() const
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


const ViterbiTCH_AFS5_9::vCand& ViterbiTCH_AFS5_9::step(uint32_t inSample, const float *probs, const float *iprobs)
{
	branchCandidates();
	getSoftCostMetrics(inSample,probs,iprobs);
	pruneCandidates();
	return minCost();
}



void ViterbiTCH_AFS5_9::decode(const SoftVector &in, BitVector& target)
{
	ViterbiTCH_AFS5_9 &decoder = *this;
	const size_t sz = in.size() - 24;
	const unsigned deferral = decoder.deferral();
	const size_t ctsz = sz + deferral*decoder.iRate();
	assert(sz == decoder.iRate()*target.size());

	// Build a "history" array where each element contains the full history.
	uint32_t * history = (uint32_t *)malloc(sizeof(uint32_t)*ctsz);
	{
		BitVector bits = in.sliced();
		uint32_t accum = 0;
		for (size_t i=0; i<sz; i++) {
			accum = (accum<<1) | bits.bit(i);
			history[i] = accum;
		}
		// Repeat last bit at the end.
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
		const char *const opt = target.end();
		// table pointers
		const float* match = matchCostTable;
		const float* mismatch = mismatchCostTable;
		size_t oCount = 0;
		while (op<opt) {
			// Viterbi algorithm
			assert(match-matchCostTable<(int)(sizeof(matchCostTable)/sizeof(matchCostTable[0])-1));
			assert(mismatch-mismatchCostTable<(int)(sizeof(mismatchCostTable)/sizeof(mismatchCostTable[0])-1));
			const ViterbiTCH_AFS5_9::vCand &minCost = decoder.step(*ip, match, mismatch);
			ip += step;
			match += step;
			mismatch += step;
			// output
			if (oCount>=deferral) *op++ = (minCost.iState >> deferral)&0x01;
			oCount++;
		}
	}
	free(history);
	free(matchCostTable);
	free(mismatchCostTable);
}



ViterbiTCH_AFS5_15::ViterbiTCH_AFS5_15()
{
	assert(mDeferral < 32);
	mCoeffs[0] = 0x01b;
	mCoeffsFB[0] = 0x01f;
	mCoeffs[1] = 0x01b;
	mCoeffsFB[1] = 0x01f;
	mCoeffs[2] = 0x015;
	mCoeffsFB[2] = 0x01f;
	mCoeffs[3] = 0x01f;
	mCoeffsFB[3] = 0x01f;
	mCoeffs[4] = 0x01f;
	mCoeffsFB[4] = 0x01f;
	for (unsigned i = 0; i < mIRate; i++) {
		computeStateTables(i);
	}
	computeGeneratorTable();
}




void ViterbiTCH_AFS5_15::initializeStates()
{
	for (unsigned i=0; i<mIStates; i++) vitClear(mSurvivors[i]);
	for (unsigned i=0; i<mNumCands; i++) vitClear(mCandidates[i]);
}



void ViterbiTCH_AFS5_15::computeStateTables(unsigned g)
{
	assert(g<mIRate);
	for (unsigned state=0; state<mIStates; state++) {
		for (unsigned in = 0; in <= 1; in++) {
			uint32_t inputVal = (state<<1) | in;
			mStateTable[g][inputVal] = applyPoly(inputVal, mCoeffs[g] ^ mCoeffsFB[g], mOrder+1) ^ in;
		}
	}
}

void ViterbiTCH_AFS5_15::computeGeneratorTable()
{
	for (unsigned index=0; index<mIStates*2; index++) {
		uint32_t t = 0;
		for (unsigned i = 0; i < mIRate; i++) {
			t = (t << 1) | mStateTable[i][index];
		}
		mGeneratorTable[index] = t;
	}
}






void ViterbiTCH_AFS5_15::branchCandidates()
{
	// Branch to generate new input states.
	const vCand *sp = mSurvivors;
	for (unsigned cand=0; cand<mNumCands; cand+=2) {
		uint32_t oStateShifted = (sp->oState) << mIRate;
		for (unsigned in = 0; in <= 1; in++) {
			mCandidates[cand+in].iState = ((sp->iState) << 1) | in;
			mCandidates[cand+in].cost = sp->cost;
			uint32_t outputs = oStateShifted;
			for (unsigned out = 0; out < mIRate; out++) {
				char feedback = applyPoly(sp->rState[out], mCoeffsFB[out] ^ 1, mOrder+1);
				char rState = (((sp->rState[out]) ^ feedback) << 1) | in;
				mCandidates[cand+in].rState[out] = rState;
				outputs |= (mGeneratorTable[rState & mCMask] & (1 << (mIRate - out - 1)));
			}
			mCandidates[cand+in].oState = outputs;
		}
		sp++;
	}
}


void ViterbiTCH_AFS5_15::getSoftCostMetrics(const uint32_t inSample, const float *matchCost, const float *mismatchCost)
{
	const float *cTab[2] = {matchCost,mismatchCost};
	for (unsigned i=0; i<mNumCands; i++) {
		vCand& thisCand = mCandidates[i];
		const unsigned mismatched = inSample ^ (thisCand.oState);
		for (unsigned i = 0; i < mIRate; i++) {
			thisCand.cost += cTab[(mismatched>>i)&0x01][mIRate-i-1];
		}
	}
}


void ViterbiTCH_AFS5_15::pruneCandidates()
{
	const vCand* c1 = mCandidates;					// 0-prefix
	const vCand* c2 = mCandidates + mIStates;		// 1-prefix
	for (unsigned i=0; i<mIStates; i++) {
		if (c1[i].cost < c2[i].cost) mSurvivors[i] = c1[i];
		else mSurvivors[i] = c2[i];
	}
}


const ViterbiTCH_AFS5_15::vCand& ViterbiTCH_AFS5_15::minCost() const
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


const ViterbiTCH_AFS5_15::vCand& ViterbiTCH_AFS5_15::step(uint32_t inSample, const float *probs, const float *iprobs)
{
	branchCandidates();
	getSoftCostMetrics(inSample,probs,iprobs);
	pruneCandidates();
	return minCost();
}



void ViterbiTCH_AFS5_15::decode(const SoftVector &in, BitVector& target)
{
	ViterbiTCH_AFS5_15 &decoder = *this;
	const size_t sz = in.size() - 20;
	const unsigned deferral = decoder.deferral();
	const size_t ctsz = sz + deferral*decoder.iRate();
	assert(sz == decoder.iRate()*target.size());

	// Build a "history" array where each element contains the full history.
	uint32_t * history = (uint32_t *)malloc(sizeof(uint32_t)*ctsz);
	{
		BitVector bits = in.sliced();
		uint32_t accum = 0;
		for (size_t i=0; i<sz; i++) {
			accum = (accum<<1) | bits.bit(i);
			history[i] = accum;
		}
		// Repeat last bit at the end.
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
		const char *const opt = target.end();
		// table pointers
		const float* match = matchCostTable;
		const float* mismatch = mismatchCostTable;
		size_t oCount = 0;
		while (op<opt) {
			// Viterbi algorithm
			assert(match-matchCostTable<(int)(sizeof(matchCostTable)/sizeof(matchCostTable[0])-1));
			assert(mismatch-mismatchCostTable<(int)(sizeof(mismatchCostTable)/sizeof(mismatchCostTable[0])-1));
			const ViterbiTCH_AFS5_15::vCand &minCost = decoder.step(*ip, match, mismatch);
			ip += step;
			match += step;
			mismatch += step;
			// output
			if (oCount>=deferral) *op++ = (minCost.iState >> deferral)&0x01;
			oCount++;
		}
	}
	free(history);
	free(matchCostTable);
	free(mismatchCostTable);
}



ViterbiTCH_AFS4_75::ViterbiTCH_AFS4_75()
{
	assert(mDeferral < 32);
	mCoeffs[0] = 0x06d;
	mCoeffsFB[0] = 0x05f;
	mCoeffs[1] = 0x06d;
	mCoeffsFB[1] = 0x05f;
	mCoeffs[2] = 0x053;
	mCoeffsFB[2] = 0x05f;
	mCoeffs[3] = 0x05f;
	mCoeffsFB[3] = 0x05f;
	mCoeffs[4] = 0x05f;
	mCoeffsFB[4] = 0x05f;
	for (unsigned i = 0; i < mIRate; i++) {
		computeStateTables(i);
	}
	computeGeneratorTable();
}




void ViterbiTCH_AFS4_75::initializeStates()
{
	for (unsigned i=0; i<mIStates; i++) vitClear(mSurvivors[i]);
	for (unsigned i=0; i<mNumCands; i++) vitClear(mCandidates[i]);
}



void ViterbiTCH_AFS4_75::computeStateTables(unsigned g)
{
	assert(g<mIRate);
	for (unsigned state=0; state<mIStates; state++) {
		for (unsigned in = 0; in <= 1; in++) {
			uint32_t inputVal = (state<<1) | in;
			mStateTable[g][inputVal] = applyPoly(inputVal, mCoeffs[g] ^ mCoeffsFB[g], mOrder+1) ^ in;
		}
	}
}

void ViterbiTCH_AFS4_75::computeGeneratorTable()
{
	for (unsigned index=0; index<mIStates*2; index++) {
		uint32_t t = 0;
		for (unsigned i = 0; i < mIRate; i++) {
			t = (t << 1) | mStateTable[i][index];
		}
		mGeneratorTable[index] = t;
	}
}






void ViterbiTCH_AFS4_75::branchCandidates()
{
	// Branch to generate new input states.
	const vCand *sp = mSurvivors;
	for (unsigned cand=0; cand<mNumCands; cand+=2) {
		uint32_t oStateShifted = (sp->oState) << mIRate;
		for (unsigned in = 0; in <= 1; in++) {
			mCandidates[cand+in].iState = ((sp->iState) << 1) | in;
			mCandidates[cand+in].cost = sp->cost;
			uint32_t outputs = oStateShifted;
			for (unsigned out = 0; out < mIRate; out++) {
				char feedback = applyPoly(sp->rState[out], mCoeffsFB[out] ^ 1, mOrder+1);
				char rState = (((sp->rState[out]) ^ feedback) << 1) | in;
				mCandidates[cand+in].rState[out] = rState;
				outputs |= (mGeneratorTable[rState & mCMask] & (1 << (mIRate - out - 1)));
			}
			mCandidates[cand+in].oState = outputs;
		}
		sp++;
	}
}


void ViterbiTCH_AFS4_75::getSoftCostMetrics(const uint32_t inSample, const float *matchCost, const float *mismatchCost)
{
	const float *cTab[2] = {matchCost,mismatchCost};
	for (unsigned i=0; i<mNumCands; i++) {
		vCand& thisCand = mCandidates[i];
		const unsigned mismatched = inSample ^ (thisCand.oState);
		for (unsigned i = 0; i < mIRate; i++) {
			thisCand.cost += cTab[(mismatched>>i)&0x01][mIRate-i-1];
		}
	}
}


void ViterbiTCH_AFS4_75::pruneCandidates()
{
	const vCand* c1 = mCandidates;					// 0-prefix
	const vCand* c2 = mCandidates + mIStates;		// 1-prefix
	for (unsigned i=0; i<mIStates; i++) {
		if (c1[i].cost < c2[i].cost) mSurvivors[i] = c1[i];
		else mSurvivors[i] = c2[i];
	}
}


const ViterbiTCH_AFS4_75::vCand& ViterbiTCH_AFS4_75::minCost() const
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


const ViterbiTCH_AFS4_75::vCand& ViterbiTCH_AFS4_75::step(uint32_t inSample, const float *probs, const float *iprobs)
{
	branchCandidates();
	getSoftCostMetrics(inSample,probs,iprobs);
	pruneCandidates();
	return minCost();
}



void ViterbiTCH_AFS4_75::decode(const SoftVector &in, BitVector& target)
{
	ViterbiTCH_AFS4_75 &decoder = *this;
	const size_t sz = in.size() - 30;
	const unsigned deferral = decoder.deferral();
	const size_t ctsz = sz + deferral*decoder.iRate();
	assert(sz == decoder.iRate()*target.size());

	// Build a "history" array where each element contains the full history.
	uint32_t * history = (uint32_t *)malloc(sizeof(uint32_t)*ctsz);
	{
		BitVector bits = in.sliced();
		uint32_t accum = 0;
		for (size_t i=0; i<sz; i++) {
			accum = (accum<<1) | bits.bit(i);
			history[i] = accum;
		}
		// Repeat last bit at the end.
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
		const char *const opt = target.end();
		// table pointers
		const float* match = matchCostTable;
		const float* mismatch = mismatchCostTable;
		size_t oCount = 0;
		while (op<opt) {
			// Viterbi algorithm
			assert(match-matchCostTable<(int)(sizeof(matchCostTable)/sizeof(matchCostTable[0])-1));
			assert(mismatch-mismatchCostTable<(int)(sizeof(mismatchCostTable)/sizeof(mismatchCostTable[0])-1));
			const ViterbiTCH_AFS4_75::vCand &minCost = decoder.step(*ip, match, mismatch);
			ip += step;
			match += step;
			mismatch += step;
			// output
			if (oCount>=deferral) *op++ = (minCost.iState >> deferral)&0x01;
			oCount++;
		}
	}
	free(history);
	free(matchCostTable);
	free(mismatchCostTable);
}



