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
#include <iostream>
#include <stdio.h>
#include <sstream>
#include <string.h>
//#include <Logger.h>

using namespace std;



BitVector::BitVector(const char *valString)
{
	// 1-30-2013 pat: I dont know what this was intended to do, but it did not create a normalized BitVector,
	// and it could even fail if the accum overlows 8 bits.
	//uint32_t accum = 0;
	//for (size_t i=0; i<size(); i++) {
	//	accum <<= 1;
	//	if (valString[i]=='1') accum |= 0x01;
	//	mStart[i] = accum;
	//}
	vInit(strlen(valString));
	char *rp = begin();
	for (const char *cp = valString; *cp; cp++, rp++) {
		*rp = (*cp == '1');
	}
}


uint64_t BitVector::peekField(size_t readIndex, unsigned length) const
{
	uint64_t accum = 0;
	char *dp = mStart + readIndex;

	for (unsigned i=0; i<length; i++) {
		accum = (accum<<1) | ((*dp++) & 0x01);
	}
	return accum;
}




uint64_t BitVector::peekFieldReversed(size_t readIndex, unsigned length) const
{
	uint64_t accum = 0;
	char *dp = mStart + readIndex + length - 1;
	assert(dp<mEnd);
	for (int i=(length-1); i>=0; i--) {
		accum = (accum<<1) | ((*dp--) & 0x01);
	}
	return accum;
}




uint64_t BitVector::readField(size_t& readIndex, unsigned length) const
{
	const uint64_t retVal = peekField(readIndex,length);
	readIndex += length;
	return retVal;
}


uint64_t BitVector::readFieldReversed(size_t& readIndex, unsigned length) const
{

	const uint64_t retVal = peekFieldReversed(readIndex,length);
	readIndex += length;
	return retVal;

}




void BitVector::fillField(size_t writeIndex, uint64_t value, unsigned length)
{
	if (length != 0) {
		char *dpBase = mStart + writeIndex;
		char *dp = dpBase + length - 1;
		assert(dp < mEnd);
		while (dp>=dpBase) {
			*dp-- = value & 0x01;
			value >>= 1;
		}
	}
}


void BitVector::fillFieldReversed(size_t writeIndex, uint64_t value, unsigned length)
{
	if (length != 0) {
		char *dp = mStart + writeIndex;
		char *dpEnd = dp + length - 1;
		assert(dpEnd < mEnd);
		while (dp<=dpEnd) {
			*dp++ = value & 0x01;
			value >>= 1;
		}
	}
}




void BitVector::writeField(size_t& writeIndex, uint64_t value, unsigned length)
{
	if (length != 0) {
		fillField(writeIndex,value,length);
		writeIndex += length;
	}
}


void BitVector::writeFieldReversed(size_t& writeIndex, uint64_t value, unsigned length)
{
	if (length != 0) {
		fillFieldReversed(writeIndex,value,length);
		writeIndex += length;
	}
}


void BitVector::invert()
{
	for (size_t i=0; i<size(); i++) {
		mStart[i] = ~mStart[i];
	}
}




void BitVector::reverse8()
{
	assert(size()>=8);

	char tmp0 = mStart[0];
	mStart[0] = mStart[7];
	mStart[7] = tmp0;

	char tmp1 = mStart[1];
	mStart[1] = mStart[6];
	mStart[6] = tmp1;

	char tmp2 = mStart[2];
	mStart[2] = mStart[5];
	mStart[5] = tmp2;

	char tmp3 = mStart[3];
	mStart[3] = mStart[4];
	mStart[4] = tmp3;
}



void BitVector::LSB8MSB()
{
	if (size()<8) return;
	size_t size8 = 8*(size()/8);
	size_t iTop = size8 - 8;
	for (size_t i=0; i<=iTop; i+=8) segment(i,8).reverse8();
}



uint64_t BitVector::syndrome(Generator& gen) const
{
	gen.clear();
	const char *dp = mStart;
	while (dp<mEnd) gen.syndromeShift(*dp++);
	return gen.state();
}


uint64_t BitVector::parity(Generator& gen) const
{
	gen.clear();
	const char *dp = mStart;
	while (dp<mEnd) gen.encoderShift(*dp++);
	return gen.state();
}


unsigned BitVector::sum() const
{
	unsigned sum = 0;
	for (size_t i=0; i<size(); i++) sum += mStart[i] & 0x01;
	return sum;
}




void BitVector::map(const unsigned *map, size_t mapSize, BitVector& dest) const
{
	for (unsigned i=0; i<mapSize; i++) {
		dest.mStart[i] = mStart[map[i]];
	}
}




void BitVector::unmap(const unsigned *map, size_t mapSize, BitVector& dest) const
{
	for (unsigned i=0; i<mapSize; i++) {
		dest.mStart[map[i]] = mStart[i];
	}
}







ostream& operator<<(ostream& os, const BitVector& hv)
{
	for (size_t i=0; i<hv.size(); i++) {
		if (hv.bit(i)) os << '1';
		else os << '0';
	}
	return os;
}




uint64_t Parity::syndrome(const BitVector& receivedCodeword)
{
	return receivedCodeword.syndrome(*this);
}


void Parity::writeParityWord(const BitVector& data, BitVector& parityTarget, bool invert)
{
	uint64_t pWord = data.parity(*this);
	if (invert) pWord = ~pWord;
	parityTarget.fillField(0,pWord,size());
}









SoftVector::SoftVector(const BitVector& source)
{
	resize(source.size());
	for (size_t i=0; i<size(); i++) {
		if (source.bit(i)) mStart[i]=1.0F;
		else mStart[i]=0.0F;
	}
}


BitVector SoftVector::sliced() const
{
	size_t sz = size();
	BitVector newSig(sz);
	for (size_t i=0; i<sz; i++) {
		if (mStart[i]>0.5F) newSig[i]=1;
		else newSig[i] = 0;
	}
	return newSig;
}



// (pat) Added 6-22-2012
float SoftVector::getEnergy(float *plow) const
{
	const SoftVector &vec = *this;
	int len = vec.size();
	float avg = 0; float low = 1;
	for (int i = 0; i < len; i++) {
		float bit = vec[i];
		float energy = 2*((bit < 0.5) ? (0.5-bit) : (bit-0.5));
		if (energy < low) low = energy;
		avg += energy/len;
	}
	if (plow) { *plow = low; }
	return avg;
}

// (pat) Added 1-2014.  Compute SNR of a soft vector.  Very similar to above.
// Since we dont really know what the expected signal values are, we will assume that the signal is 0 or 1
// and return the SNR on that basis.
// SNR is power(signal) / power(noise) where power can be calculated as (RMS(signal) / RMS(noise))**2 of the values.
// Since RMS is square-rooted, ie RMS = sqrt(1/n * (x1**2 + x2**2 ...)), we just add up the squares.
// To compute RMS of the signal we will remove any constant offset, so the signal values are either 0.5 or -0.5,
// so the RMS of the signal is just 0.5**2 * len;  all we need to compute is the noise component.
float SoftVector::getSNR() const
{
	float sumSquaresNoise = 0;
	const SoftVector &vec = *this;
	int len = vec.size();
	if (len == 0) { return 0.0; }
	for (int i = 0; i < len; i++) {
		float bit = vec[i];
		if (bit < 0.5) {
			// Assume signal is 0.
			sumSquaresNoise += (bit - 0.0) * (bit - 0.0);
		} else {
			// Assume signal is 1.
			sumSquaresNoise += (bit - 1.0) * (bit - 1.0);
		}
	}
	float sumSquaresSignal = 0.5 * 0.5 * len;
	// I really want log10 of this to convert to dB, but log is expensive, and Harvind seems to like absolute SNR.
	// Clamp max to 999; it shouldnt get up there but be sure.  This also avoids divide by zero.
	if (sumSquaresNoise * 1000 < sumSquaresSignal) return 999;
	return sumSquaresSignal / sumSquaresNoise;
}



ostream& operator<<(ostream& os, const SoftVector& sv)
{
	for (size_t i=0; i<sv.size(); i++) {
		if (sv[i]<0.25) os << "0";
		else if (sv[i]>0.75) os << "1";
		else os << "-";
	}
	return os;
}



void BitVector::pack(unsigned char* targ) const
{
	// Assumes MSB-first packing.
	unsigned bytes = size()/8;
	for (unsigned i=0; i<bytes; i++) {
		targ[i] = peekField(i*8,8);
	}
	unsigned whole = bytes*8;
	unsigned rem = size() - whole;
	if (rem==0) return;
	targ[bytes] = peekField(whole,rem) << (8-rem);
}

void BitVector::pack2(unsigned char* targ) const
{
    unsigned int i;
    unsigned char curbyte = 0;

    for (i = 0; i < size(); i++)
    {
        uint8_t bitnum = 7 - (i % 8);
        curbyte |= ((char)bit(i) << bitnum);
        if(i % 8 == 7){
            *targ++ = curbyte;
            curbyte = 0;
        }
    }

	// Assumes MSB-first packing.
//	unsigned bytes = size()/8;
//	for (unsigned i=0; i<bytes; i++) {
//		targ[i] = peekField(i*8,8);
//	}
//	unsigned whole = bytes*8;
//	unsigned rem = size() - whole;
//	if (rem==0) return;
//	targ[bytes] = peekField(whole,rem) << (8-rem);
}



string BitVector::packToString() const
{
	string result;
	result.reserve((size()+7)/8);
	// Tempting to call this->pack(result.c_str()) but technically c_str() is read-only.
	unsigned bytes = size()/8;
	for (unsigned i=0; i<bytes; i++) {
		result.push_back(peekField(i*8,8));
	}
	unsigned whole = bytes*8;
	unsigned rem = size() - whole;
	if (rem==0) return result;
	result.push_back(peekField(whole,rem) << (8-rem));
	return result;
}


void BitVector::unpack(const unsigned char* src)
{
	// Assumes MSB-first packing.
	unsigned bytes = size()/8;
	for (unsigned i=0; i<bytes; i++) {
		fillField(i*8,src[i],8);
	}
	unsigned whole = bytes*8;
	unsigned rem = size() - whole;
	if (rem==0) return;
        fillField(whole,src[bytes] >> (8-rem),rem);
}

void BitVector::hex(ostream& os) const
{
	os << std::hex;
	unsigned digits = size()/4;
	size_t wp=0;
	for (unsigned i=0; i<digits; i++) {
		os << readField(wp,4);
	}
	os << std::dec;
}

std::string BitVector::hexstr() const
{
	std::ostringstream ss;
	hex(ss);
	return ss.str();
}


bool BitVector::unhex(const char* src)
{
	// Assumes MSB-first packing.
	unsigned int val;
	unsigned digits = size()/4;
	for (unsigned i=0; i<digits; i++) {
		if (sscanf(src+i, "%1x", &val) < 1) {
			return false;
		}
		fillField(i*4,val,4);
	}
	unsigned whole = digits*4;
	unsigned rem = size() - whole;
	if (rem>0) {
		if (sscanf(src+digits, "%1x", &val) < 1) {
			return false;
		}
		fillField(whole,val,rem);
	}
	return true;
}

bool BitVector::operator==(const BitVector &other) const
{
	unsigned l = size();
	return l == other.size() && 0==memcmp(begin(),other.begin(),l);
}

void BitVector::copyPunctured(BitVector &dst, const unsigned *puncture, const size_t plth)
{
	assert(size() - plth == dst.size());
	char *srcp = mStart;
	char *dstp = dst.mStart;
	const unsigned *pend = puncture + plth;
	while (srcp < mEnd) {
		if (puncture < pend) {
			int n = (*puncture++) - (srcp - mStart);
			assert(n >= 0);
			for (int i = 0; i < n; i++) {
				assert(srcp < mEnd && dstp < dst.mEnd);
				*dstp++ = *srcp++;
			}
			srcp++;
		} else {
			while (srcp < mEnd) {
				assert(dstp < dst.mEnd);
				*dstp++ = *srcp++;
			}
		}
	}
	assert(dstp == dst.mEnd && puncture == pend);
}

void SoftVector::copyUnPunctured(SoftVector &dst, const unsigned *puncture, const size_t plth)
{
	assert(size() + plth == dst.size());
	float *srcp = mStart;
	float *dstp = dst.mStart;
	const unsigned *pend = puncture + plth;
	while (dstp < dst.mEnd) {
		if (puncture < pend) {
			int n = (*puncture++) - (dstp - dst.mStart);
			assert(n >= 0);
			for (int i = 0; i < n; i++) {
				assert(srcp < mEnd && dstp < dst.mEnd);
				*dstp++ = *srcp++;
			}
			*dstp++ = 0.5;
		} else {
			while (srcp < mEnd) {
				assert(dstp < dst.mEnd);
				*dstp++ = *srcp++;
			}
		}
	}
	assert(dstp == dst.mEnd && puncture == pend);
}

// vim: ts=4 sw=4
