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

#ifndef BITVECTORS_H
#define BITVECTORS_H

#include "Vector.h"
#include <stdint.h>
#include <stdio.h>


class BitVector;
class SoftVector;




/** Shift-register (LFSR) generator. */
class Generator {

	private:

	uint64_t mCoeff;	///< polynomial coefficients. LSB is zero exponent.
	uint64_t mState;	///< shift register state. LSB is most recent.
	uint64_t mMask;		///< mask for reading state
	unsigned mLen;		///< number of bits used in shift register
	unsigned mLen_1;	///< mLen - 1

	public:

	Generator(uint64_t wCoeff, unsigned wLen)
		:mCoeff(wCoeff),mState(0),
		mMask((1ULL<<wLen)-1),
		mLen(wLen),mLen_1(wLen-1)
	{ assert(wLen<64); }

	void clear() { mState=0; }

	/**@name Accessors */
	//@{
	uint64_t state() const { return mState & mMask; }
	unsigned size() const { return mLen; }
	//@}

	/**
		Calculate one bit of a syndrome.
		This is in the .h for inlining.
	*/
	void syndromeShift(unsigned inBit)
	{
		const unsigned fb = (mState>>(mLen_1)) & 0x01;
		mState = (mState<<1) ^ (inBit & 0x01);
		if (fb) mState ^= mCoeff;
	}

	/**
		Update the generator state by one cycle.
		This is in the .h for inlining.
	*/
	void encoderShift(unsigned inBit)
	{
		const unsigned fb = ((mState>>(mLen_1)) ^ inBit) & 0x01;
		mState <<= 1;
		if (fb) mState ^= mCoeff;
	}


};




/** Parity (CRC-type) generator and checker based on a Generator. */
class Parity : public Generator {

	protected:

	unsigned mCodewordSize;

	public:

	Parity(uint64_t wCoefficients, unsigned wParitySize, unsigned wCodewordSize)
		:Generator(wCoefficients, wParitySize),
		mCodewordSize(wCodewordSize)
	{ }

	/** Compute the parity word and write it into the target segment.  */
	void writeParityWord(const BitVector& data, BitVector& parityWordTarget, bool invert=true);

	/** Compute the syndrome of a received sequence. */
	uint64_t syndrome(const BitVector& receivedCodeword);
};


// (pat) Nov 2013.  I rationalized the behavior of BitVector and added assertions to core dump code
// that relied on the bad aspects of the original behavior.  See comments at VectorBase.
class BitVector : public VectorBase<char>
{
	public:
	/**@name Constructors. */
	//@{

	/**@name Casts of Vector constructors. */
	BitVector(VectorDataType wData, char* wStart, char* wEnd) : VectorBase<char>(wData, wStart, wEnd) {}

	// The one and only copy-constructor.
	BitVector(const BitVector&other) : VectorBase<char>() {
		VECTORDEBUG("BitVector(%p)",(void*)&other);
		if (other.getData()) {
			this->clone(other);
		} else {
			this->makeAlias(other);
		}
	}

	// (pat) Removed default value for len and added 'explicit'.  Please do not remove 'explicit';
	// it prevents auto-conversion of int to BitVector in constructors.
	// Previous code was often ambiguous, especially for L3Frame and descendent constructors, leading to latent bugs.
	explicit BitVector(size_t len) { this->vInit(len); }
	BitVector() { this->vInit(0); }

	/** Build a BitVector by concatenation. */
	BitVector(const BitVector& other1, const BitVector& other2) : VectorBase<char>()
	{
		assert(this->getData() == 0);
		this->vConcat(other1,other2);
	}

	/** Construct from a string of "0" and "1". */
	// (pat) Characters that are not '0' or '1' map to '0'.
	BitVector(const char* valString);
	//@}

	/**@name Casts and overrides of Vector operators. */
	//@{
	// (pat) Please DO NOT add a const anywhere in this method.  Use cloneSegment instead.
	BitVector segment(size_t start, size_t span)
	{
		char* wStart = this->begin() + start;
		char* wEnd = wStart + span;
		assert(wEnd<=this->end());
#if BITVECTOR_REFCNTS
		return BitVector(mData,wStart,wEnd);
#else
		return BitVector(NULL,wStart,wEnd);
#endif
	}

	// (pat) Historically the BitVector segment method had const and non-const versions with different behavior.
	// I changed the name of the const version to cloneSegment and replaced all uses throughout OpenBTS.
	const BitVector cloneSegment(size_t start, size_t span) const
	{
		BitVector seg = const_cast<BitVector*>(this)->segment(start,span);
		// (pat) We are depending on the Return Value Optimization not to invoke the copy-constructor on the result,
		// which would result in its immediate destruction while we are still using it.
		BitVector result;
		result.clone(seg);
		return result;
	}

	BitVector alias() const {
		return const_cast<BitVector*>(this)->segment(0,size());
	}

	BitVector head(size_t span) { return segment(0,span); }
	BitVector tail(size_t start) { return segment(start,size()-start); }

	// (pat) Please do NOT put the const version of head and tail back in, because historically they were messed up.
	// Use cloneSegment instead.
	//const BitVector head(size_t span) const { return segment(0,span); }
	//const BitVector tail(size_t start) const { return segment(start,size()-start); }
	//@}


	void zero() { fill(0); }

	/**@name FEC operations. */
	//@{
	/** Calculate the syndrome of the vector with the given Generator. */
	uint64_t syndrome(Generator& gen) const;
	/** Calculate the parity word for the vector with the given Generator. */
	uint64_t parity(Generator& gen) const;
	//@}


	/** Invert 0<->1. */
	void invert();

	/**@name Byte-wise operations. */
	//@{
	/** Reverse an 8-bit vector. */
	void reverse8();
	/** Reverse groups of 8 within the vector (byte reversal). */
	void LSB8MSB();
	//@}

	/**@name Serialization and deserialization. */
	//@{
	uint64_t peekField(size_t readIndex, unsigned length) const;
	uint64_t peekFieldReversed(size_t readIndex, unsigned length) const;
	uint64_t readField(size_t& readIndex, unsigned length) const;
	uint64_t readFieldReversed(size_t& readIndex, unsigned length) const;
	void fillField(size_t writeIndex, uint64_t value, unsigned length);
	void fillFieldReversed(size_t writeIndex, uint64_t value, unsigned length);
	void writeField(size_t& writeIndex, uint64_t value, unsigned length);
	void writeFieldReversed(size_t& writeIndex, uint64_t value, unsigned length);
	void write0(size_t& writeIndex) { writeField(writeIndex,0,1); }
	void write1(size_t& writeIndex) { writeField(writeIndex,1,1); }

	//@}

	/** Sum of bits. */
	unsigned sum() const;

	/** Reorder bits, dest[i] = this[map[i]]. */
	void map(const unsigned *map, size_t mapSize, BitVector& dest) const;

	/** Reorder bits, dest[map[i]] = this[i]. */
	void unmap(const unsigned *map, size_t mapSize, BitVector& dest) const;

	/** Pack into a char array. */
	void pack(unsigned char*) const;

	/*  Roman: This is here for debugging */
	void pack2(unsigned char*) const;

	// Same as pack but return a string.
	std::string packToString() const;

	/** Unpack from a char array. */
	void unpack(const unsigned char*);

	/** Make a hexdump string. */
	void hex(std::ostream&) const;
	std::string hexstr() const;

	/** Unpack from a hexdump string.
	*  @returns true on success, false on error. */
	bool unhex(const char*);

	// For this method, 'other' should have been run through the copy-constructor already
	// (unless it was newly created, ie foo.dup(L2Frame(...)), in which case we are screwed anyway)
	// so the call to makeAlias is redundant.
	// This only works if other is already an alias.
	void dup(BitVector other) { assert(!this->getData()); makeAlias(other); assert(this->mStart == other.mStart); }
	void dup(BitVector &other) { makeAlias(other); assert(this->mStart == other.mStart); }

#if 0
	void operator=(const BitVector& other) {
		printf("BitVector::operator=\n");
		assert(0);
		//this->dup(other);
	}
#endif

    bool operator==(const BitVector &other) const;

	/** Copy to dst, not including those indexed in puncture. */
	void copyPunctured(BitVector &dst, const unsigned *puncture, const size_t plth);

	/** Index a single bit. */
	// (pat) Cant have too many ways to do this, I guess.
	bool bit(size_t index) const
	{
		// We put this code in .h for fast inlining.
		const char *dp = this->begin()+index;
		assert(dp<this->end());
		return (*dp) & 0x01;
	}

	char& operator[](size_t index)
	{
		assert(this->mStart+index<this->mEnd);
		return this->mStart[index];
	}

	const char& operator[](size_t index) const
	{
		assert(this->mStart+index<this->mEnd);
		return this->mStart[index];
	}

	/** Set a bit */
	void settfb(size_t index, int value)
	{
		char *dp = this->mStart+index;
		assert(dp<this->mEnd);
		*dp = value;
	}

	typedef char* iterator;
	typedef const char* const_iterator;
};

// (pat) BitVector2 was an intermediate step in fixing BitVector but is no longer needed.
#define BitVector2 BitVector


std::ostream& operator<<(std::ostream&, const BitVector&);






/**
  The SoftVector class is used to represent a soft-decision signal.
  Values 0..1 represent probabilities that a bit is "true".
 */
class SoftVector: public Vector<float> {

	public:

	/** Build a SoftVector of a given length. */
	SoftVector(size_t wSize=0):Vector<float>(wSize) {}

	/** Construct a SoftVector from a C string of "0", "1", and "X". */
	SoftVector(const char* valString);

	/** Construct a SoftVector from a BitVector. */
	SoftVector(const BitVector& source);

	/**
		Wrap a SoftVector around a block of floats.
		The block will be delete[]ed upon desctuction.
	*/
	SoftVector(float *wData, unsigned length)
		:Vector<float>(wData,length)
	{}

	SoftVector(float* wData, float* wStart, float* wEnd)
		:Vector<float>(wData,wStart,wEnd)
	{ }

	/**
		Casting from a Vector<float>.
		Note that this is NOT pass-by-reference.
	*/
	SoftVector(Vector<float> source)
		:Vector<float>(source)
	{}


	/**@name Casts and overrides of Vector operators. */
	//@{
	SoftVector segment(size_t start, size_t span)
	{
		float* wStart = mStart + start;
		float* wEnd = wStart + span;
		assert(wEnd<=mEnd);
		return SoftVector(NULL,wStart,wEnd);
	}

	SoftVector alias()
		{ return segment(0,size()); }

	const SoftVector segment(size_t start, size_t span) const
		{ return (SoftVector)(Vector<float>::segment(start,span)); }

	SoftVector head(size_t span) { return segment(0,span); }
	const SoftVector head(size_t span) const { return segment(0,span); }
	SoftVector tail(size_t start) { return segment(start,size()-start); }
	const SoftVector tail(size_t start) const { return segment(start,size()-start); }
	//@}

	// (pat) How good is the SoftVector in the sense of the bits being solid?
	// Result of 1 is perfect and 0 means all the bits were 0.5
	// If plow is non-NULL, also return the lowest energy bit.
	float getEnergy(float *low=0) const;
	float getSNR() const;

	/** Fill with "unknown" values. */
	void unknown() { fill(0.5F); }

	/** Return a hard bit value from a given index by slicing. */
	bool bit(size_t index) const
	{
		const float *dp = mStart+index;
		assert(dp<mEnd);
		return (*dp)>0.5F;
	}

	/** Slice the whole signal into bits. */
	BitVector sliced() const;

	/** Copy to dst, adding in 0.5 for those indexed in puncture. */
	void copyUnPunctured(SoftVector &dst, const unsigned *puncture, const size_t plth);

	/** Return a soft bit. */
	float softbit(size_t index) const
	{
		const float *dp = mStart+index;
		assert(dp<mEnd);
		return *dp;
	}

	/** Set a soft bit */
	void settfb(size_t index, float value)
	{
		float *dp = mStart+index;
		assert(dp<mEnd);
		*dp = value;
	}
};



std::ostream& operator<<(std::ostream&, const SoftVector&);




#endif
// vim: ts=4 sw=4
