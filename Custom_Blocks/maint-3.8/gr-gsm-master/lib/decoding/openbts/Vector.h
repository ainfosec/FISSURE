/*
 * Copyright 2008 Free Software Foundation, Inc.
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

/**@file Simplified Vector template with aliases. */


#ifndef VECTOR_H
#define VECTOR_H

#include <string.h>
#include <iostream>
#include <assert.h>
#include <stdio.h>
// We cant use Logger.h in this file...
extern int gVectorDebug;
//#define ENABLE_VECTORDEBUG
#ifdef ENABLE_VECTORDEBUG
#define VECTORDEBUG(...) { printf(__VA_ARGS__); printf(" this=%p [%p,%p,%p]\n",(void*)this,(void*)&mData,mStart,mEnd); }
//#define VECTORDEBUG(msg) { std::cout<<msg<<std::endl; }
#else
#define VECTORDEBUG(...)
#endif

#define BITVECTOR_REFCNTS 0

#if BITVECTOR_REFCNTS
// (pat) Started to add refcnts, decided against it for now.
template <class T> class RCData : public RefCntBase {
        public:
        T* mPointer;
};
#endif


/**
        A simplified Vector template with aliases.
        Unlike std::vector, this class does not support dynamic resizing.
        Unlike std::vector, this class does support "aliases" and subvectors.
*/
// (pat) Nov 2013:  Vector and the derived classes BitVector and SoftVector were originally written with behavior
// that differed for const and non-const cases, making them very difficult to use and resulting in many extremely
// difficult to find bugs in the code base.
// Ultimately these classes should all be converted to reference counted methodologies, but as an interim measure
// I am rationalizing their behavior until we flush out all places in the code base that inadvertently depended
// on the original behavior.  This is done with assert statements in BitVector methods.
// ====
// What the behavior was probably supposed to be:
//              Vectors can 'own' the data they point to or not.  Only one Vector 'owns' the memory at a time,
//              so that automatic destruction can be used.  So whenever there is an operation that yields one
//              vector from another the options were: clone (allocate a new vector from memory), alias (make the
//              new vector point into the memory of the original vector) or shift (the new Vector steals the
//              memory ownership from the original vector.)
//              The const copy-constructor did a clone, the non-const copy constructor did a shiftMem, and the segment and
//              related methods (head, tail, etc) returned aliases.
//              Since a copy-constructor is inserted transparently in sometimes surprising places, this made the
//              class very difficult to use.  Moreover, since the C++ standard specifies that a copy-constructor is used
//              to copy the return value from functions, it makes it literally impossible for a function to fully control
//              the return value.  Our code has relied on the "Return Value Optimization" which says that the C++ compiler
//              may omit the copy-construction of the return value even if the copy-constructor has side-effects, which ours does.
//              This methodology is fundamentally incompatible with C++.
// What the original behavior actually was:
//      class Vector:
//              The copy-constructor and assignment operators did a clone for the const case and a shift for the non-const case.
//                      This is really horrible.
//              The segment methods were identical for const and non-const cases, always returning an alias.
//              This also resulted in zillions of redundant mallocs and copies throughout the code base.
//      class BitVector:
//              Copy-constructor:
//                      BitVector did not have any copy-constructors, and I think the intent was that it would have the same behavior
//                      as Vector, but that is not how C++ works: with no copy-constructor the default copy-constructor
//                      uses only the const case, so only the const Vector copy-constructor was used.  Therefore it always cloned,
//                      and the code base relied heavily on the "Return Value Optimization" to work at all.
//              Assignment operator:
//                      BitVector did not have one, so C++ makes a default one that calls Vector::operator=() as a side effect,
//                      which did a clone; not sure if there was a non-const version and no longer care.
//              segment methods:
//                      The non-const segment() returned an alias, and the const segment() returned a clone.
//                      I think the intent was that the behavior should be the same as Vector, but there was a conversion
//                      of the result of the const segment() method from Vector to BitVector which caused the Vector copy-constructor
//                      to be (inadvertently) invoked, resulting in the const version of the segment method returning a clone.
// What the behavior is now:
//      VectorBase:
//              There is a new VectorBase class that has only the common methods and extremely basic constructors.
//              The VectorBase class MUST NOT CONTAIN: copy constructors, non-trivial constructors called from derived classes,
//              or any method that returns a VectorBase type object.  Why?  Because any of the above when used in derived classes
//              can cause copy-constructor invocation, often surprisingly, obfuscating the code.
//              Each derived class must provide its own: copy-constructors and segment() and related methods, since we do not
//              want to inadvertently invoke a copy-constructor to convert the segment() result from VectorBase to the derived type.
//      BitVector:
//              The BitVector copy-constructor and assignment operator (inherited from VectorBase) paradigm is:
//              if the copied Vector owned memory, perform a clone so the new vector owns memory also,
//              otherwise just do a simple copy, which is another alias.  This isnt perfect but works every place
//              in our code base and easier to use than the previous paradigm.
//              The segment method always returns an alias.
//              If you want a clone of a segment, use cloneSegment(), which replaces the previous: const segment(...) const method.
//              Note that the semantics of cloneSegment still rely on the Return Value Optimization.  Oh well, we should use refcnts.
//      Vector:
//              I left Vector alone (except for rearrangement to separate out VectorBase.)  Vector should just not be used.
//      SoftVector:
//              SoftVector and signalVector should be updated similar to BitVector, but I did not want to disturb them.
// What the behavior should be:
//              All these should be reference-counted, similar to ByteVector.
template <class T> class VectorBase
{
        // TODO -- Replace memcpy calls with for-loops. (pat) in case class T is not POD [Plain Old Data]

        protected:
#if BITVECTOR_REFCNTS
        typedef RefCntPointer<RCData<T> > VectorDataType;
#else
        typedef T* VectorDataType;
#endif
        VectorDataType mData;           ///< allocated data block.
        T* mStart;              ///< start of useful data
        T* mEnd;                ///< end of useful data + 1

        // Init vector with specified size.  Previous contents are completely discarded.  This is only used for initialization.
        void vInit(size_t elements)
        {
                mData = elements ? new T[elements] : NULL;
                mStart = mData;  // This is where mStart get set to zero
                mEnd = mStart + elements;
        }

        /** Assign from another Vector, shifting ownership. */
        // (pat) This should be eliminated, but it is used by Vector and descendents.
        void shiftMem(VectorBase<T>&other)
        {
                VECTORDEBUG("VectorBase::shiftMem(%p)",(void*)&other);
                this->clear();
                this->mData=other.mData;
                this->mStart=other.mStart;
                this->mEnd=other.mEnd;
                other.mData=NULL;
        }

        // Assign from another Vector, making this an alias to other.
        void makeAlias(const VectorBase<T> &other)
        {
                if (this->getData()) {
                        assert(this->getData() != other.getData()); // Not possible by the semantics of Vector.
                        this->clear();
                }
                this->mStart=const_cast<T*>(other.mStart);
                this->mEnd=const_cast<T*>(other.mEnd);
        }

        public:

        /** Return the size of the Vector in units, ie, the number of T elements. */
        size_t size() const
        {
                assert(mStart>=mData);
                assert(mEnd>=mStart);
                return mEnd - mStart;
        }

        /** Return size in bytes. */
        size_t bytes() const { return this->size()*sizeof(T); }

        /** Change the size of the Vector in items (not bytes), discarding content. */
        void resize(size_t newElements) {
                //VECTORDEBUG("VectorBase::resize("<<(void*)this<<","<<newElements<<")");
                VECTORDEBUG("VectorBase::resize(%p,%d) %s",this,newElements, (mData?"delete":""));
                if (mData!=NULL) delete[] mData;
                vInit(newElements);
        }

        /** Release memory and clear pointers. */
        void clear() { this->resize(0); }


        /** Copy data from another vector. */
        void clone(const VectorBase<T>& other) {
                this->resize(other.size());
                memcpy(mData,other.mStart,other.bytes());
        }

        void vConcat(const VectorBase<T>&other1, const VectorBase<T>&other2) {
                this->resize(other1.size()+other2.size());
                memcpy(this->mStart, other1.mStart, other1.bytes());
                memcpy(this->mStart+other1.size(), other2.mStart, other2.bytes());
        }

        protected:

        VectorBase() : mData(0), mStart(0), mEnd(0) {}

        /** Build a Vector with explicit values. */
        VectorBase(VectorDataType wData, T* wStart, T* wEnd) :mData(wData),mStart(wStart),mEnd(wEnd) {
                //VECTORDEBUG("VectorBase("<<(void*)wData);
                VECTORDEBUG("VectorBase(%p,%p,%p)",this->getData(),wStart,wEnd);
        }

        public:

        /** Destroy a Vector, deleting held memory. */
        ~VectorBase() {
                //VECTORDEBUG("~VectorBase("<<(void*)this<<")");
                VECTORDEBUG("~VectorBase(%p)",this);
                this->clear();
        }

        bool isOwner() { return !!this->mData; }        // Do we own any memory ourselves?

        std::string inspect() const {
                char buf[100];
                snprintf(buf,100," mData=%p mStart=%p mEnd=%p ",(void*)mData,mStart,mEnd);
                return std::string(buf);
        }


        /**
                Copy part of this Vector to a segment of another Vector.
                @param other The other vector.
                @param start The start point in the other vector.
                @param span The number of elements to copy.
        */
        void copyToSegment(VectorBase<T>& other, size_t start, size_t span) const
        {
                T* base = other.mStart + start;
                assert(base+span<=other.mEnd);
                assert(mStart+span<=mEnd);
                memcpy(base,mStart,span*sizeof(T));
        }

        /** Copy all of this Vector to a segment of another Vector. */
        void copyToSegment(VectorBase<T>& other, size_t start=0) const { copyToSegment(other,start,size()); }

        void copyTo(VectorBase<T>& other) const { copyToSegment(other,0,size()); }

        /**
                Copy a segment of this vector into another.
                @param other The other vector (to copt into starting at 0.)
                @param start The start point in this vector.
                @param span The number of elements to copy.
                WARNING: This function does NOT resize the result - you must set the result size before entering.
        */
        void segmentCopyTo(VectorBase<T>& other, size_t start, size_t span) const
        {
                const T* base = mStart + start;
                assert(base+span<=mEnd);
                assert(other.mStart+span<=other.mEnd);
                memcpy(other.mStart,base,span*sizeof(T));
        }

        void fill(const T& val)
        {
                T* dp=mStart;
                while (dp<mEnd) *dp++=val;
        }

        void fill(const T& val, unsigned start, unsigned length)
        {
                T* dp=mStart+start;
                T* end=dp+length;
                assert(end<=mEnd);
                while (dp<end) *dp++=val;
        }

        /** Assign from another Vector. */
        // (pat) This is used for both const and non-const cases.
        // If the original vector owned memory, clone it, otherwise just copy the segment data.
        void operator=(const VectorBase<T>& other) {
                //std::cout << "Vector=(this="<<this->inspect()<<",other="<<other.inspect()<<")"<<endl;
                if (other.getData()) {
                        this->clone(other);
                } else {
                        this->makeAlias(other);
                }
                //std::cout << "Vector= after(this="<<this->inspect()<<")"<<endl;
        }


        T& operator[](size_t index)
        {
                assert(mStart+index<mEnd);
                return mStart[index];
        }

        const T& operator[](size_t index) const
        {
                assert(mStart+index<mEnd);
                return mStart[index];
        }

        const T* begin() const { return this->mStart; }
        T* begin() { return this->mStart; }
        const T* end() const { return this->mEnd; }
        T* end() { return this->mEnd; }
#if BITVECTOR_REFCNTS
        const T*getData() const { return this->mData.isNULL() ? 0 : this->mData->mPointer; }
#else
        const T*getData() const { return this->mData; }
#endif
};

// (pat) Nov 2013.  This class retains the original poor behavior.  See comments at VectorBase
template <class T> class Vector : public VectorBase<T>
{
        public:

        /** Build an empty Vector of a given size. */
        Vector(size_t wSize=0) { this->resize(wSize); }

        /** Build a Vector by shifting the data block. */
        Vector(Vector<T>& other) : VectorBase<T>(other.mData,other.mStart,other.mEnd) { other.mData=NULL; }

        /** Build a Vector by copying another. */
        Vector(const Vector<T>& other):VectorBase<T>() { this->clone(other); }

        /** Build a Vector with explicit values. */
        Vector(T* wData, T* wStart, T* wEnd) : VectorBase<T>(wData,wStart,wEnd) { }

        /** Build a vector from an existing block, NOT to be deleted upon destruction. */
        Vector(T* wStart, size_t span) : VectorBase<T>(NULL,wStart,wStart+span) { }

        /** Build a Vector by concatenation. */
        Vector(const Vector<T>& other1, const Vector<T>& other2):VectorBase<T>() {
                assert(this->mData == 0);
                this->vConcat(other1,other2);
        }

        //@{

        /** Assign from another Vector, shifting ownership. */
        void operator=(Vector<T>& other) { this->shiftMem(other); }

        /** Assign from another Vector, copying. */
        void operator=(const Vector<T>& other) { this->clone(other); }

        /** Return an alias to a segment of this Vector. */
        Vector<T> segment(size_t start, size_t span)
        {
                T* wStart = this->mStart + start;
                T* wEnd = wStart + span;
                assert(wEnd<=this->mEnd);
                return Vector<T>(NULL,wStart,wEnd);
        }

        /** Return an alias to a segment of this Vector. */
        const Vector<T> segment(size_t start, size_t span) const
        {
                T* wStart = this->mStart + start;
                T* wEnd = wStart + span;
                assert(wEnd<=this->mEnd);
                return Vector<T>(NULL,wStart,wEnd);
        }

        Vector<T> head(size_t span) { return segment(0,span); }
        const Vector<T> head(size_t span) const { return segment(0,span); }
        Vector<T> tail(size_t start) { return segment(start,this->size()-start); }
        const Vector<T> tail(size_t start) const { return segment(start,this->size()-start); }

        /**@name Iterator types. */
        //@{
        typedef T* iterator;
        typedef const T* const_iterator;
        //@}

        //@}
};





/** Basic print operator for Vector objects. */
template <class T>
std::ostream& operator<<(std::ostream& os, const Vector<T>& v)
{
        for (unsigned i=0; i<v.size(); i++) os << v[i] << " ";
        return os;
}



#endif
// vim: ts=4 sw=4
