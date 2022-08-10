#!/usr/bin/env python
# coding: utf-8
# vim: set ts=4 sw=4 tw=0 et fenc=utf8 pm=:
import struct
import sys
import math
import numpy
import os.path
import cmath
import re
import getopt
import gr_iridium as iridium


UW_DOWNLINK = "022220002002"
UW_UPLINK = "220002002022"

def normalize(v):
    m = max([abs(x) for x in v])
    return [x/m for x in v]

def mynormalize(v):
    reals = normalize([x.real for x in v])
    imags = normalize([x.imag for x in v])
    zip=[]
    for i in xrange(len(reals)):
        zip.append(complex(reals[i],imags[i]))
    return zip

class Demod(object):
    def __init__(self, sample_rate, verbose=False, debug=False):
        self._sample_rate=sample_rate
        self._verbose=verbose
        self._debug = debug
        
        if self._verbose:
            print "sample rate:",self._sample_rate

        if self._sample_rate % iridium.SYMBOLS_PER_SECOND != 0:
            raise Exception("Non-int samples per symbol")

        self._samples_per_symbol= self._sample_rate / iridium.SYMBOLS_PER_SECOND

        if self._verbose:
            print "samples per symbol:",self._samples_per_symbol

    def qpsk(self, phase):
        self._nsymbols+=1
        phase = phase % 360

        # In theory we should only see 45, 135, 225 and 315 here.
        sym=int(phase)/90
        #print "symbol", sym

        off=(45-(phase % 90))
        if (abs(off)>22):
            if self._verbose:
                print "Symbol offset >22"
            self._errors+='1'
        else:
            self._errors+='0'

        return sym,off

    def demod(self, signal, direction=None, return_final_offset=False, start_sample=None, timestamp=None):
        self._errors=''
        self._nsymbols=0

        level=abs(numpy.mean(signal[:16*self._samples_per_symbol]))
        lmax=abs(numpy.max(signal[:16*self._samples_per_symbol]))

        if self._verbose:
            print "level:",level
            print 'lmax:', lmax

        i = start_sample

        # Make sure we do not get a slightly negative index
        # from the correlations
        i = max(i, 0)

        symbols=[]
        if self._debug:
            self.samples=[]

        #Graphical debugging stuff (the *.peaks file)
        if self._debug:
            self.peaks=[complex(-lmax,0)]*len(signal)
            self.turned_signal=[0+0j] * len(signal)
            mapping= [2,1,-2,-1] # mapping: symbols->*.peaks output

        if self._verbose:
            print "len:",len(signal)

        phase=0 # Current phase offset
        alpha=2 # How many degrees is still fine.

        delay=0
        sdiff=2 # Timing check difference

        low = 0 # Number of signals below threshold

        if(self._samples_per_symbol<20):
            sdiff=1

        while True:
            if self._debug:
                self.peaks[i]=complex(-lmax,lmax/10.)

            """
            # Adjust our sample rate to reality
            try:
                cur=signal[i].real
                pre=signal[i-self._samples_per_symbol].real
                post=signal[i+self._samples_per_symbol].real
                curpre=signal[i-sdiff].real
                curpost=signal[i+sdiff].real

                if pre<0 and post<0 and cur>0:
                    if curpre>cur and cur>curpost:
                        if self._verbose:
                            print "Sampled late"
                        i-=sdiff
                        delay-=sdiff
                    if curpre<cur and cur<curpost:
                        if self._verbose:
                            print "Sampled early"
                        i+=sdiff
                        delay-=sdiff
                elif pre>0 and post>0 and cur<0:
                    if curpre>cur and cur>curpost:
                        if self._verbose:
                            print "Sampled early"
                        i+=sdiff
                        delay+=sdiff
                    if curpre<cur and cur<curpost:
                        if self._verbose:
                            print "Sampled late"
                        i-=sdiff
                        delay-=sdiff
                else:
                    cur=signal[i].imag
                    pre=signal[i-self._samples_per_symbol].imag
                    post=signal[i+self._samples_per_symbol].imag
                    curpre=signal[i-sdiff].imag
                    curpost=signal[i+sdiff].imag

                    if pre<0 and post<0 and cur>0:
                        if curpre>cur and cur>curpost:
                            if self._verbose:
                                print "Sampled late"
                            i-=sdiff
                            delay-=sdiff
                        if curpre<cur and cur<curpost:
                            if self._verbose:
                                print "Sampled early"
                            i+=sdiff
                            delay+=sdiff
                    elif pre>0 and post>0 and cur<0:
                        if curpre>cur and cur>curpost:
                            if self._verbose:
                                print "Sampled early"
                            i+=sdiff
                            delay+=sdiff
                        if curpre<cur and cur<curpost:
                            if self._verbose:
                                print "Sampled late"
                            i-=sdiff
                            delay-=sdiff
            except IndexError:
                if self._verbose:
                    print "Last sample"
            """

            lvl= abs(signal[i])/level
            ang= cmath.phase(signal[i])/math.pi*180
            symbol,offset = self.qpsk(ang+phase)

            phase += offset/5.

            """
            if(offset>alpha):
                if self._debug:
                    try:
                        self.peaks[i+self._samples_per_symbol/10]=complex(-lmax*0.8,0);
                    except IndexError:
                        if self._verbose:
                            print "Last sample"
                if self._verbose:
                    print "offset forward"
                phase+=sdiff
            if(offset<-alpha):
                if self._debug:
                    self.peaks[i-self._samples_per_symbol/10]=complex(-lmax*0.8,0);
                if self._verbose:
                    print "offset backward"
                phase-=sdiff

            """
            symbols=symbols+[symbol]
            if self._debug:
                self.samples=self.samples+[signal[i]]

            if self._verbose:
                print "Symbol @%06d (%3d°,%3.0f%%)=%d delay=%d phase=%d"%(i,ang%360,lvl*100,symbol,delay,phase)
            if self._debug:
                self.peaks[i]=complex(+lmax,mapping[symbol]*lmax/5.)
                self.turned_signal[i:i+self._samples_per_symbol] = signal[i:i+self._samples_per_symbol] * cmath.rect(1,numpy.radians(phase))
            i+=self._samples_per_symbol

            if i>=len(signal) : break

            if abs(signal[i]) < lmax/8.:
                low += 1
                if low > 2:
                    break

        if self._verbose:
            print "Done."

        access=""
        for s in symbols[:iridium.UW_LENGTH]:
            access+=str(s)

        # Do gray code on symbols
        data=""
        oldsym=0
        dataarray=[]
        for s in symbols:
            bits=(s-oldsym)%4
            if bits==0:
                bits=0
            elif bits==1:
                bits=2
            elif bits==2:
                bits=3
            else:
                bits=1
            oldsym=s
            data+=str((bits&2)/2)+str(bits&1)
            dataarray+=[(bits&2)/2,bits&1]

        if access == UW_DOWNLINK or access == UW_UPLINK:
            access_ok = True
        else:
            access_ok = False

        lead_out = "100101111010110110110011001111"
        lead_out_ok = lead_out in data

        if lead_out_ok:
            # TODO: Check if we are above 1626 MHz
            data = data[:data.find(lead_out)]
            self._nsymbols = (len(data) + len(lead_out)) / 2
            self._errors = self._errors[:self._nsymbols]

        error_count = self._errors.count('1')
        confidence = (1-float(error_count)/self._nsymbols)*100

        self._real_freq_offset=phase/360.*iridium.SYMBOLS_PER_SECOND/self._nsymbols

        if self._verbose:
            print "access:",access_ok,"(%s)"%access
            print "leadout:",lead_out_ok
            print "len:",self._nsymbols
            print "confidence:",confidence
            print "data:",data
            print "final delay",delay
            print "final phase",phase
            print "frequency offset:", self._real_freq_offset

        if access_ok:
            data="<"+data[:iridium.UW_LENGTH*2]+"> "+data[iridium.UW_LENGTH*2:]

        data=re.sub(r'([01]{32})',r'\1 ',data)

        if return_final_offset:
            return (dataarray, data, access_ok, lead_out_ok, confidence, level, self._nsymbols,self._real_freq_offset)
        else:
            return (dataarray, data, access_ok, lead_out_ok, confidence, level, self._nsymbols)

