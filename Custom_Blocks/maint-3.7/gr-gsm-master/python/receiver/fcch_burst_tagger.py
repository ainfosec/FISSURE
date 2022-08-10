#!/usr/bin/env python2
# -*- coding: utf-8 -*-
# @file
# @author (C) 2014 by Piotr Krysik <ptrkrysik@gmail.com>
# @section LICENSE
# 
# This is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3, or (at your option)
# any later version.
# 
# This software is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this software; see the file COPYING.  If not, write to
# the Free Software Foundation, Inc., 51 Franklin Street,
# Boston, MA 02110-1301, USA.
# 

from numpy import *
#from pylab import *
from gnuradio import gr
import pmt
from chirpz import ZoomFFT

class fcch_burst_tagger(gr.sync_block):
    """
    docstring for block fcch_burst_tagger
    """
    def __init__(self, OSR):
        gr.sync_block.__init__(self,
            name="fcch_burst_tagger",
            in_sig=[complex64, float32],
            out_sig=[complex64])

        self.state=False
        self.symbol_rate = 1625000/6
        self.OSR=OSR
        self.samp_rate = self.symbol_rate*OSR
        self.burst_size = int(156.25*self.OSR)
        self.guard_period = int(round(8.25*self.OSR))
        self.block_size = self.burst_size+self.guard_period
        self.processed_block_size = int(142*self.OSR)
        self.set_history(self.block_size)
        self.set_output_multiple(self.guard_period)
        self.prev_offset=0
        
        #parameters of zoomfft frequency estimator
        f1 = self.symbol_rate/4*0.9
        f2 = self.symbol_rate/4*1.1
        m=5000*self.OSR
        self.zoomfft = ZoomFFT(self.processed_block_size, f1, f2, m, Fs=self.samp_rate)
        self.f_axis = linspace(f1,f2,m)

    def work(self, input_items, output_items):
        in0=input_items[0]
        output_items[0][:] = in0[self.history()-1:]

        threshold = input_items[1][self.history()-1:]
        threshold_diff = diff(concatenate([[0],threshold]))
        up_to_high_indexes = nonzero(threshold_diff>0)[0]

        up_to_high_idx=[] 
        
        for up_to_high_idx in up_to_high_indexes:         #look for "high" value at the trigger
            if up_to_high_idx==0 and self.state==True:    #if it's not transition from "low" to "high"
                continue                                  #then continue
            self.state=True                               #if found - change state
        
        if self.state==True and up_to_high_idx and any(threshold_diff<0):          #and look for transition from high to low
            last_up_to_high_idx = up_to_high_idx
            last_high_to_low_idx = nonzero(threshold_diff<0)[0][-1]
            
            if last_high_to_low_idx-last_up_to_high_idx>0:
                coarse_idx = int(last_high_to_low_idx+self.history()-self.block_size)
                inst_freq = angle(in0[coarse_idx:coarse_idx+self.block_size]*in0[coarse_idx-self.OSR:coarse_idx+self.block_size-self.OSR].conj())/(2*pi)*self.symbol_rate #instantaneus frequency estimate
                precise_idx = self.find_best_position(inst_freq)
#                measured_freq = mean(inst_freq[precise_idx:precise_idx+self.processed_block_size])
                expected_freq = self.symbol_rate/4
                
                print "input_items:",len(in0)
                print "coarse_idx",coarse_idx
                print "coarse_idx+precise_idx",coarse_idx+precise_idx
                
                zoomed_spectrum = abs(self.zoomfft(in0[coarse_idx+precise_idx:coarse_idx+precise_idx+self.processed_block_size]))
                measured_freq = self.f_axis[argmax(zoomed_spectrum)]
                freq_offset = measured_freq - expected_freq
                offset = self.nitems_written(0) + coarse_idx + precise_idx - self.guard_period
                key = pmt.string_to_symbol("fcch")
                value =  pmt.from_double(freq_offset)
                self.add_item_tag(0,offset, key, value)
                self.state=False

#   Some additional plots and prints for debugging
#                print "coarse_idx+precise_idx",coarse_idx+precise_idx
#                print "offset-self.nitems_written(0):",offset-self.nitems_written(0)
                print offset-self.prev_offset
                self.prev_offset=offset
                print "freq offset", freq_offset
#                freq_offset = measured_freq - expected_freq
#                plot(self.f_axis, zoomed_spectrum)
#                show()
#                plot(inst_freq[precise_idx:precise_idx+self.burst_size])
#                show()
#                plot(unwrap(angle(in0[coarse_idx+precise_idx:coarse_idx+precise_idx+self.burst_size])))
#                show()
#                
        return len(output_items[0])

    def find_best_position(self, inst_freq):
        lowest_max_min_diff = 1e6 #1e6 - just some large value
        start_pos = 0
        
        for ii in xrange(0,int(2*self.guard_period)):
            min_inst_freq = min(inst_freq[ii:self.processed_block_size+ii-1]);
            max_inst_freq = max(inst_freq[ii:self.processed_block_size+ii-1]);

            if (lowest_max_min_diff > max_inst_freq - min_inst_freq):
                lowest_max_min_diff = max_inst_freq - min_inst_freq;
                start_pos = ii
#                print 'start_pos',start_pos
        
#        plot(xrange(start_pos,start_pos+self.processed_block_size),inst_freq[start_pos:start_pos+self.processed_block_size],'r.')
#        hold(True)
#        plot(inst_freq)
#        show()
        
        return start_pos
