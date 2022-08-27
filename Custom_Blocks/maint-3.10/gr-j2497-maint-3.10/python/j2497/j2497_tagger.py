#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright 2020 gr-j2497 author.
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


import numpy
from gnuradio import gr
import pmt

class j2497_tagger(gr.sync_block):
    """
    docstring for block j2497_tagger
    """
    def __init__(self):
        gr.sync_block.__init__(self,
            name="j2497_tagger",
            in_sig=[numpy.complex64, numpy.float32],
            out_sig=[numpy.complex64])
	
        self.scanning = True
        self.threshold = 210
        self.peak_index = 0
        self.fill_start_buffer = False
        self.tag_offset = 0
        self.start_buffer = numpy.array([], dtype=numpy.float32)

    def work(self, input_items, output_items):
        in0 = input_items[0]
        in1 = input_items[1]
	
        out = output_items[0]
        
        # Tag First Peak by Detecting Four Peaks Spaced 100 Samples Apart
        if self.scanning is True and len(in1>0):
            for n in range(0,len(in1),5):
            
                # Detect Candidate Starts
                if in1[n] > self.threshold or self.fill_start_buffer is True:	
                    self.fill_start_buffer = True	
                    
                    # Gather Small Buffer for Detecting Peaks
                    if len(self.start_buffer) < 500:
                        if len(self.start_buffer) + len(in1[n:]) >= 500:
                            self.start_buffer = numpy.append(self.start_buffer, in1[n:])
                        else:
                            self.start_buffer = numpy.append(self.start_buffer, in1[n:])
                            self.tag_offset = self.tag_offset-len(self.start_buffer)
                            
                    # Start Buffer is Full
                    if len(self.start_buffer) >= 500:
                        
                        # Find Peak in Start Buffer
                        get_max_index = 0
                        for m in range(0,100):                           
                            
                            # Get Center of Peak
                            if self.start_buffer[m] > self.threshold:                               
                                get_max_index = numpy.argmax(self.start_buffer[m:m+20])	   
                                break
                        
                        # Make Tag in Complex Stream
                        if (self.start_buffer[get_max_index+100] > self.threshold) and (self.start_buffer[get_max_index+200] > self.threshold) and (self.start_buffer[get_max_index+300] > self.threshold):
                            start_tag_estimate = self.nitems_written(0)+self.tag_offset+n+get_max_index
                            if start_tag_estimate-self.nitems_written(0) < 0:
                                start_tag_estimate = self.nitems_written(0)
                            key = pmt.intern("burst")
                            value = pmt.intern("start")
                            self.add_item_tag(0, start_tag_estimate, key, value)
                            self.peak_index = n+get_max_index
                            self.scanning = False
                            self.start_buffer = numpy.array([], dtype=numpy.float32)
                            self.fill_start_buffer = False
                            self.tag_offset = 0
                            break
                        
                        # False Positive    
                        else:
                            self.start_buffer = numpy.array([], dtype=numpy.float32)
                            self.fill_start_buffer = False
                            self.tag_offset = 0
                            n = n+50
                       
        # Tag Last Peak    
        if self.scanning is False:
            last_index = 0
            
            # Update for Windows Less than 100
            if self.peak_index > len(in1):
                self.peak_index = self.peak_index - len(in1)
            else:
                # Find the End of the Peaks
                for nn in range(self.peak_index,len(in1),100):
                    last_index = nn
                    
                    # Make Tag in Complex Stream
                    if in1[nn] < self.threshold:
                        key = pmt.intern("burst")
                        value = pmt.intern("end")
                        self.add_item_tag(0, self.nitems_written(0)+nn, key, value)
                        self.scanning = True
                        break
                
                # Remember Index at the End of Window
                self.peak_index = 100-(len(in1)-last_index)
        
        out[:] = in0
        return len(output_items[0])

