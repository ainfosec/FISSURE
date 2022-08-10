#!/usr/bin/env python
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
from scipy.ndimage.filters import uniform_filter1d

class sch_receiver():
    """
    docstring for class sch_reciever
    """
    def __init__(self, OSR):
        self.sync_seq = array([1, 0, 1, 1, 1, 0, 0, 1, 0, 1, 1, 0, 0, 0, 1, 0,
                               0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1,
                               0, 0, 1, 0, 1, 1, 0, 1, 0, 1, 0, 0, 0, 1, 0, 1,
                               0, 1, 1, 1, 0, 1, 1, 0, 0, 0, 0, 1, 1, 0, 1, 1])
        self.OSR = OSR
        sync_seq_msk_tmp = self.msk_mod(self.sync_seq, -1j)
        self.sync_seq_msk = sync_seq_msk_tmp[5:59]
        self.sync_seq_msk_interp = zeros(self.OSR*len(self.sync_seq_msk), dtype=complex64)
        self.sync_seq_msk_interp[::OSR] = self.sync_seq_msk
        self.L = 5

    def msk_mod(self, x, start_point):
        x_nrz = 2*x-1 
        x_diffenc = x_nrz[1:]*x_nrz[0:-1]
        mod_tmp = concatenate((array([start_point]),1j*x_diffenc))
        return cumprod(mod_tmp)
    
    def get_chan_imp_resp(self, sch_burst):
        sch_burst_bl = resize(array(sch_burst), (int(len(sch_burst)/self.OSR),self.OSR))
        correlation_bl = zeros(shape(sch_burst_bl), dtype=complex64)
        for ii in xrange(0,self.OSR):
            correlation_bl[:,ii]=correlate(sch_burst_bl[:,ii],self.sync_seq_msk,'same')
        
        correlation_bl = correlation_bl/len(self.sync_seq_msk)
        power_bl_mov_avg = uniform_filter1d(abs(correlation_bl)**2,self.L+1,mode='constant',axis=0)

        print "correlation_bl.argmax()",argmax(abs(correlation_bl))
        print "power_bl_mov_avg.argmax()",(power_bl_mov_avg).argmax()
        print 'unravel_index(correlation_bl.argmax(), correlation_bl.shape)',unravel_index(argmax(abs(correlation_bl)), correlation_bl.shape)
        print 'unravel_index(power_bl_mov_avg.argmax(), power_bl_mov_avg.shape)',unravel_index(power_bl_mov_avg.argmax(), power_bl_mov_avg.shape)
        (r_corrmax, c_corrmax)=unravel_index(argmax(abs(correlation_bl)), correlation_bl.shape)
        (r_powmax, c_powmax)=unravel_index(power_bl_mov_avg.argmax(), power_bl_mov_avg.shape)
        
#        correlation = zeros(shape(sch_burst))
#        correlation = correlate(sch_burst, self.sync_seq_msk_interp,'same')/len(self.sync_seq_msk)
#        print "pozycja maksimum",argmax(abs(correlation))
#        plot(abs(hstack(correlation_bl))*1000)
##        hold(True)
##        plot(abs(sch_burst)*500)
##        print shape(range(0,len(sch_burst),self.OSR))
##        print shape(correlation_bl[:,0])
#        for ii in range(0,self.OSR):
#            if ii == c_powmax:
#                plot(range(ii,len(correlation_bl[:,0])*self.OSR,self.OSR),power_bl_mov_avg[:,ii]*5e6,'g.')
#            else:
#                plot(range(ii,len(correlation_bl[:,0])*self.OSR,self.OSR),power_bl_mov_avg[:,ii]*5e6,'r.')
#        show()
#        figure()
        print 'r_powmax: ',r_powmax
#        plot(abs(correlation_bl[range(r_powmax-(self.L+1)/2+1,r_powmax+(self.L+1)/2+1), c_powmax]),'g')
#        hold(True)
#        plot(abs(correlation_bl[range(r_corrmax-(self.L+1)/2+1,r_corrmax+(self.L+1)/2+1), c_corrmax]),'r')
#        show()
        
    def receive(self, input_corr, chan_imp_resp):
        pass

class sch_detector(gr.sync_block):
    """
    docstring for block sch_detector
    """
    def __init__(self, OSR):
        gr.sync_block.__init__(self,
            name="sch_detector",
            in_sig=[complex64],
            out_sig=[complex64])
        self.OSR = OSR
        self.states = {"waiting_for_fcch_tag":1, "reaching_sch_burst":2, "sch_at_input_buffer":3}
        self.state = self.states["waiting_for_fcch_tag"]
        self.sch_offset = -100 #-100 - just some invalid value of sch burst position in the stream
        self.burst_size = int(round(156.25*self.OSR))
        self.guard_period = int(round(8.25*self.OSR))
        self.block_size = self.burst_size + self.guard_period
        self.set_history(self.block_size)
        self.set_output_multiple(self.guard_period)
        self.sch_receiver = sch_receiver(OSR)
        
    def work(self, input_items, output_items):
        in0 = input_items[0]
        out = output_items[0]
        to_consume = len(in0)-self.history()
        
        if self.state == self.states["waiting_for_fcch_tag"]:
            fcch_tags = []
            
            start = self.nitems_written(0)
            stop = start + len(in0)
            key = pmt.string_to_symbol("fcch")
            fcch_tags = self.get_tags_in_range(0, start, stop, key)
            if fcch_tags:
                self.sch_offset = fcch_tags[0].offset + int(round(8*self.burst_size+0*self.guard_period)) #156.25 is number of GMSK symbols per timeslot, 
                                                                                       #8.25 is arbitrary safety margin in order to avoid cutting boundary of SCH burst
                self.state = self.states["reaching_sch_burst"]
            
        elif self.state == self.states["reaching_sch_burst"]:
            samples_left = self.sch_offset-self.nitems_written(0)
            if samples_left <= len(in0)-self.history():
                to_consume = samples_left
                self.state = self.states["sch_at_input_buffer"]

        elif self.state == self.states["sch_at_input_buffer"]:
            offset = self.nitems_written(0)
            key = pmt.string_to_symbol("sch")
            value =  pmt.from_double(0)
            self.add_item_tag(0,offset, key, value)
            self.state = self.states["waiting_for_fcch_tag"]
            self.sch_receiver.get_chan_imp_resp(in0[0:self.block_size+self.guard_period])
#            plot(unwrap(angle(in0[0:2*self.block_size])))
#            show()

        out[:] = in0[self.history()-1:]
        return to_consume
        
    def get_OSR(self):
        return self.OSR

    def set_OSR(self, OSR):
        self.OSR = OSR
        self.burst_size = int(round(156.25*self.OSR))
        self.guard_period = int(round(8.25*self.OSR))
        self.block_size = self.burst_size + self.guard_period
        self.set_history(self.block_size)
        self.sch_receiver = sch_receiver(OSR)

