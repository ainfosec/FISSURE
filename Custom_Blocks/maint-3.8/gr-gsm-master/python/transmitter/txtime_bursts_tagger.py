#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @file
# @author Piotr Krysik <ptrkrysik@gmail.com>
# @section LICENSE
# 
# Gr-gsm is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3, or (at your option)
# any later version.
# 
# Gr-gsm is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with gr-gsm; see the file COPYING.  If not, write to
# the Free Software Foundation, Inc., 51 Franklin Street,
# Boston, MA 02110-1301, USA.
# 
# 

from gnuradio import gr
from .fn_time import fn_time_delta
import pmt
import numpy

class txtime_bursts_tagger(gr.basic_block):
    """
    A block that adds txtime metadata to a burst
    """
    def __init__(self, init_fn=0, init_time=0, time_hint=None, timing_advance=0, delay_correction=0):
        gr.basic_block.__init__(self,
            name="txtime_bursts_tagger",
            in_sig=[],
            out_sig=[])
        self.set_fn_time_reference(init_fn, init_time)
        if time_hint is not None:
            self.set_time_hint(time_hint)

        self.timing_advance = timing_advance
        self.delay_correction = delay_correction

        self.message_port_register_in(pmt.intern("fn_time"))
        self.message_port_register_in(pmt.intern("bursts"))
        self.message_port_register_out(pmt.intern("bursts"))

        self.set_msg_handler(pmt.intern("fn_time"), self.process_fn_time_reference)
        self.set_msg_handler(pmt.intern("bursts"), self.process_txtime_of_burst)
        
    def process_fn_time_reference(self, msg):
        time_hint = pmt.to_python(pmt.dict_ref(msg, pmt.intern("time_hint"), pmt.PMT_NIL))
        fn_time = pmt.to_python(pmt.dict_ref(msg, pmt.intern("fn_time"), pmt.PMT_NIL))

        if time_hint is not None:
            self.time_hint = time_hint
        elif fn_time is not None:
            self.fn_ref = fn_time[0][0]
            self.ts = fn_time[0][1]
            full = fn_time[1][0]
            frac = fn_time[1][1]
        
            self.time_ref = full+frac
            self.time_hint = self.time_ref
             
    def process_txtime_of_burst(self, msg):
        burst_with_header = pmt.to_python(pmt.cdr(msg))
        fn = burst_with_header[11]+burst_with_header[10]*2**8+burst_with_header[9]*2**16+burst_with_header[8]*2**24
        ts_num = burst_with_header[3]
        if self.fn_ref is not None:
          fn_delta, txtime = fn_time_delta(self.fn_ref, self.time_ref, fn, self.time_hint, ts_num)
          txtime_corrected = txtime - self.delay_correction
          txtime_final = txtime_corrected - self.timing_advance
          
          txtime_secs = int(txtime_final)
          txtime_fracs = txtime_final-int(txtime_final)
          #print "txtime_secs",txtime_secs,"txtime_fracs",txtime_fracs
          tags_dict = pmt.dict_add(pmt.make_dict(), pmt.intern("tx_time"), pmt.make_tuple(pmt.from_uint64(txtime_secs),pmt.from_double(txtime_fracs)))
          tags_dict = pmt.dict_add(tags_dict, pmt.intern("fn"), pmt.from_uint64(fn))
          new_msg = pmt.cons(tags_dict, pmt.cdr(msg))
          self.message_port_pub(pmt.intern("bursts"), new_msg)
        
    def set_fn_time_reference(self, init_fn, init_time):
        self.fn_ref = init_fn
        self.time_ref = init_time
        self.set_time_hint(init_time)

    def set_time_hint(self, time_hint):
        self.time_hint = time_hint

    def set_delay_correction(delay_correction):
        self.delay_correction = delay_correction
        
    def set_timing_advance(timing_advance):
        self.timing_advance = timing_advance
        
