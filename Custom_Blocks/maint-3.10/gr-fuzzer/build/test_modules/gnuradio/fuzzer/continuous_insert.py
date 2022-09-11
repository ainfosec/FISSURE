#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2022 gr-fuzzer author.
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

class continuous_insert(gr.sync_block):
    """
    docstring for block continuous_insert
    """
    def __init__(self):
        gr.sync_block.__init__(self,
            name="continuous_insert",
            in_sig=[numpy.uint8],
            out_sig=[numpy.uint8])

        self.message_vector = vector
        self.new_vector = vector
        self.message_port_register_in(pmt.intern("packet_in"))
        self.set_msg_handler(pmt.intern("packet_in"), self.set_vector)
        self.index = 0
        self.reset = 0            


    def work(self, input_items, output_items):
        in0 = input_items[0]
        out = output_items[0]
        
        input_len = len(input_items[0])

        for n in range(0,input_len):
            out[n] = self.message_vector[self.index]
                        
            if self.index >= len(self.message_vector)-1:
                self.index = 0
            else:
                self.index = self.index + 1

        if self.reset == 1:
            #print("RESET!!!!")
            self.message_vector = self.new_vector
            self.index = 0
            self.reset = 0
        
        return len(output_items[0])


    def set_vector(self,vector):
        #print("SET VECTOR!")
        #print(vector)

        self.new_vector = []
        for n in range(0,pmt.length(vector)):
            new_value = numpy.uint8(pmt.to_python(pmt.nth(n,vector)))
            self.new_vector.append(new_value)

        self.reset = 1
