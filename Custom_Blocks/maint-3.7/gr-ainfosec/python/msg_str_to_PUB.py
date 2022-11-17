#!/usr/bin/env python
# -*- coding: utf-8 -*-
# 
# Copyright 2022 gr-ainfosec author.
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
import zmq

class msg_str_to_PUB(gr.basic_block):
    """
    docstring for block msg_str_to_PUB
    """
    def __init__(self, address):
        gr.basic_block.__init__(self,
            name="msg_str_to_PUB",
            in_sig=None,
            out_sig=None)
            
        self.message_port_register_in(pmt.intern("Message"))
        self.set_msg_handler(pmt.intern("Message"), self.handle_msg)
        
        ctx = zmq.Context()
        self.sock = ctx.socket(zmq.PUB)
        self.sock.bind(address)
        
    def handle_msg(self, msg):
        # print("NEW MESSAGE")
        # print(str(msg))
        self.sock.send_string(str(msg))
