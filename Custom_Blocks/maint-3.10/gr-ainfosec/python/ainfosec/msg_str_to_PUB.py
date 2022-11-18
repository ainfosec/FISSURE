#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2022 gr-ainfosec author.
#
# SPDX-License-Identifier: GPL-3.0-or-later
#


import numpy
from gnuradio import gr
import pmt
import zmq

class msg_str_to_PUB(gr.basic_block):
    """
    docstring for block msg_str_to_PUB
    """
    def __init__(self,address):
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
        self.sock.send_string(str(msg))
