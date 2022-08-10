#!/usr/bin/env python
# -*- coding: utf-8 -*-
# 
# Copyright 2016 Free Software Foundation, Inc.
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
import time
import gr_iridium

class iridium_frame_printer(gr.sync_block):
    """
    docstring for block iridium_frame_printer
    """
    def __init__(self):
        gr.sync_block.__init__(self,
            name="iridium_frame_printer",
            in_sig=None,
            out_sig=None)

        self._file_info = "i-%d-t1" % time.time()
        self.message_port_register_in(gr.pmt.intern('pdus'))
        self.set_msg_handler(gr.pmt.intern('pdus'), self.handle_msg)

    def handle_msg(self, msg_pmt):
        meta = gr.pmt.to_python(gr.pmt.car(msg_pmt))
        msg = gr.pmt.cdr(msg_pmt)
        bits = gr.pmt.u8vector_elements(msg)
        timestamp = meta['timestamp']
        freq = meta['center_frequency']
        id = meta['id']
        confidence = meta['confidence']
        level = meta['level']
        n_symbols = meta['n_symbols']
        data = ''.join([str(x) for x in bits])
        print "RAW: %s %07d %010d A:OK I:%011d %3d%% %.3f %3d %s"%(self._file_info, timestamp, freq, id,
            confidence, level, (n_symbols - gr_iridium.UW_LENGTH), data)

    def work(self, input_items, output_items):
        return len(input_items[0])

