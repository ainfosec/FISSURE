#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2020 Free Software Foundation, Inc.
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
from . import gr_iridium_demod
from . import gr_iridium as iridium
import time

class iridium_qpsk_demod(gr.sync_block):
    """
    docstring for block iridium_qpsk_demod
    """
    def __init__(self, sample_rate, file_info=None):
        gr.sync_block.__init__(self,
            name="iridium-qpsk-demod",
            in_sig=None,
            out_sig=None)

        self._demod = gr_iridium_demod.Demod(sample_rate, verbose=False, debug=False)

        self._file_info = file_info
        if self._file_info == None:
            self._file_info = "i-%.1f-t1" % time.time()

        self._n_handled_bursts = 0
        self._n_access_ok_bursts = 0
        self.message_port_register_in(gr.pmt.intern('cpdus'))
        self.set_msg_handler(gr.pmt.intern('cpdus'), self.handle_msg)

    def handle_msg(self, msg_pmt):
        meta = gr.pmt.to_python(gr.pmt.car(msg_pmt))
        msg = gr.pmt.cdr(msg_pmt)

        if not gr.pmt.is_c32vector(msg):
            return

        signal = gr.pmt.c32vector_elements(msg)

        #{'center_frequency': 1625897344.0,
        # 'direction': 0L,
        # 'sample_rate': 250000.0,
        # 'uw_start': 160L}
        #print(meta)

        self._n_handled_bursts += 1
        dataarray, data, access_ok, lead_out_ok, confidence, level, nsymbols = self._demod.demod(signal, start_sample=meta['uw_start'])
        rawfile = self._file_info
        timestamp = meta['offset'] / meta['sample_rate'] * 1000
        freq = meta['center_frequency']
        print("RAW: %s %07d %010d A:%s L:%s %3d%% %.3f %3d %s"%(rawfile,timestamp,freq,("no","OK")[access_ok],("no","OK")[lead_out_ok],confidence,level,(nsymbols-iridium.UW_LENGTH),data))
        if access_ok:
            self._n_access_ok_bursts += 1


    def work(self, input_items, output_items):
        return len(input_items[0])

    def get_n_handled_bursts(self):
        return self._n_handled_bursts

    def get_n_access_ok_bursts(self):
        return self._n_access_ok_bursts
