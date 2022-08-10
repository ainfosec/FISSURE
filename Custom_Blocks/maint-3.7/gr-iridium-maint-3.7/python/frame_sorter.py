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

class frame_sorter(gr.sync_block):
    """
    docstring for block frame_sorter
    """
    def __init__(self):
        gr.sync_block.__init__(self,
            name="frame_sorter",
            in_sig=None,
            out_sig=None)

        self._messages = []
        self.message_port_register_in(gr.pmt.intern('pdus'))
        self.message_port_register_out(gr.pmt.intern('pdus'))
        self.set_msg_handler(gr.pmt.intern('pdus'), self.handle_msg)

    def handle_msg(self, msg_pmt):
        meta = gr.pmt.to_python(gr.pmt.car(msg_pmt))
        timestamp = meta['timestamp']
        freq = meta['center_frequency']
        confidence = meta['confidence']

        remove_count = 0
        for message in self._messages:
            if timestamp - message['meta']['timestamp'] > 1000:
                self.message_port_pub(gr.pmt.intern('pdus'), gr.pmt.cons(gr.pmt.to_pmt(message['meta']), gr.pmt.to_pmt(message['data'])))
                remove_count += 1
            else:
                break
        self._messages = self._messages[remove_count:]

        insert_index = 0
        for message in self._messages:
            if message['meta']['timestamp'] > timestamp:
                break
            if message['meta']['timestamp'] == timestamp and message['meta']['center_frequency'] > freq:
                break
            insert_index += 1

        def dup(a, b):
            if (abs(a['meta']['timestamp'] - b['meta']['timestamp']) <= 1 and
                abs(a['meta']['center_frequency'] - b['meta']['center_frequency']) < 10000):
                return True
            return False

        def offset_ok(offset):
            return insert_index + offset >= 0 and insert_index + offset < len(self._messages)

        message = {'meta': meta, 'data': gr.pmt.to_python(gr.pmt.cdr(msg_pmt))}

        replace_index = None

        if offset_ok(0):
            if dup(self._messages[insert_index], message):
                if self._messages[insert_index]['meta']['confidence'] < confidence:
                    replace_index = insert_index
                else:
                    return

        offset = 1
        while replace_index is None:
            if offset_ok(+offset):
                if dup(self._messages[insert_index + offset], message):
                    if self._messages[insert_index + offset]['meta']['confidence'] < confidence:
                        replace_index = insert_index + offset
                        break
                    else:
                        return

            if offset_ok(-offset):
                if dup(self._messages[insert_index - offset], message):
                    if self._messages[insert_index - offset]['meta']['confidence'] < confidence:
                        replace_index = insert_index - offset
                        break
                    else:
                        return

            if ((not offset_ok(-offset) or abs(self._messages[insert_index - offset]['meta']['timestamp'] - timestamp) > 1) and
                    (not offset_ok(+offset)  or abs(self._messages[insert_index + offset]['meta']['timestamp'] - timestamp) > 1)):
                break
            offset += 1

        if replace_index is not None:
            self._messages[replace_index] = message
        else:
            self._messages.insert(insert_index, message)

    def work(self, input_items, output_items):
        return len(input_items[0])

