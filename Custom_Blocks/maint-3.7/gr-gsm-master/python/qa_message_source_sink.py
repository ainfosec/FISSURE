#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @file
# @author (C) 2015 by Roman Khassraf <rkhassraf@gmail.com>
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

from gnuradio import gr, gr_unittest, blocks
import grgsm_swig as grgsm
import os
import pmt
import sys
import tempfile

class qa_message_source_sink (gr_unittest.TestCase):
   
    def setUp (self):
        self.tb = gr.top_block()
        self.tmpfile = tempfile.NamedTemporaryFile()
                
    def tearDown (self):
        self.tmpfile.close()
        
    #def getOutput(self):
        #self.tmpfile.seek(0)
        #return self.tmpfile.read()
    
    #def getOutputExpected(self, expected_lines):
        #out = ""
        #for l in expected_lines:
            #out = out + l + "\n"
        #return out

    def test_001_no_prefix_no_header (self):
        """
            Four messages, without any prefix, no gsmtap header
        """
        msgs_input = [
            "02 04 01 00 00 00 c9 00 00 1d 3c e5 02 00 01 00 15 06 21 00 01 f0 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b",
            #"02 04 01 00 00 00 ca 00 00 1d 3c e9 02 00 02 00 15 06 21 00 01 f0 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b",
            #"02 04 01 00 00 00 cb 00 00 1d 3d 0e 01 00 00 00 59 06 1a 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ff e5 04 00",
            #"02 04 01 00 00 00 cb 00 00 1d 3d 12 02 00 00 00 15 06 21 00 01 f0 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b"
        ]
        
        # there is a whitespace at the beginning of message_printer output
        msgs_expected = [
            "02 04 01 00 00 00 c9 00 00 1d 3c e5 02 00 01 00 15 06 21 00 01 f0 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b",
            #"02 04 01 00 00 00 ca 00 00 1d 3c e9 02 00 02 00 15 06 21 00 01 f0 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b",
            #" 59 06 1a 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 ff e5 04 00",
            #" 15 06 21 00 01 f0 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b"
        ]
        
        src = grgsm.message_source(msgs_input)
        file_sink = grgsm.message_file_sink(self.tmpfile.name)
        
        #printer = grgsm.message_printer(pmt.intern(""), False)
        #self.tb.msg_connect(src, "msgs", printer, "msgs")
        self.tb.run()

        #self.assertEqual(self.getOutput(), self.getOutputExpected(msgs_expected))
       
        
if __name__ == '__main__':
    gr_unittest.run(qa_message_source_sink, "qa_message_source_sink.xml")
