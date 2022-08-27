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

from gnuradio import gr, gr_unittest
from gnuradio import blocks
from txtime_bursts_tagger import txtime_bursts_tagger
#from transmitter.txtime_bursts_tagger import txtime_bursts_tagger
from pmt import *

def make_time_hint_msg(time_hint):
    return cons( dict_add(make_dict(), intern("time_hint"), from_double(time_hint)),PMT_NIL)

def make_fn_time_msg(fn_ref, time_ref):
    return cons( dict_add(make_dict(), intern("fn_time"), cons(from_uint64(fn_ref), from_double(time_ref))),PMT_NIL)

class qa_txtime_bursts_tagger (gr_unittest.TestCase):

    def setUp (self):
        self.tb = gr.top_block ()

    def tearDown (self):
        self.tb = None

    def test_001_t (self):
        tb  = self.tb
        time_ref = 0
        fn_ref = 0
        dut = txtime_bursts_tagger(fn_ref, time_ref)

        framenumbers_input = [1259192, 1076346, 1076242, 235879, 1259218]
        timeslots_input = [6, 3, 4, 3, 5]
        bursts_input = [
            "0001100001000111100111101111100101000100101011000010011110011101001111101100010100111111100000110100011111101011101100100111110011000100010001010000",
            "0001000101000000001001111110000110010110110111110111101000001101001111101100010100111111001110001001110101110001010001000111011010010001011011000000",
            "0001001101101101000111001000101011001101001110110001001100111101001111101100010100111111111001001010011010011111010010010101011001001011011100110000",
            "0000010010100000001001101010100001011100010001101100111111101101001111101100010100111111101101001110100010101110010110101111100010010000110010110000",
        ]
        
        src = gsm.burst_source(framenumbers_input, timeslots_input, bursts_input)
        sink = gsm.burst_sink()
        
        self.tb.msg_connect(src, "out", dut, "bursts")
        self.tb.msg_connect(dut, "bursts", sink, "in")
        
        tb.start()
        tb.wait()
        print("Dupa")
        print(sink)
        
        
#        msg1 = make_msg(1,"lol1")
#        msg2 = make_msg(1,"lol2")
#        msg3 = make_msg(2,"lol1")
#        msg4 = make_msg(2,"lol1")
#        
#        port = intern("msgs")

#        tb.msg_connect(g,"msgs",dbg,"store")
#        #tb.msg_connect(g,"msgs",dbg,"print_pdu")

#        tb.start()

#        g.to_basic_block()._post(port, msg1)
#        g.to_basic_block()._post(port, msg3)
#        g.to_basic_block()._post(port, msg2)
#        g.to_basic_block()._post(port, msg4)



#        while dbg.num_messages() < 4:
#            time.sleep(0.1)

#        tb.stop()
#        tb.wait()
#        print dbg.get_message(0)
#        print get_id(dbg.get_message(0))
#        
#        self.assertEqual(get_id(dbg.get_message(0)),1)
#        self.assertEqual(get_id(dbg.get_message(1)),1)
#        self.assertEqual(get_id(dbg.get_message(2)),2)
#        self.assertEqual(get_id(dbg.get_message(3)),2)



if __name__ == '__main__':
    gr_unittest.run(qa_txtime_bursts_tagger)
