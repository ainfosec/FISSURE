#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#
# SPDX-License-Identifier: GPL-3.0
#
# GNU Radio Python Flow Graph
# Title: Sniffer Tagged Stream
# GNU Radio version: 3.10.1.1

from gnuradio import blocks
from gnuradio import gr
from gnuradio.filter import firdes
from gnuradio.fft import window
import sys
import signal
from argparse import ArgumentParser
from gnuradio.eng_arg import eng_float, intx
from gnuradio import eng_notation
from gnuradio import gr, pdu
from gnuradio import zeromq
import gnuradio.ainfosec as ainfosec




class Sniffer_tagged_stream(gr.top_block):

    def __init__(self):
        gr.top_block.__init__(self, "Sniffer Tagged Stream", catch_exceptions=True)

        ##################################################
        # Variables
        ##################################################
        self.port = port = 50001
        self.address = address = "127.0.0.1:5066"

        ##################################################
        # Blocks
        ##################################################
        self.zeromq_sub_source_0_0 = zeromq.sub_source(gr.sizeof_char, 1, "tcp://" + address, 100, True, -1, '')
        self.pdu_tagged_stream_to_pdu_0 = pdu.tagged_stream_to_pdu(gr.types.byte_t, 'packet_len')
        self.blocks_throttle_0_0 = blocks.throttle(gr.sizeof_char*1, 250000,True)
        self.blocks_tagged_stream_align_0 = blocks.tagged_stream_align(gr.sizeof_char*1, 'packet_len')
        self.ainfosec_UDP_to_Wireshark_Async_0 = ainfosec.UDP_to_Wireshark_Async(port)


        ##################################################
        # Connections
        ##################################################
        self.msg_connect((self.pdu_tagged_stream_to_pdu_0, 'pdus'), (self.ainfosec_UDP_to_Wireshark_Async_0, 'in'))
        self.connect((self.blocks_tagged_stream_align_0, 0), (self.blocks_throttle_0_0, 0))
        self.connect((self.blocks_throttle_0_0, 0), (self.pdu_tagged_stream_to_pdu_0, 0))
        self.connect((self.zeromq_sub_source_0_0, 0), (self.blocks_tagged_stream_align_0, 0))


    def get_port(self):
        return self.port

    def set_port(self, port):
        self.port = port

    def get_address(self):
        return self.address

    def set_address(self, address):
        self.address = address




def main(top_block_cls=Sniffer_tagged_stream, options=None):
    tb = top_block_cls()

    def sig_handler(sig=None, frame=None):
        tb.stop()
        tb.wait()

        sys.exit(0)

    signal.signal(signal.SIGINT, sig_handler)
    signal.signal(signal.SIGTERM, sig_handler)

    tb.start()

    try:
        input('Press Enter to quit: ')
    except EOFError:
        pass
    tb.stop()
    tb.wait()


if __name__ == '__main__':
    main()
