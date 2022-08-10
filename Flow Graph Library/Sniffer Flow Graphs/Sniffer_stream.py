#!/usr/bin/env python2
# -*- coding: utf-8 -*-
##################################################
# GNU Radio Python Flow Graph
# Title: Sniffer Stream
# Generated: Sat Oct 16 12:17:44 2021
##################################################


from gnuradio import blocks
from gnuradio import eng_notation
from gnuradio import gr
from gnuradio import zeromq
from gnuradio.eng_option import eng_option
from gnuradio.filter import firdes
from optparse import OptionParser
import ainfosec


class Sniffer_stream(gr.top_block):

    def __init__(self):
        gr.top_block.__init__(self, "Sniffer Stream")

        ##################################################
        # Variables
        ##################################################
        self.port = port = 50001
        self.address = address = "127.0.0.1:5066"

        ##################################################
        # Blocks
        ##################################################
        self.zeromq_sub_source_0_0 = zeromq.sub_source(gr.sizeof_char, 1, "tcp://" + address, 100, True, -1)
        self.blocks_throttle_0_0 = blocks.throttle(gr.sizeof_char*1, 250000,True)
        self.ainfosec_UDP_to_Wireshark_0 = ainfosec.UDP_to_Wireshark(int(port))

        ##################################################
        # Connections
        ##################################################
        self.connect((self.blocks_throttle_0_0, 0), (self.ainfosec_UDP_to_Wireshark_0, 0))
        self.connect((self.zeromq_sub_source_0_0, 0), (self.blocks_throttle_0_0, 0))

    def get_port(self):
        return self.port

    def set_port(self, port):
        self.port = port

    def get_address(self):
        return self.address

    def set_address(self, address):
        self.address = address


def main(top_block_cls=Sniffer_stream, options=None):

    tb = top_block_cls()
    tb.start()
    try:
        raw_input('Press Enter to quit: ')
    except EOFError:
        pass
    tb.stop()
    tb.wait()


if __name__ == '__main__':
    main()
