#!/usr/bin/env python2
# -*- coding: utf-8 -*-
##################################################
# GNU Radio Python Flow Graph
# Title: Sniffer Async
# Generated: Sat Feb 12 22:26:45 2022
##################################################


from gnuradio import eng_notation
from gnuradio import gr
from gnuradio import zeromq
from gnuradio.eng_option import eng_option
from gnuradio.filter import firdes
from optparse import OptionParser
import ainfosec


class Sniffer_async(gr.top_block):

    def __init__(self):
        gr.top_block.__init__(self, "Sniffer Async")

        ##################################################
        # Variables
        ##################################################
        self.port = port = 50001
        self.address = address = "127.0.0.1:5066"

        ##################################################
        # Blocks
        ##################################################
        self.zeromq_sub_msg_source_0 = zeromq.sub_msg_source("tcp://" + address, 100)
        self.ainfosec_UDP_to_Wireshark_Async_0 = ainfosec.UDP_to_Wireshark_Async(port)

        ##################################################
        # Connections
        ##################################################
        self.msg_connect((self.zeromq_sub_msg_source_0, 'out'), (self.ainfosec_UDP_to_Wireshark_Async_0, 'in'))

    def get_port(self):
        return self.port

    def set_port(self, port):
        self.port = port

    def get_address(self):
        return self.address

    def set_address(self, address):
        self.address = address


def main(top_block_cls=Sniffer_async, options=None):

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
