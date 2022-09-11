#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#
# SPDX-License-Identifier: GPL-3.0
#
# GNU Radio Python Flow Graph
# Title: Wifi Default Limesdr Relay
# GNU Radio version: 3.10.1.1

from gnuradio import gr
from gnuradio.filter import firdes
from gnuradio.fft import window
import sys
import signal
from argparse import ArgumentParser
from gnuradio.eng_arg import eng_float, intx
from gnuradio import eng_notation
import gnuradio.limesdr as limesdr




class Wifi_Default_LimeSDR_Relay(gr.top_block):

    def __init__(self):
        gr.top_block.__init__(self, "Wifi Default Limesdr Relay", catch_exceptions=True)

        ##################################################
        # Variables
        ##################################################
        self.tx_gain = tx_gain = 60
        self.tx_frequency = tx_frequency = 2432e6
        self.tx_channel = tx_channel = 0
        self.sample_rate = sample_rate = 20e6
        self.rx_gain = rx_gain = 60
        self.rx_frequency = rx_frequency = 2412e6
        self.rx_channel = rx_channel = 0
        self.notes = notes = "Relays Wifi signals from one frequency to another."

        ##################################################
        # Blocks
        ##################################################
        self.limesdr_source_0 = limesdr.source('', rx_channel, '')

        self.limesdr_sink_0 = limesdr.sink('', tx_channel, '', '')



        ##################################################
        # Connections
        ##################################################
        self.connect((self.limesdr_source_0, 0), (self.limesdr_sink_0, 0))


    def get_tx_gain(self):
        return self.tx_gain

    def set_tx_gain(self, tx_gain):
        self.tx_gain = tx_gain
        self.limesdr_sink_0.set_gain(int(self.tx_gain),0)
        self.limesdr_sink_0.set_gain(int(self.tx_gain),1)

    def get_tx_frequency(self):
        return self.tx_frequency

    def set_tx_frequency(self, tx_frequency):
        self.tx_frequency = tx_frequency
        self.limesdr_sink_0.set_center_freq(self.tx_frequency, 0)

    def get_tx_channel(self):
        return self.tx_channel

    def set_tx_channel(self, tx_channel):
        self.tx_channel = tx_channel

    def get_sample_rate(self):
        return self.sample_rate

    def set_sample_rate(self, sample_rate):
        self.sample_rate = sample_rate

    def get_rx_gain(self):
        return self.rx_gain

    def set_rx_gain(self, rx_gain):
        self.rx_gain = rx_gain
        self.limesdr_source_0.set_gain(int(self.rx_gain),0)
        self.limesdr_source_0.set_gain(int(self.rx_gain),1)

    def get_rx_frequency(self):
        return self.rx_frequency

    def set_rx_frequency(self, rx_frequency):
        self.rx_frequency = rx_frequency
        self.limesdr_source_0.set_center_freq(self.rx_frequency, 0)

    def get_rx_channel(self):
        return self.rx_channel

    def set_rx_channel(self, rx_channel):
        self.rx_channel = rx_channel

    def get_notes(self):
        return self.notes

    def set_notes(self, notes):
        self.notes = notes




def main(top_block_cls=Wifi_Default_LimeSDR_Relay, options=None):
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
