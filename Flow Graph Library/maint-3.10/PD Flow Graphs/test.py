#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#
# SPDX-License-Identifier: GPL-3.0
#
# GNU Radio Python Flow Graph
# Title: Test
# Description: Generic demodulation flow graph for MSK signals.
# GNU Radio version: 3.10.7.0

from gnuradio import blocks
from gnuradio import gr
from gnuradio.filter import firdes
from gnuradio.fft import window
import sys
import signal
from argparse import ArgumentParser
from gnuradio.eng_arg import eng_float, intx
from gnuradio import eng_notation
from gnuradio import uhd
import time
import numpy




class test(gr.top_block):

    def __init__(self):
        gr.top_block.__init__(self, "Test", catch_exceptions=True)

        ##################################################
        # Variables
        ##################################################
        self.time_out = time_out = 100
        self.signal_type = signal_type = "MSK"
        self.sample_rate = sample_rate = 2000000
        self.rx_usrp_gain = rx_usrp_gain = 30
        self.rx_usrp_channel = rx_usrp_channel = "A:0"
        self.rx_usrp_antenna = rx_usrp_antenna = "TX/RX"
        self.rx_frequency = rx_frequency = 2425.729695e6
        self.nbits_prior = nbits_prior = 32
        self.min_burst_size = min_burst_size = 100
        self.max_burst_size = max_burst_size = 100000
        self.ip_address = ip_address = "192.168.40.2"
        self.baud_rate = baud_rate = 250000
        self.address = address = "*:5066"

        ##################################################
        # Blocks
        ##################################################

        self.uhd_usrp_source_0 = uhd.usrp_source(
            ",".join(("addr=" + ip_address, "")),
            uhd.stream_args(
                cpu_format="fc32",
                args='',
                channels=list(range(0,1)),
            ),
        )
        self.uhd_usrp_source_0.set_clock_source('internal', 0)
        self.uhd_usrp_source_0.set_subdev_spec(rx_usrp_channel, 0)
        self.uhd_usrp_source_0.set_samp_rate(sample_rate)
        self.uhd_usrp_source_0.set_time_unknown_pps(uhd.time_spec(0))

        self.uhd_usrp_source_0.set_center_freq(rx_frequency, 0)
        self.uhd_usrp_source_0.set_antenna(rx_usrp_antenna, 0)
        self.uhd_usrp_source_0.set_bandwidth(sample_rate, 0)
        self.uhd_usrp_source_0.set_gain(rx_usrp_gain, 0)
        self.blocks_null_sink_0 = blocks.null_sink(gr.sizeof_gr_complex*1)


        ##################################################
        # Connections
        ##################################################
        self.connect((self.uhd_usrp_source_0, 0), (self.blocks_null_sink_0, 0))


    def get_time_out(self):
        return self.time_out

    def set_time_out(self, time_out):
        self.time_out = time_out

    def get_signal_type(self):
        return self.signal_type

    def set_signal_type(self, signal_type):
        self.signal_type = signal_type

    def get_sample_rate(self):
        return self.sample_rate

    def set_sample_rate(self, sample_rate):
        self.sample_rate = sample_rate
        self.uhd_usrp_source_0.set_samp_rate(self.sample_rate)
        self.uhd_usrp_source_0.set_bandwidth(self.sample_rate, 0)

    def get_rx_usrp_gain(self):
        return self.rx_usrp_gain

    def set_rx_usrp_gain(self, rx_usrp_gain):
        self.rx_usrp_gain = rx_usrp_gain
        self.uhd_usrp_source_0.set_gain(self.rx_usrp_gain, 0)

    def get_rx_usrp_channel(self):
        return self.rx_usrp_channel

    def set_rx_usrp_channel(self, rx_usrp_channel):
        self.rx_usrp_channel = rx_usrp_channel

    def get_rx_usrp_antenna(self):
        return self.rx_usrp_antenna

    def set_rx_usrp_antenna(self, rx_usrp_antenna):
        self.rx_usrp_antenna = rx_usrp_antenna
        self.uhd_usrp_source_0.set_antenna(self.rx_usrp_antenna, 0)

    def get_rx_frequency(self):
        return self.rx_frequency

    def set_rx_frequency(self, rx_frequency):
        self.rx_frequency = rx_frequency
        self.uhd_usrp_source_0.set_center_freq(self.rx_frequency, 0)

    def get_nbits_prior(self):
        return self.nbits_prior

    def set_nbits_prior(self, nbits_prior):
        self.nbits_prior = nbits_prior

    def get_min_burst_size(self):
        return self.min_burst_size

    def set_min_burst_size(self, min_burst_size):
        self.min_burst_size = min_burst_size

    def get_max_burst_size(self):
        return self.max_burst_size

    def set_max_burst_size(self, max_burst_size):
        self.max_burst_size = max_burst_size

    def get_ip_address(self):
        return self.ip_address

    def set_ip_address(self, ip_address):
        self.ip_address = ip_address

    def get_baud_rate(self):
        return self.baud_rate

    def set_baud_rate(self, baud_rate):
        self.baud_rate = baud_rate

    def get_address(self):
        return self.address

    def set_address(self, address):
        self.address = address




def main(top_block_cls=test, options=None):
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
