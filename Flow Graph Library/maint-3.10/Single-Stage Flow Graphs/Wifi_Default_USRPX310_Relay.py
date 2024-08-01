#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#
# SPDX-License-Identifier: GPL-3.0
#
# GNU Radio Python Flow Graph
# Title: Wifi Default Usrpx310 Relay
# GNU Radio version: 3.10.7.0

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




class Wifi_Default_USRPX310_Relay(gr.top_block):

    def __init__(self):
        gr.top_block.__init__(self, "Wifi Default Usrpx310 Relay", catch_exceptions=True)

        ##################################################
        # Variables
        ##################################################
        self.usrp_channel = usrp_channel = "A:0"
        self.tx_usrp_gain = tx_usrp_gain = 70
        self.tx_frequency = tx_frequency = 5175e6
        self.sample_rate = sample_rate = 20e6
        self.rx_usrp_gain = rx_usrp_gain = 50
        self.rx_frequency = rx_frequency = 2412e6
        self.notes = notes = "Relays Wifi signals from one frequency to another."
        self.ip_address = ip_address = "192.168.40.2"

        ##################################################
        # Blocks
        ##################################################

        self.uhd_usrp_source_0_0 = uhd.usrp_source(
            ",".join(("addr=" + ip_address, "")),
            uhd.stream_args(
                cpu_format="fc32",
                args='',
                channels=list(range(0,1)),
            ),
        )
        self.uhd_usrp_source_0_0.set_subdev_spec(usrp_channel, 0)
        self.uhd_usrp_source_0_0.set_samp_rate(sample_rate)
        self.uhd_usrp_source_0_0.set_time_unknown_pps(uhd.time_spec(0))

        self.uhd_usrp_source_0_0.set_center_freq(rx_frequency, 0)
        self.uhd_usrp_source_0_0.set_antenna('RX2', 0)
        self.uhd_usrp_source_0_0.set_gain(rx_usrp_gain, 0)
        self.uhd_usrp_sink_0_0 = uhd.usrp_sink(
            ",".join(("addr=" + ip_address, "")),
            uhd.stream_args(
                cpu_format="fc32",
                args='',
                channels=list(range(0,1)),
            ),
            '',
        )
        self.uhd_usrp_sink_0_0.set_subdev_spec(usrp_channel, 0)
        self.uhd_usrp_sink_0_0.set_samp_rate(sample_rate)
        self.uhd_usrp_sink_0_0.set_time_unknown_pps(uhd.time_spec(0))

        self.uhd_usrp_sink_0_0.set_center_freq(tx_frequency, 0)
        self.uhd_usrp_sink_0_0.set_antenna('TX/RX', 0)
        self.uhd_usrp_sink_0_0.set_gain(tx_usrp_gain, 0)


        ##################################################
        # Connections
        ##################################################
        self.connect((self.uhd_usrp_source_0_0, 0), (self.uhd_usrp_sink_0_0, 0))


    def get_usrp_channel(self):
        return self.usrp_channel

    def set_usrp_channel(self, usrp_channel):
        self.usrp_channel = usrp_channel

    def get_tx_usrp_gain(self):
        return self.tx_usrp_gain

    def set_tx_usrp_gain(self, tx_usrp_gain):
        self.tx_usrp_gain = tx_usrp_gain
        self.uhd_usrp_sink_0_0.set_gain(self.tx_usrp_gain, 0)

    def get_tx_frequency(self):
        return self.tx_frequency

    def set_tx_frequency(self, tx_frequency):
        self.tx_frequency = tx_frequency
        self.uhd_usrp_sink_0_0.set_center_freq(self.tx_frequency, 0)

    def get_sample_rate(self):
        return self.sample_rate

    def set_sample_rate(self, sample_rate):
        self.sample_rate = sample_rate
        self.uhd_usrp_sink_0_0.set_samp_rate(self.sample_rate)
        self.uhd_usrp_source_0_0.set_samp_rate(self.sample_rate)

    def get_rx_usrp_gain(self):
        return self.rx_usrp_gain

    def set_rx_usrp_gain(self, rx_usrp_gain):
        self.rx_usrp_gain = rx_usrp_gain
        self.uhd_usrp_source_0_0.set_gain(self.rx_usrp_gain, 0)

    def get_rx_frequency(self):
        return self.rx_frequency

    def set_rx_frequency(self, rx_frequency):
        self.rx_frequency = rx_frequency
        self.uhd_usrp_source_0_0.set_center_freq(self.rx_frequency, 0)

    def get_notes(self):
        return self.notes

    def set_notes(self, notes):
        self.notes = notes

    def get_ip_address(self):
        return self.ip_address

    def set_ip_address(self, ip_address):
        self.ip_address = ip_address




def main(top_block_cls=Wifi_Default_USRPX310_Relay, options=None):
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
