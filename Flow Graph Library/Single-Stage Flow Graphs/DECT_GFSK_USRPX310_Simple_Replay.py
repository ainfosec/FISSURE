#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#
# SPDX-License-Identifier: GPL-3.0
#
# GNU Radio Python Flow Graph
# Title: Dect Gfsk Usrpx310 Simple Replay
# GNU Radio version: 3.10.1.1

from gnuradio import analog
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




class DECT_GFSK_USRPX310_Simple_Replay(gr.top_block):

    def __init__(self):
        gr.top_block.__init__(self, "Dect Gfsk Usrpx310 Simple Replay", catch_exceptions=True)

        ##################################################
        # Variables
        ##################################################
        self.tx_usrp_gain = tx_usrp_gain = 20
        self.tx_usrp_channel = tx_usrp_channel = "A:0"
        self.tx_usrp_antenna = tx_usrp_antenna = "TX/RX"
        self.tx_frequency = tx_frequency = 1921.536e6
        self.squelch_value = squelch_value = -23
        self.sample_rate = sample_rate = 8e6
        self.rx_usrp_gain = rx_usrp_gain = 20
        self.rx_usrp_channel = rx_usrp_channel = "A:0"
        self.rx_usrp_antenna = rx_usrp_antenna = "RX2"
        self.rx_frequency = rx_frequency = 1928.448e6
        self.notes = notes = "Relays a DECT signal to another frequency."
        self.ip_address = ip_address = "192.168.40.2"

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
        self.uhd_usrp_source_0.set_subdev_spec(rx_usrp_channel, 0)
        self.uhd_usrp_source_0.set_samp_rate(sample_rate)
        self.uhd_usrp_source_0.set_time_unknown_pps(uhd.time_spec(0))

        self.uhd_usrp_source_0.set_center_freq(rx_frequency, 0)
        self.uhd_usrp_source_0.set_antenna(rx_usrp_antenna, 0)
        self.uhd_usrp_source_0.set_gain(rx_usrp_gain, 0)
        self.uhd_usrp_sink_0 = uhd.usrp_sink(
            ",".join(("addr=" + ip_address, "")),
            uhd.stream_args(
                cpu_format="fc32",
                args='',
                channels=list(range(0,1)),
            ),
            '',
        )
        self.uhd_usrp_sink_0.set_subdev_spec(tx_usrp_channel, 0)
        self.uhd_usrp_sink_0.set_samp_rate(sample_rate)
        self.uhd_usrp_sink_0.set_time_unknown_pps(uhd.time_spec(0))

        self.uhd_usrp_sink_0.set_center_freq(tx_frequency, 0)
        self.uhd_usrp_sink_0.set_antenna(tx_usrp_antenna, 0)
        self.uhd_usrp_sink_0.set_gain(tx_usrp_gain, 0)
        self.analog_pwr_squelch_xx_0 = analog.pwr_squelch_cc(squelch_value, 0.5, 100, True)


        ##################################################
        # Connections
        ##################################################
        self.connect((self.analog_pwr_squelch_xx_0, 0), (self.uhd_usrp_sink_0, 0))
        self.connect((self.uhd_usrp_source_0, 0), (self.analog_pwr_squelch_xx_0, 0))


    def get_tx_usrp_gain(self):
        return self.tx_usrp_gain

    def set_tx_usrp_gain(self, tx_usrp_gain):
        self.tx_usrp_gain = tx_usrp_gain
        self.uhd_usrp_sink_0.set_gain(self.tx_usrp_gain, 0)

    def get_tx_usrp_channel(self):
        return self.tx_usrp_channel

    def set_tx_usrp_channel(self, tx_usrp_channel):
        self.tx_usrp_channel = tx_usrp_channel

    def get_tx_usrp_antenna(self):
        return self.tx_usrp_antenna

    def set_tx_usrp_antenna(self, tx_usrp_antenna):
        self.tx_usrp_antenna = tx_usrp_antenna
        self.uhd_usrp_sink_0.set_antenna(self.tx_usrp_antenna, 0)

    def get_tx_frequency(self):
        return self.tx_frequency

    def set_tx_frequency(self, tx_frequency):
        self.tx_frequency = tx_frequency
        self.uhd_usrp_sink_0.set_center_freq(self.tx_frequency, 0)

    def get_squelch_value(self):
        return self.squelch_value

    def set_squelch_value(self, squelch_value):
        self.squelch_value = squelch_value
        self.analog_pwr_squelch_xx_0.set_threshold(self.squelch_value)

    def get_sample_rate(self):
        return self.sample_rate

    def set_sample_rate(self, sample_rate):
        self.sample_rate = sample_rate
        self.uhd_usrp_sink_0.set_samp_rate(self.sample_rate)
        self.uhd_usrp_source_0.set_samp_rate(self.sample_rate)

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

    def get_notes(self):
        return self.notes

    def set_notes(self, notes):
        self.notes = notes

    def get_ip_address(self):
        return self.ip_address

    def set_ip_address(self, ip_address):
        self.ip_address = ip_address




def main(top_block_cls=DECT_GFSK_USRPX310_Simple_Replay, options=None):
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
