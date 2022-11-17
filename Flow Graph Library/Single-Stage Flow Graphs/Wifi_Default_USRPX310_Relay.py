#!/usr/bin/env python2
# -*- coding: utf-8 -*-
##################################################
# GNU Radio Python Flow Graph
# Title: Wifi Default Usrpx310 Relay
# GNU Radio version: 3.7.13.5
##################################################


from gnuradio import eng_notation
from gnuradio import gr
from gnuradio import uhd
from gnuradio.eng_option import eng_option
from gnuradio.filter import firdes
from optparse import OptionParser
import time


class Wifi_Default_USRPX310_Relay(gr.top_block):

    def __init__(self):
        gr.top_block.__init__(self, "Wifi Default Usrpx310 Relay")

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
        		channels=range(1),
        	),
        )
        self.uhd_usrp_source_0_0.set_subdev_spec(usrp_channel, 0)
        self.uhd_usrp_source_0_0.set_samp_rate(sample_rate)
        self.uhd_usrp_source_0_0.set_center_freq(rx_frequency, 0)
        self.uhd_usrp_source_0_0.set_gain(rx_usrp_gain, 0)
        self.uhd_usrp_source_0_0.set_antenna('RX2', 0)
        self.uhd_usrp_source_0_0.set_auto_dc_offset(True, 0)
        self.uhd_usrp_source_0_0.set_auto_iq_balance(True, 0)
        self.uhd_usrp_sink_0_0 = uhd.usrp_sink(
        	",".join(("addr=" + ip_address, "")),
        	uhd.stream_args(
        		cpu_format="fc32",
        		channels=range(1),
        	),
        )
        self.uhd_usrp_sink_0_0.set_subdev_spec(usrp_channel, 0)
        self.uhd_usrp_sink_0_0.set_samp_rate(sample_rate)
        self.uhd_usrp_sink_0_0.set_center_freq(tx_frequency, 0)
        self.uhd_usrp_sink_0_0.set_gain(tx_usrp_gain, 0)
        self.uhd_usrp_sink_0_0.set_antenna('TX/RX', 0)



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
        self.uhd_usrp_source_0_0.set_samp_rate(self.sample_rate)
        self.uhd_usrp_sink_0_0.set_samp_rate(self.sample_rate)

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
    tb.start()
    try:
        raw_input('Press Enter to quit: ')
    except EOFError:
        pass
    tb.stop()
    tb.wait()


if __name__ == '__main__':
    main()
