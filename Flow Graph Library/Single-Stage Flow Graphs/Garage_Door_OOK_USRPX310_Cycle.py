#!/usr/bin/env python2
# -*- coding: utf-8 -*-
##################################################
# GNU Radio Python Flow Graph
# Title: Garage Door Ook Usrpx310 Cycle
# Generated: Sun Sep 19 09:33:05 2021
##################################################


from gnuradio import blocks
from gnuradio import eng_notation
from gnuradio import gr
from gnuradio import uhd
from gnuradio.eng_option import eng_option
from gnuradio.filter import firdes
from optparse import OptionParser
import garage_door
import time


class Garage_Door_OOK_USRPX310_Cycle(gr.top_block):

    def __init__(self):
        gr.top_block.__init__(self, "Garage Door Ook Usrpx310 Cycle")

        ##################################################
        # Variables
        ##################################################
        self.tx_usrp_gain = tx_usrp_gain = 30
        self.tx_usrp_frequency = tx_usrp_frequency = 310.4e6
        self.tx_usrp_channel = tx_usrp_channel = "A:0"
        self.tx_usrp_antenna = tx_usrp_antenna = "TX/RX"
        self.starting_dip = starting_dip = 0
        self.sample_rate = sample_rate = 1e6
        self.notes = notes = "Cycles through DIP switch combinations sequentially."
        self.ip_address = ip_address = "192.168.40.2"
        self.dip_interval = dip_interval = 0.001
        self.bursts_per_dip = bursts_per_dip = 5
        self.burst_interval = burst_interval = 0.02

        ##################################################
        # Blocks
        ##################################################
        self.uhd_usrp_sink_0 = uhd.usrp_sink(
        	",".join(("addr=" + ip_address, "")),
        	uhd.stream_args(
        		cpu_format="fc32",
        		channels=range(1),
        	),
        )
        self.uhd_usrp_sink_0.set_subdev_spec(tx_usrp_channel, 0)
        self.uhd_usrp_sink_0.set_samp_rate(sample_rate)
        self.uhd_usrp_sink_0.set_center_freq(tx_usrp_frequency, 0)
        self.uhd_usrp_sink_0.set_gain(tx_usrp_gain, 0)
        self.uhd_usrp_sink_0.set_antenna(tx_usrp_antenna, 0)
        self.garage_door_message_cycler_0 = garage_door.message_cycler(sample_rate,dip_interval,starting_dip,bursts_per_dip,burst_interval)
        self.blocks_null_source_0 = blocks.null_source(gr.sizeof_gr_complex*1)
        self.blocks_multiply_const_vxx_0 = blocks.multiply_const_vcc((0.9, ))

        ##################################################
        # Connections
        ##################################################
        self.connect((self.blocks_multiply_const_vxx_0, 0), (self.uhd_usrp_sink_0, 0))
        self.connect((self.blocks_null_source_0, 0), (self.garage_door_message_cycler_0, 0))
        self.connect((self.garage_door_message_cycler_0, 0), (self.blocks_multiply_const_vxx_0, 0))

    def get_tx_usrp_gain(self):
        return self.tx_usrp_gain

    def set_tx_usrp_gain(self, tx_usrp_gain):
        self.tx_usrp_gain = tx_usrp_gain
        self.uhd_usrp_sink_0.set_gain(self.tx_usrp_gain, 0)


    def get_tx_usrp_frequency(self):
        return self.tx_usrp_frequency

    def set_tx_usrp_frequency(self, tx_usrp_frequency):
        self.tx_usrp_frequency = tx_usrp_frequency
        self.uhd_usrp_sink_0.set_center_freq(self.tx_usrp_frequency, 0)

    def get_tx_usrp_channel(self):
        return self.tx_usrp_channel

    def set_tx_usrp_channel(self, tx_usrp_channel):
        self.tx_usrp_channel = tx_usrp_channel

    def get_tx_usrp_antenna(self):
        return self.tx_usrp_antenna

    def set_tx_usrp_antenna(self, tx_usrp_antenna):
        self.tx_usrp_antenna = tx_usrp_antenna
        self.uhd_usrp_sink_0.set_antenna(self.tx_usrp_antenna, 0)

    def get_starting_dip(self):
        return self.starting_dip

    def set_starting_dip(self, starting_dip):
        self.starting_dip = starting_dip
        self.garage_door_message_cycler_0.set_dip(self.starting_dip)

    def get_sample_rate(self):
        return self.sample_rate

    def set_sample_rate(self, sample_rate):
        self.sample_rate = sample_rate
        self.uhd_usrp_sink_0.set_samp_rate(self.sample_rate)
        self.garage_door_message_cycler_0.set_sample_rate(self.sample_rate)

    def get_notes(self):
        return self.notes

    def set_notes(self, notes):
        self.notes = notes

    def get_ip_address(self):
        return self.ip_address

    def set_ip_address(self, ip_address):
        self.ip_address = ip_address

    def get_dip_interval(self):
        return self.dip_interval

    def set_dip_interval(self, dip_interval):
        self.dip_interval = dip_interval
        self.garage_door_message_cycler_0.set_dip_interval(self.dip_interval)

    def get_bursts_per_dip(self):
        return self.bursts_per_dip

    def set_bursts_per_dip(self, bursts_per_dip):
        self.bursts_per_dip = bursts_per_dip
        self.garage_door_message_cycler_0.set_bpd(self.bursts_per_dip)

    def get_burst_interval(self):
        return self.burst_interval

    def set_burst_interval(self, burst_interval):
        self.burst_interval = burst_interval
        self.garage_door_message_cycler_0.set_burst_interval(self.burst_interval)


def main(top_block_cls=Garage_Door_OOK_USRPX310_Cycle, options=None):

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
