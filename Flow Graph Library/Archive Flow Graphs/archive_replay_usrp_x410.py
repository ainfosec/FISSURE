#!/usr/bin/env python2
# -*- coding: utf-8 -*-
##################################################
# GNU Radio Python Flow Graph
# Title: Archive Replay Usrp X410
# GNU Radio version: 3.7.13.5
##################################################


from gnuradio import blocks
from gnuradio import eng_notation
from gnuradio import gr
from gnuradio import uhd
from gnuradio.eng_option import eng_option
from gnuradio.filter import firdes
from optparse import OptionParser
import pmt
import time


class archive_replay_usrp_x410(gr.top_block):

    def __init__(self):
        gr.top_block.__init__(self, "Archive Replay Usrp X410")

        ##################################################
        # Variables
        ##################################################
        self.tx_gain = tx_gain = 30
        self.tx_frequency = tx_frequency = 2425.715e6
        self.tx_channel = tx_channel = "A:0"
        self.sample_rate = sample_rate = 4e6
        self.ip_address = ip_address = "192.168.40.2"
        self.filepath = filepath = ""

        ##################################################
        # Blocks
        ##################################################
        self.uhd_usrp_sink_0 = uhd.usrp_sink(
        	",".join(("ip_addr="+ip_address, "")),
        	uhd.stream_args(
        		cpu_format="fc32",
        		channels=range(1),
        	),
        )
        self.uhd_usrp_sink_0.set_subdev_spec(tx_channel, 0)
        self.uhd_usrp_sink_0.set_samp_rate(float(sample_rate))
        self.uhd_usrp_sink_0.set_center_freq(float(tx_frequency), 0)
        self.uhd_usrp_sink_0.set_gain(float(tx_gain), 0)
        self.uhd_usrp_sink_0.set_antenna('TX/RX', 0)
        self.blocks_file_source_0 = blocks.file_source(gr.sizeof_gr_complex*1, filepath, True)
        self.blocks_file_source_0.set_begin_tag(pmt.PMT_NIL)



        ##################################################
        # Connections
        ##################################################
        self.connect((self.blocks_file_source_0, 0), (self.uhd_usrp_sink_0, 0))

    def get_tx_gain(self):
        return self.tx_gain

    def set_tx_gain(self, tx_gain):
        self.tx_gain = tx_gain
        self.uhd_usrp_sink_0.set_gain(float(self.tx_gain), 0)


    def get_tx_frequency(self):
        return self.tx_frequency

    def set_tx_frequency(self, tx_frequency):
        self.tx_frequency = tx_frequency
        self.uhd_usrp_sink_0.set_center_freq(float(self.tx_frequency), 0)

    def get_tx_channel(self):
        return self.tx_channel

    def set_tx_channel(self, tx_channel):
        self.tx_channel = tx_channel

    def get_sample_rate(self):
        return self.sample_rate

    def set_sample_rate(self, sample_rate):
        self.sample_rate = sample_rate
        self.uhd_usrp_sink_0.set_samp_rate(float(self.sample_rate))

    def get_ip_address(self):
        return self.ip_address

    def set_ip_address(self, ip_address):
        self.ip_address = ip_address

    def get_filepath(self):
        return self.filepath

    def set_filepath(self, filepath):
        self.filepath = filepath
        self.blocks_file_source_0.open(self.filepath, True)


def main(top_block_cls=archive_replay_usrp_x410, options=None):

    tb = top_block_cls()
    tb.start()
    tb.wait()


if __name__ == '__main__':
    main()
