#!/usr/bin/env python2
# -*- coding: utf-8 -*-
##################################################
# GNU Radio Python Flow Graph
# Title: Iq Recorder Usrp X410
# GNU Radio version: 3.7.13.5
##################################################


from gnuradio import blocks
from gnuradio import eng_notation
from gnuradio import gr
from gnuradio import uhd
from gnuradio.eng_option import eng_option
from gnuradio.filter import firdes
from optparse import OptionParser
import time


class iq_recorder_usrp_x410(gr.top_block):

    def __init__(self):
        gr.top_block.__init__(self, "Iq Recorder Usrp X410")

        ##################################################
        # Variables
        ##################################################
        self.sample_rate = sample_rate = 1
        self.rx_gain = rx_gain = 20
        self.rx_frequency = rx_frequency = 2412
        self.rx_channel = rx_channel = "A:0"
        self.rx_antenna = rx_antenna = "TX/RX"
        self.ip_address = ip_address = "192.168.40.2"
        self.filepath = filepath = ""
        self.file_length = file_length = 100000

        ##################################################
        # Blocks
        ##################################################
        self.uhd_usrp_source_0_0 = uhd.usrp_source(
        	",".join(("addr="+ip_address, "")),
        	uhd.stream_args(
        		cpu_format="fc32",
        		channels=range(1),
        	),
        )
        self.uhd_usrp_source_0_0.set_subdev_spec(rx_channel, 0)
        self.uhd_usrp_source_0_0.set_samp_rate(float(sample_rate)*1e6)
        self.uhd_usrp_source_0_0.set_center_freq(float(rx_frequency)*1e6, 0)
        self.uhd_usrp_source_0_0.set_gain(float(rx_gain), 0)
        self.uhd_usrp_source_0_0.set_antenna(rx_antenna, 0)
        self.uhd_usrp_source_0_0.set_auto_dc_offset(True, 0)
        self.uhd_usrp_source_0_0.set_auto_iq_balance(True, 0)
        self.blocks_skiphead_0 = blocks.skiphead(gr.sizeof_gr_complex*1, 200000)
        self.blocks_head_0 = blocks.head(gr.sizeof_gr_complex*1, file_length)
        self.blocks_file_sink_0 = blocks.file_sink(gr.sizeof_gr_complex*1, filepath, False)
        self.blocks_file_sink_0.set_unbuffered(False)



        ##################################################
        # Connections
        ##################################################
        self.connect((self.blocks_head_0, 0), (self.blocks_file_sink_0, 0))
        self.connect((self.blocks_skiphead_0, 0), (self.blocks_head_0, 0))
        self.connect((self.uhd_usrp_source_0_0, 0), (self.blocks_skiphead_0, 0))

    def get_sample_rate(self):
        return self.sample_rate

    def set_sample_rate(self, sample_rate):
        self.sample_rate = sample_rate
        self.uhd_usrp_source_0_0.set_samp_rate(float(self.sample_rate)*1e6)

    def get_rx_gain(self):
        return self.rx_gain

    def set_rx_gain(self, rx_gain):
        self.rx_gain = rx_gain
        self.uhd_usrp_source_0_0.set_gain(float(self.rx_gain), 0)


    def get_rx_frequency(self):
        return self.rx_frequency

    def set_rx_frequency(self, rx_frequency):
        self.rx_frequency = rx_frequency
        self.uhd_usrp_source_0_0.set_center_freq(float(self.rx_frequency)*1e6, 0)

    def get_rx_channel(self):
        return self.rx_channel

    def set_rx_channel(self, rx_channel):
        self.rx_channel = rx_channel

    def get_rx_antenna(self):
        return self.rx_antenna

    def set_rx_antenna(self, rx_antenna):
        self.rx_antenna = rx_antenna
        self.uhd_usrp_source_0_0.set_antenna(self.rx_antenna, 0)

    def get_ip_address(self):
        return self.ip_address

    def set_ip_address(self, ip_address):
        self.ip_address = ip_address

    def get_filepath(self):
        return self.filepath

    def set_filepath(self, filepath):
        self.filepath = filepath
        self.blocks_file_sink_0.open(self.filepath)

    def get_file_length(self):
        return self.file_length

    def set_file_length(self, file_length):
        self.file_length = file_length
        self.blocks_head_0.set_length(self.file_length)


def main(top_block_cls=iq_recorder_usrp_x410, options=None):

    tb = top_block_cls()
    tb.start()
    tb.wait()


if __name__ == '__main__':
    main()
