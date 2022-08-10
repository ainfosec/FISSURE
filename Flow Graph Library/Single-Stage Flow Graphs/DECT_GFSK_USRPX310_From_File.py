#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#
# SPDX-License-Identifier: GPL-3.0
#
# GNU Radio Python Flow Graph
# Title: Dect Gfsk Usrpx310 From File
# GNU Radio version: 3.8.1.0

from gnuradio import blocks
import pmt
from gnuradio import digital
from gnuradio import gr
from gnuradio.filter import firdes
import sys
import signal
from argparse import ArgumentParser
from gnuradio.eng_arg import eng_float, intx
from gnuradio import eng_notation
from gnuradio import uhd
import time

class DECT_GFSK_USRPX310_From_File(gr.top_block):

    def __init__(self):
        gr.top_block.__init__(self, "Dect Gfsk Usrpx310 From File")

        ##################################################
        # Variables
        ##################################################
        self.tx_usrp_gain = tx_usrp_gain = 30
        self.tx_usrp_channel = tx_usrp_channel = "A:0"
        self.tx_usrp_antenna = tx_usrp_antenna = "TX/RX"
        self.tx_frequency = tx_frequency = 1926.720e6
        self.sample_rate = sample_rate = 3.456e6
        self.notes = notes = "Modulates a previously-recorded DECT packet."
        self.ip_address = ip_address = "192.168.40.2"
        self.filepath = filepath = "/home/user/FISSURE/Attack Recordings/DECT_Data"

        ##################################################
        # Blocks
        ##################################################
        self.uhd_usrp_sink_0_0 = uhd.usrp_sink(
            ",".join(("addr=" + ip_address, "")),
            uhd.stream_args(
                cpu_format="fc32",
                args='',
                channels=list(range(0,1)),
            ),
            '',
        )
        self.uhd_usrp_sink_0_0.set_subdev_spec(tx_usrp_channel, 0)
        self.uhd_usrp_sink_0_0.set_center_freq(tx_frequency, 0)
        self.uhd_usrp_sink_0_0.set_gain(tx_usrp_gain, 0)
        self.uhd_usrp_sink_0_0.set_antenna(tx_usrp_antenna, 0)
        self.uhd_usrp_sink_0_0.set_samp_rate(sample_rate)
        self.uhd_usrp_sink_0_0.set_time_unknown_pps(uhd.time_spec())
        self.digital_gmsk_mod_0 = digital.gmsk_mod(
            samples_per_symbol=3,
            bt=0.35,
            verbose=False,
            log=False)
        self.blocks_file_source_0 = blocks.file_source(gr.sizeof_char*1, filepath, True, 0, 0)
        self.blocks_file_source_0.set_begin_tag(pmt.PMT_NIL)
        self.blocks_delay_0 = blocks.delay(gr.sizeof_gr_complex*1, 1000000)



        ##################################################
        # Connections
        ##################################################
        self.connect((self.blocks_delay_0, 0), (self.uhd_usrp_sink_0_0, 0))
        self.connect((self.blocks_file_source_0, 0), (self.digital_gmsk_mod_0, 0))
        self.connect((self.digital_gmsk_mod_0, 0), (self.blocks_delay_0, 0))

    def get_tx_usrp_gain(self):
        return self.tx_usrp_gain

    def set_tx_usrp_gain(self, tx_usrp_gain):
        self.tx_usrp_gain = tx_usrp_gain
        self.uhd_usrp_sink_0_0.set_gain(self.tx_usrp_gain, 0)

    def get_tx_usrp_channel(self):
        return self.tx_usrp_channel

    def set_tx_usrp_channel(self, tx_usrp_channel):
        self.tx_usrp_channel = tx_usrp_channel

    def get_tx_usrp_antenna(self):
        return self.tx_usrp_antenna

    def set_tx_usrp_antenna(self, tx_usrp_antenna):
        self.tx_usrp_antenna = tx_usrp_antenna
        self.uhd_usrp_sink_0_0.set_antenna(self.tx_usrp_antenna, 0)

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

    def get_notes(self):
        return self.notes

    def set_notes(self, notes):
        self.notes = notes

    def get_ip_address(self):
        return self.ip_address

    def set_ip_address(self, ip_address):
        self.ip_address = ip_address

    def get_filepath(self):
        return self.filepath

    def set_filepath(self, filepath):
        self.filepath = filepath
        self.blocks_file_source_0.open(self.filepath, True)



def main(top_block_cls=DECT_GFSK_USRPX310_From_File, options=None):
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
