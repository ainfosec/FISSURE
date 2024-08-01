#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#
# SPDX-License-Identifier: GPL-3.0
#
# GNU Radio Python Flow Graph
# Title: General General Usrpb2X0 Iq Record Squelch
# GNU Radio version: 3.8.5.0

from gnuradio import analog
from gnuradio import blocks
from gnuradio import gr
from gnuradio.filter import firdes
import sys
import signal
from argparse import ArgumentParser
from gnuradio.eng_arg import eng_float, intx
from gnuradio import eng_notation
from gnuradio import uhd
import time


class General_General_USRPB2x0_IQ_Record_Squelch(gr.top_block):

    def __init__(self):
        gr.top_block.__init__(self, "General General Usrpb2X0 Iq Record Squelch")

        ##################################################
        # Variables
        ##################################################
        self.squelch_threshold = squelch_threshold = -50
        self.squelch_ramp = squelch_ramp = 100
        self.squelch_alpha = squelch_alpha = 0.5
        self.serial = serial = "False"
        self.sample_rate = sample_rate = 1000000
        self.rx_gain = rx_gain = 70
        self.rx_frequency = rx_frequency = 2412e6
        self.rx_channel = rx_channel = "A:A"
        self.rx_antenna = rx_antenna = "TX/RX"
        self.filepath = filepath = ""
        self.file_length = file_length = 100000

        ##################################################
        # Blocks
        ##################################################
        self.uhd_usrp_source_0 = uhd.usrp_source(
            ",".join((serial, "")),
            uhd.stream_args(
                cpu_format="fc32",
                args='',
                channels=list(range(0,1)),
            ),
        )
        self.uhd_usrp_source_0.set_subdev_spec(rx_channel, 0)
        self.uhd_usrp_source_0.set_center_freq(float(rx_frequency), 0)
        self.uhd_usrp_source_0.set_gain(float(rx_gain), 0)
        self.uhd_usrp_source_0.set_antenna(rx_antenna, 0)
        self.uhd_usrp_source_0.set_samp_rate(float(sample_rate))
        self.uhd_usrp_source_0.set_time_unknown_pps(uhd.time_spec())
        self.blocks_skiphead_0 = blocks.skiphead(gr.sizeof_gr_complex*1, 200000)
        self.blocks_head_0 = blocks.head(gr.sizeof_gr_complex*1, file_length)
        self.blocks_file_sink_0 = blocks.file_sink(gr.sizeof_gr_complex*1, filepath, False)
        self.blocks_file_sink_0.set_unbuffered(False)
        self.analog_pwr_squelch_xx_0 = analog.pwr_squelch_cc(float(squelch_threshold), float(squelch_alpha), int(squelch_ramp), True)


        ##################################################
        # Connections
        ##################################################
        self.connect((self.analog_pwr_squelch_xx_0, 0), (self.blocks_head_0, 0))
        self.connect((self.blocks_head_0, 0), (self.blocks_file_sink_0, 0))
        self.connect((self.blocks_skiphead_0, 0), (self.analog_pwr_squelch_xx_0, 0))
        self.connect((self.uhd_usrp_source_0, 0), (self.blocks_skiphead_0, 0))


    def get_squelch_threshold(self):
        return self.squelch_threshold

    def set_squelch_threshold(self, squelch_threshold):
        self.squelch_threshold = squelch_threshold
        self.analog_pwr_squelch_xx_0.set_threshold(float(self.squelch_threshold))

    def get_squelch_ramp(self):
        return self.squelch_ramp

    def set_squelch_ramp(self, squelch_ramp):
        self.squelch_ramp = squelch_ramp

    def get_squelch_alpha(self):
        return self.squelch_alpha

    def set_squelch_alpha(self, squelch_alpha):
        self.squelch_alpha = squelch_alpha
        self.analog_pwr_squelch_xx_0.set_alpha(float(self.squelch_alpha))

    def get_serial(self):
        return self.serial

    def set_serial(self, serial):
        self.serial = serial

    def get_sample_rate(self):
        return self.sample_rate

    def set_sample_rate(self, sample_rate):
        self.sample_rate = sample_rate
        self.uhd_usrp_source_0.set_samp_rate(float(self.sample_rate))

    def get_rx_gain(self):
        return self.rx_gain

    def set_rx_gain(self, rx_gain):
        self.rx_gain = rx_gain
        self.uhd_usrp_source_0.set_gain(float(self.rx_gain), 0)

    def get_rx_frequency(self):
        return self.rx_frequency

    def set_rx_frequency(self, rx_frequency):
        self.rx_frequency = rx_frequency
        self.uhd_usrp_source_0.set_center_freq(float(self.rx_frequency), 0)

    def get_rx_channel(self):
        return self.rx_channel

    def set_rx_channel(self, rx_channel):
        self.rx_channel = rx_channel

    def get_rx_antenna(self):
        return self.rx_antenna

    def set_rx_antenna(self, rx_antenna):
        self.rx_antenna = rx_antenna
        self.uhd_usrp_source_0.set_antenna(self.rx_antenna, 0)

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





def main(top_block_cls=General_General_USRPB2x0_IQ_Record_Squelch, options=None):
    tb = top_block_cls()

    def sig_handler(sig=None, frame=None):
        tb.stop()
        tb.wait()

        sys.exit(0)

    signal.signal(signal.SIGINT, sig_handler)
    signal.signal(signal.SIGTERM, sig_handler)

    tb.start()

    tb.wait()


if __name__ == '__main__':
    main()
