#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#
# SPDX-License-Identifier: GPL-3.0
#
# GNU Radio Python Flow Graph
# Title: X10 Ook Usrpb2X0 Demod
# Description: Decodes X10 signals and prints the output.
# GNU Radio version: 3.10.4.0

from gnuradio import blocks
from gnuradio import digital
from gnuradio import filter
from gnuradio.filter import firdes
from gnuradio import gr
from gnuradio.fft import window
import sys
import signal
from argparse import ArgumentParser
from gnuradio.eng_arg import eng_float, intx
from gnuradio import eng_notation
from gnuradio import uhd
import time
from gnuradio import zeromq
import gnuradio.X10 as X10




class X10_OOK_USRPB2x0_Demod(gr.top_block):

    def __init__(self):
        gr.top_block.__init__(self, "X10 Ook Usrpb2X0 Demod", catch_exceptions=True)

        ##################################################
        # Variables
        ##################################################
        self.zmq_port = zmq_port = 5066
        self.serial = serial = "False"
        self.sample_rate = sample_rate = 1e6
        self.rx_usrp_gain = rx_usrp_gain = 70
        self.rx_usrp_frequency = rx_usrp_frequency = 310.8e6
        self.rx_usrp_channel = rx_usrp_channel = "A:A"
        self.rx_usrp_antenna = rx_usrp_antenna = "TX/RX"
        self.notes = notes = "Decodes X10 signals and prints the output."

        ##################################################
        # Blocks
        ##################################################
        self.zeromq_pub_msg_sink_0 = zeromq.pub_msg_sink("tcp://*:" + str(zmq_port), 100, True)
        self.uhd_usrp_source_0 = uhd.usrp_source(
            ",".join((serial, "")),
            uhd.stream_args(
                cpu_format="fc32",
                args='',
                channels=list(range(0,1)),
            ),
        )
        self.uhd_usrp_source_0.set_subdev_spec(rx_usrp_channel, 0)
        self.uhd_usrp_source_0.set_samp_rate(sample_rate)
        self.uhd_usrp_source_0.set_time_unknown_pps(uhd.time_spec(0))

        self.uhd_usrp_source_0.set_center_freq(rx_usrp_frequency, 0)
        self.uhd_usrp_source_0.set_antenna(rx_usrp_antenna, 0)
        self.uhd_usrp_source_0.set_gain(rx_usrp_gain, 0)
        self.fir_filter_xxx_0_0 = filter.fir_filter_fff(1, [0.125]*8)
        self.fir_filter_xxx_0_0.declare_sample_delay(0)
        self.digital_correlate_access_code_tag_xx_0 = digital.correlate_access_code_tag_bb('111111111111111111111111111111111111111100000000000000000000', 0, 'Start')
        self.blocks_threshold_ff_0_0 = blocks.threshold_ff(.05, .05, 0)
        self.blocks_multiply_const_vxx_0 = blocks.multiply_const_ff(1000)
        self.blocks_message_debug_0 = blocks.message_debug(True)
        self.blocks_keep_one_in_n_0_0 = blocks.keep_one_in_n(gr.sizeof_float*1, 125)
        self.blocks_float_to_uchar_0 = blocks.float_to_uchar()
        self.blocks_complex_to_mag_squared_0 = blocks.complex_to_mag_squared(1)
        self.blocks_char_to_float_0 = blocks.char_to_float(1, 1)
        self.X10_x10_decoder_0 = X10.x10_decoder()


        ##################################################
        # Connections
        ##################################################
        self.msg_connect((self.X10_x10_decoder_0, 'out'), (self.blocks_message_debug_0, 'print'))
        self.msg_connect((self.X10_x10_decoder_0, 'bytes'), (self.zeromq_pub_msg_sink_0, 'in'))
        self.connect((self.blocks_char_to_float_0, 0), (self.X10_x10_decoder_0, 0))
        self.connect((self.blocks_complex_to_mag_squared_0, 0), (self.fir_filter_xxx_0_0, 0))
        self.connect((self.blocks_float_to_uchar_0, 0), (self.digital_correlate_access_code_tag_xx_0, 0))
        self.connect((self.blocks_keep_one_in_n_0_0, 0), (self.blocks_float_to_uchar_0, 0))
        self.connect((self.blocks_multiply_const_vxx_0, 0), (self.blocks_threshold_ff_0_0, 0))
        self.connect((self.blocks_threshold_ff_0_0, 0), (self.blocks_keep_one_in_n_0_0, 0))
        self.connect((self.digital_correlate_access_code_tag_xx_0, 0), (self.blocks_char_to_float_0, 0))
        self.connect((self.fir_filter_xxx_0_0, 0), (self.blocks_multiply_const_vxx_0, 0))
        self.connect((self.uhd_usrp_source_0, 0), (self.blocks_complex_to_mag_squared_0, 0))


    def get_zmq_port(self):
        return self.zmq_port

    def set_zmq_port(self, zmq_port):
        self.zmq_port = zmq_port

    def get_serial(self):
        return self.serial

    def set_serial(self, serial):
        self.serial = serial

    def get_sample_rate(self):
        return self.sample_rate

    def set_sample_rate(self, sample_rate):
        self.sample_rate = sample_rate
        self.uhd_usrp_source_0.set_samp_rate(self.sample_rate)

    def get_rx_usrp_gain(self):
        return self.rx_usrp_gain

    def set_rx_usrp_gain(self, rx_usrp_gain):
        self.rx_usrp_gain = rx_usrp_gain
        self.uhd_usrp_source_0.set_gain(self.rx_usrp_gain, 0)

    def get_rx_usrp_frequency(self):
        return self.rx_usrp_frequency

    def set_rx_usrp_frequency(self, rx_usrp_frequency):
        self.rx_usrp_frequency = rx_usrp_frequency
        self.uhd_usrp_source_0.set_center_freq(self.rx_usrp_frequency, 0)

    def get_rx_usrp_channel(self):
        return self.rx_usrp_channel

    def set_rx_usrp_channel(self, rx_usrp_channel):
        self.rx_usrp_channel = rx_usrp_channel

    def get_rx_usrp_antenna(self):
        return self.rx_usrp_antenna

    def set_rx_usrp_antenna(self, rx_usrp_antenna):
        self.rx_usrp_antenna = rx_usrp_antenna
        self.uhd_usrp_source_0.set_antenna(self.rx_usrp_antenna, 0)

    def get_notes(self):
        return self.notes

    def set_notes(self, notes):
        self.notes = notes




def main(top_block_cls=X10_OOK_USRPB2x0_Demod, options=None):
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
