#!/usr/bin/env python2
# -*- coding: utf-8 -*-
##################################################
# GNU Radio Python Flow Graph
# Title: Sim
# Generated: Thu Oct 12 12:33:05 2017
##################################################
import threading


import os
import sys
sys.path.append(os.environ.get('GRC_HIER_PATH', os.path.expanduser('~/.grc_gnuradio')))

from argparse import ArgumentParser
from gnuradio import analog
from gnuradio import blocks
from gnuradio import eng_notation
from gnuradio import gr
from gnuradio.eng_arg import eng_float, intx
from gnuradio.filter import firdes
from gnuradio.filter import pfb
from wifi_phy_hier import wifi_phy_hier  # grc-generated hier_block
import foo
import ieee802_11
import math
import pmt
import random


class sim(gr.top_block):

    def __init__(self, encoding=2, interference="ofdm", interval=50, messages=50, repetition=23, size=546, snr=20):
        gr.top_block.__init__(self, "Sim")

        self._lock = threading.RLock()

        ##################################################
        # Parameters
        ##################################################
        self.encoding = encoding
        self.interference = interference
        self.interval = interval
        self.messages = messages
        self.repetition = repetition
        self.size = size
        self.snr = snr

        ##################################################
        # Variables
        ##################################################
        self.window_size = window_size = 48
        self.sync_length = sync_length = 320
        self.out_buf_size = out_buf_size = 960000
        self.filename = filename = "results/sim_%d_%.1f_%s_.pcap" % (repetition, snr, interference)

        ##################################################
        # Blocks
        ##################################################
        self.wifi_phy_hier_0_0 = wifi_phy_hier(
            bandwidth=10e6,
            chan_est=ieee802_11.LS,
            encoding=encoding,
            frequency=5.89e9,
            sensitivity=0.56,
        )
        self.wifi_phy_hier_0 = wifi_phy_hier(
            bandwidth=10e6,
            chan_est=ieee802_11.LS,
            encoding=encoding,
            frequency=5.89e9,
            sensitivity=0.56,
        )
        self.pfb_arb_resampler_xxx_0_0 = pfb.arb_resampler_ccf(
        	  1 + 15e-6,
                  taps=None,
        	  flt_size=32)
        self.pfb_arb_resampler_xxx_0_0.declare_sample_delay(0)

        self.pfb_arb_resampler_xxx_0 = pfb.arb_resampler_ccf(
        	  1 + 15e-6,
                  taps=None,
        	  flt_size=32)
        self.pfb_arb_resampler_xxx_0.declare_sample_delay(0)

        self.ieee802_11_mac_0_0 = ieee802_11.mac(([0x12, 0x12, 0x12, 0x12, 0x12, 0x12]), ([0x34, 0x34, 0x34, 0x34, 0x34, 0x34]), ([0x56, 0x56, 0x56, 0x56, 0x56, 0x56]))
        self.ieee802_11_mac_0 = ieee802_11.mac(([0x23, 0x23, 0x23, 0x23, 0x23, 0x23]), ([0x42, 0x42, 0x42, 0x42, 0x42, 0x42]), ([0xff, 0xff, 0xff, 0xff, 0xff, 0xff]))
        self.foo_wireshark_connector_0 = foo.wireshark_connector(127, False)
        self.foo_random_periodic_msg_source_0_0 = foo.random_periodic_msg_source(ieee802_11.mac_payload_to_payload(size), interval, messages, True, False, repetition+123)
        self.foo_random_periodic_msg_source_0 = foo.random_periodic_msg_source(ieee802_11.mac_payload_to_payload(size), interval, messages, True, False, repetition+4242)
        self.foo_packet_pad2_0_0_0 = foo.packet_pad2(False, False, 0.001, 4000, 5000)
        (self.foo_packet_pad2_0_0_0).set_min_output_buffer(960000)
        self.foo_packet_pad2_0_0 = foo.packet_pad2(False, False, 0.001, 4000, 5000)
        (self.foo_packet_pad2_0_0).set_min_output_buffer(960000)
        self.foo_packet_pad2_0 = foo.packet_pad2(False, False, 0.001, 4000, 5000)
        (self.foo_packet_pad2_0).set_min_output_buffer(960000)
        self.blocks_stream_to_tagged_stream_0 = blocks.stream_to_tagged_stream(gr.sizeof_gr_complex, 1, ieee802_11.payload_to_samples(ieee802_11.mac_payload_to_payload(size), encoding), "packet_len")
        self.blocks_skiphead_0 = blocks.skiphead(gr.sizeof_gr_complex*1, 2400 + repetition * 4)
        self.blocks_multiply_const_vxx_2 = blocks.multiply_const_vcc((0, ))
        self.blocks_multiply_const_vxx_1_1 = blocks.multiply_const_vcc((1 if interference == "noise" else 0, ))
        self.blocks_multiply_const_vxx_1_0 = blocks.multiply_const_vcc((0.00001, ))
        self.blocks_multiply_const_vxx_1 = blocks.multiply_const_vcc((1 if interference == "ofdm" else 0, ))
        self.blocks_multiply_const_vxx_0 = blocks.multiply_const_vcc(((10**(snr/10.0))**.5, ))
        self.blocks_file_sink_0 = blocks.file_sink(gr.sizeof_char*1, filename, False)
        self.blocks_file_sink_0.set_unbuffered(True)
        self.blocks_add_xx_1 = blocks.add_vcc(1)
        self.blocks_add_xx_0 = blocks.add_vcc(1)
        self.analog_noise_source_x_0_0 = analog.noise_source_c(analog.GR_GAUSSIAN, 1, repetition+1)
        self.analog_noise_source_x_0 = analog.noise_source_c(analog.GR_GAUSSIAN, 1, repetition+12312)



        ##################################################
        # Connections
        ##################################################
        self.msg_connect((self.foo_random_periodic_msg_source_0, 'out'), (self.ieee802_11_mac_0, 'app in'))
        self.msg_connect((self.foo_random_periodic_msg_source_0_0, 'out'), (self.ieee802_11_mac_0_0, 'app in'))
        self.msg_connect((self.ieee802_11_mac_0, 'phy out'), (self.wifi_phy_hier_0, 'mac_in'))
        self.msg_connect((self.ieee802_11_mac_0_0, 'phy out'), (self.wifi_phy_hier_0_0, 'mac_in'))
        self.msg_connect((self.wifi_phy_hier_0, 'mac_out'), (self.foo_wireshark_connector_0, 'in'))
        self.connect((self.analog_noise_source_x_0, 0), (self.blocks_add_xx_1, 1))
        self.connect((self.analog_noise_source_x_0_0, 0), (self.blocks_multiply_const_vxx_1_0, 0))
        self.connect((self.blocks_add_xx_0, 0), (self.wifi_phy_hier_0, 0))
        self.connect((self.blocks_add_xx_1, 0), (self.blocks_stream_to_tagged_stream_0, 0))
        self.connect((self.blocks_multiply_const_vxx_0, 0), (self.blocks_skiphead_0, 0))
        self.connect((self.blocks_multiply_const_vxx_1, 0), (self.blocks_add_xx_0, 1))
        self.connect((self.blocks_multiply_const_vxx_1_0, 0), (self.blocks_add_xx_0, 3))
        self.connect((self.blocks_multiply_const_vxx_1_1, 0), (self.blocks_add_xx_0, 2))
        self.connect((self.blocks_multiply_const_vxx_2, 0), (self.blocks_add_xx_1, 0))
        self.connect((self.blocks_multiply_const_vxx_2, 0), (self.wifi_phy_hier_0_0, 0))
        self.connect((self.blocks_skiphead_0, 0), (self.blocks_add_xx_0, 0))
        self.connect((self.blocks_stream_to_tagged_stream_0, 0), (self.foo_packet_pad2_0_0_0, 0))
        self.connect((self.foo_packet_pad2_0, 0), (self.blocks_multiply_const_vxx_0, 0))
        self.connect((self.foo_packet_pad2_0_0, 0), (self.pfb_arb_resampler_xxx_0, 0))
        self.connect((self.foo_packet_pad2_0_0_0, 0), (self.pfb_arb_resampler_xxx_0_0, 0))
        self.connect((self.foo_wireshark_connector_0, 0), (self.blocks_file_sink_0, 0))
        self.connect((self.pfb_arb_resampler_xxx_0, 0), (self.blocks_multiply_const_vxx_1, 0))
        self.connect((self.pfb_arb_resampler_xxx_0_0, 0), (self.blocks_multiply_const_vxx_1_1, 0))
        self.connect((self.wifi_phy_hier_0, 0), (self.blocks_multiply_const_vxx_2, 0))
        self.connect((self.wifi_phy_hier_0, 0), (self.foo_packet_pad2_0, 0))
        self.connect((self.wifi_phy_hier_0_0, 0), (self.foo_packet_pad2_0_0, 0))

    def get_encoding(self):
        return self.encoding

    def set_encoding(self, encoding):
        with self._lock:
            self.encoding = encoding
            self.wifi_phy_hier_0_0.set_encoding(self.encoding)
            self.wifi_phy_hier_0.set_encoding(self.encoding)
            self.blocks_stream_to_tagged_stream_0.set_packet_len(ieee802_11.payload_to_samples(ieee802_11.mac_payload_to_payload(self.size), self.encoding))
            self.blocks_stream_to_tagged_stream_0.set_packet_len_pmt(ieee802_11.payload_to_samples(ieee802_11.mac_payload_to_payload(self.size), self.encoding))

    def get_interference(self):
        return self.interference

    def set_interference(self, interference):
        with self._lock:
            self.interference = interference
            self.set_filename("results/sim_%d_%.1f_%s_.pcap" % (self.repetition, self.snr, self.interference))
            self.blocks_multiply_const_vxx_1_1.set_k((1 if self.interference == "noise" else 0, ))
            self.blocks_multiply_const_vxx_1.set_k((1 if self.interference == "ofdm" else 0, ))

    def get_interval(self):
        return self.interval

    def set_interval(self, interval):
        with self._lock:
            self.interval = interval

    def get_messages(self):
        return self.messages

    def set_messages(self, messages):
        with self._lock:
            self.messages = messages

    def get_repetition(self):
        return self.repetition

    def set_repetition(self, repetition):
        with self._lock:
            self.repetition = repetition
            self.set_filename("results/sim_%d_%.1f_%s_.pcap" % (self.repetition, self.snr, self.interference))

    def get_size(self):
        return self.size

    def set_size(self, size):
        with self._lock:
            self.size = size
            self.blocks_stream_to_tagged_stream_0.set_packet_len(ieee802_11.payload_to_samples(ieee802_11.mac_payload_to_payload(self.size), self.encoding))
            self.blocks_stream_to_tagged_stream_0.set_packet_len_pmt(ieee802_11.payload_to_samples(ieee802_11.mac_payload_to_payload(self.size), self.encoding))

    def get_snr(self):
        return self.snr

    def set_snr(self, snr):
        with self._lock:
            self.snr = snr
            self.set_filename("results/sim_%d_%.1f_%s_.pcap" % (self.repetition, self.snr, self.interference))
            self.blocks_multiply_const_vxx_0.set_k(((10**(self.snr/10.0))**.5, ))

    def get_window_size(self):
        return self.window_size

    def set_window_size(self, window_size):
        with self._lock:
            self.window_size = window_size

    def get_sync_length(self):
        return self.sync_length

    def set_sync_length(self, sync_length):
        with self._lock:
            self.sync_length = sync_length

    def get_out_buf_size(self):
        return self.out_buf_size

    def set_out_buf_size(self, out_buf_size):
        with self._lock:
            self.out_buf_size = out_buf_size

    def get_filename(self):
        return self.filename

    def set_filename(self, filename):
        with self._lock:
            self.filename = filename
            self.blocks_file_sink_0.open(self.filename)


def argument_parser():
    parser = ArgumentParser()
    parser.add_argument(
        "--encoding", dest="encoding", type=intx, default=2,
        help="Set encoding [default=%(default)r]")
    parser.add_argument(
        "--interference", dest="interference", type=str, default="ofdm",
        help="Set interference [default=%(default)r]")
    parser.add_argument(
        "--interval", dest="interval", type=eng_float, default=eng_notation.num_to_str(50),
        help="Set interval [default=%(default)r]")
    parser.add_argument(
        "--messages", dest="messages", type=intx, default=50,
        help="Set messages [default=%(default)r]")
    parser.add_argument(
        "--repetition", dest="repetition", type=intx, default=23,
        help="Set repetition [default=%(default)r]")
    parser.add_argument(
        "--size", dest="size", type=intx, default=546,
        help="Set size [default=%(default)r]")
    parser.add_argument(
        "--snr", dest="snr", type=eng_float, default=eng_notation.num_to_str(20),
        help="Set snr [default=%(default)r]")
    return parser


def main(top_block_cls=sim, options=None):
    if options is None:
        options = argument_parser().parse_args()

    tb = top_block_cls(encoding=options.encoding, interference=options.interference, interval=options.interval, messages=options.messages, repetition=options.repetition, size=options.size, snr=options.snr)
    tb.start()
    tb.wait()


if __name__ == '__main__':
    main()
