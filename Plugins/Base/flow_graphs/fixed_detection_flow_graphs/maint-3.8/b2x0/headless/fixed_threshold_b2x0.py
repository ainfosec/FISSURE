#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#
# SPDX-License-Identifier: GPL-3.0
#
# GNU Radio Python Flow Graph
# Title: Not titled yet
# Author: user
# GNU Radio version: 3.8.5.0

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
from gnuradio.fft import logpwrfft
import epy_block_0
import numpy as np
import random


class fixed_threshold_b2x0(gr.top_block):

    def __init__(self, antenna_default='TX/RX', channel_default='A:A', gain_default='65', ip_address='', min_interval="1", rx_freq_default='2412000000', sample_rate_default='20e6', serial='False', threshold_default='0'):
        gr.top_block.__init__(self, "Not titled yet")

        ##################################################
        # Parameters
        ##################################################
        self.antenna_default = antenna_default
        self.channel_default = channel_default
        self.gain_default = gain_default
        self.ip_address = ip_address
        self.min_interval = min_interval
        self.rx_freq_default = rx_freq_default
        self.sample_rate_default = sample_rate_default
        self.serial = serial
        self.threshold_default = threshold_default

        ##################################################
        # Variables
        ##################################################
        self.up_line_adj = up_line_adj = 8191
        self.low_line_adj = low_line_adj = 1
        self.fft_size = fft_size = 8192
        self.below_zero = below_zero = -1000
        self.vec_height = vec_height = 1000
        self.up_bound_vec_top_half = up_bound_vec_top_half = (fft_size-up_line_adj-1)*(below_zero,)
        self.up_bound_vec_bottom_half = up_bound_vec_bottom_half = (up_line_adj)*(below_zero,)
        self.thresh_adj = thresh_adj = -60
        self.samp_rate = samp_rate = 1e6
        self.rx_gain = rx_gain = 60
        self.rx_freq = rx_freq = rx_freq_default
        self.rx_antenna = rx_antenna = "TX/RX"
        self.low_bound_vec_top_half = low_bound_vec_top_half = (fft_size-low_line_adj-1)*(below_zero,)
        self.low_bound_vec_bottom_half = low_bound_vec_bottom_half = (low_line_adj)*(below_zero,)
        self.in_box_spec_len = in_box_spec_len = int(np.abs(up_line_adj-low_line_adj))
        self.full_band_size = full_band_size = 8192

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
        self.uhd_usrp_source_0.set_subdev_spec(channel_default, 0)
        self.uhd_usrp_source_0.set_center_freq(float(rx_freq), 0)
        self.uhd_usrp_source_0.set_gain(rx_gain, 0)
        self.uhd_usrp_source_0.set_antenna(rx_antenna, 0)
        self.uhd_usrp_source_0.set_samp_rate(samp_rate)
        self.uhd_usrp_source_0.set_time_unknown_pps(uhd.time_spec())
        self.logpwrfft_x_0 = logpwrfft.logpwrfft_c(
            sample_rate=samp_rate,
            fft_size=fft_size,
            ref_scale=2,
            frame_rate=30,
            avg_alpha=1.0,
            average=False,
            shift=True)
        self.epy_block_0 = epy_block_0.blk(vec_len=fft_size, sample_rate=samp_rate, rx_freq_mhz=float(rx_freq)/1e6, min_publish_interval_s=float(min_interval))
        self.blocks_vector_source_x_0 = blocks.vector_source_f((thresh_adj,)*full_band_size, True, fft_size, [])
        self.blocks_message_debug_0 = blocks.message_debug()
        self.blocks_max_xx_0 = blocks.max_ff(fft_size, fft_size)
        self.blocks_add_const_vxx_0 = blocks.add_const_vff(((below_zero*10),)*(low_line_adj)+(0,)*in_box_spec_len+((below_zero*10),)*(fft_size-up_line_adj))


        ##################################################
        # Connections
        ##################################################
        self.msg_connect((self.epy_block_0, 'detected_signals'), (self.blocks_message_debug_0, 'print'))
        self.connect((self.blocks_add_const_vxx_0, 0), (self.blocks_max_xx_0, 1))
        self.connect((self.blocks_max_xx_0, 0), (self.epy_block_0, 0))
        self.connect((self.blocks_vector_source_x_0, 0), (self.blocks_max_xx_0, 0))
        self.connect((self.blocks_vector_source_x_0, 0), (self.epy_block_0, 1))
        self.connect((self.logpwrfft_x_0, 0), (self.blocks_add_const_vxx_0, 0))
        self.connect((self.uhd_usrp_source_0, 0), (self.logpwrfft_x_0, 0))


    def get_antenna_default(self):
        return self.antenna_default

    def set_antenna_default(self, antenna_default):
        self.antenna_default = antenna_default

    def get_channel_default(self):
        return self.channel_default

    def set_channel_default(self, channel_default):
        self.channel_default = channel_default

    def get_gain_default(self):
        return self.gain_default

    def set_gain_default(self, gain_default):
        self.gain_default = gain_default

    def get_ip_address(self):
        return self.ip_address

    def set_ip_address(self, ip_address):
        self.ip_address = ip_address

    def get_min_interval(self):
        return self.min_interval

    def set_min_interval(self, min_interval):
        self.min_interval = min_interval
        self.epy_block_0.min_publish_interval_s = float(self.min_interval)

    def get_rx_freq_default(self):
        return self.rx_freq_default

    def set_rx_freq_default(self, rx_freq_default):
        self.rx_freq_default = rx_freq_default
        self.set_rx_freq(self.rx_freq_default)

    def get_sample_rate_default(self):
        return self.sample_rate_default

    def set_sample_rate_default(self, sample_rate_default):
        self.sample_rate_default = sample_rate_default

    def get_serial(self):
        return self.serial

    def set_serial(self, serial):
        self.serial = serial

    def get_threshold_default(self):
        return self.threshold_default

    def set_threshold_default(self, threshold_default):
        self.threshold_default = threshold_default

    def get_up_line_adj(self):
        return self.up_line_adj

    def set_up_line_adj(self, up_line_adj):
        self.up_line_adj = up_line_adj
        self.set_in_box_spec_len(int(np.abs(self.up_line_adj-self.low_line_adj)))
        self.set_up_bound_vec_bottom_half((self.up_line_adj)*(self.below_zero,))
        self.set_up_bound_vec_top_half((self.fft_size-self.up_line_adj-1)*(self.below_zero,))
        self.blocks_add_const_vxx_0.set_k(((self.below_zero*10),)*(self.low_line_adj)+(0,)*self.in_box_spec_len+((self.below_zero*10),)*(self.fft_size-self.up_line_adj))

    def get_low_line_adj(self):
        return self.low_line_adj

    def set_low_line_adj(self, low_line_adj):
        self.low_line_adj = low_line_adj
        self.set_in_box_spec_len(int(np.abs(self.up_line_adj-self.low_line_adj)))
        self.set_low_bound_vec_bottom_half((self.low_line_adj)*(self.below_zero,))
        self.set_low_bound_vec_top_half((self.fft_size-self.low_line_adj-1)*(self.below_zero,))
        self.blocks_add_const_vxx_0.set_k(((self.below_zero*10),)*(self.low_line_adj)+(0,)*self.in_box_spec_len+((self.below_zero*10),)*(self.fft_size-self.up_line_adj))

    def get_fft_size(self):
        return self.fft_size

    def set_fft_size(self, fft_size):
        self.fft_size = fft_size
        self.set_low_bound_vec_top_half((self.fft_size-self.low_line_adj-1)*(self.below_zero,))
        self.set_up_bound_vec_top_half((self.fft_size-self.up_line_adj-1)*(self.below_zero,))
        self.blocks_add_const_vxx_0.set_k(((self.below_zero*10),)*(self.low_line_adj)+(0,)*self.in_box_spec_len+((self.below_zero*10),)*(self.fft_size-self.up_line_adj))

    def get_below_zero(self):
        return self.below_zero

    def set_below_zero(self, below_zero):
        self.below_zero = below_zero
        self.set_low_bound_vec_bottom_half((self.low_line_adj)*(self.below_zero,))
        self.set_low_bound_vec_top_half((self.fft_size-self.low_line_adj-1)*(self.below_zero,))
        self.set_up_bound_vec_bottom_half((self.up_line_adj)*(self.below_zero,))
        self.set_up_bound_vec_top_half((self.fft_size-self.up_line_adj-1)*(self.below_zero,))
        self.blocks_add_const_vxx_0.set_k(((self.below_zero*10),)*(self.low_line_adj)+(0,)*self.in_box_spec_len+((self.below_zero*10),)*(self.fft_size-self.up_line_adj))

    def get_vec_height(self):
        return self.vec_height

    def set_vec_height(self, vec_height):
        self.vec_height = vec_height

    def get_up_bound_vec_top_half(self):
        return self.up_bound_vec_top_half

    def set_up_bound_vec_top_half(self, up_bound_vec_top_half):
        self.up_bound_vec_top_half = up_bound_vec_top_half

    def get_up_bound_vec_bottom_half(self):
        return self.up_bound_vec_bottom_half

    def set_up_bound_vec_bottom_half(self, up_bound_vec_bottom_half):
        self.up_bound_vec_bottom_half = up_bound_vec_bottom_half

    def get_thresh_adj(self):
        return self.thresh_adj

    def set_thresh_adj(self, thresh_adj):
        self.thresh_adj = thresh_adj
        self.blocks_vector_source_x_0.set_data((self.thresh_adj,)*self.full_band_size, [])

    def get_samp_rate(self):
        return self.samp_rate

    def set_samp_rate(self, samp_rate):
        self.samp_rate = samp_rate
        self.epy_block_0.sample_rate = self.samp_rate
        self.logpwrfft_x_0.set_sample_rate(self.samp_rate)
        self.uhd_usrp_source_0.set_samp_rate(self.samp_rate)

    def get_rx_gain(self):
        return self.rx_gain

    def set_rx_gain(self, rx_gain):
        self.rx_gain = rx_gain
        self.uhd_usrp_source_0.set_gain(self.rx_gain, 0)

    def get_rx_freq(self):
        return self.rx_freq

    def set_rx_freq(self, rx_freq):
        self.rx_freq = rx_freq
        self.epy_block_0.rx_freq_mhz = float(self.rx_freq)/1e6
        self.uhd_usrp_source_0.set_center_freq(float(self.rx_freq), 0)

    def get_rx_antenna(self):
        return self.rx_antenna

    def set_rx_antenna(self, rx_antenna):
        self.rx_antenna = rx_antenna
        self.uhd_usrp_source_0.set_antenna(self.rx_antenna, 0)

    def get_low_bound_vec_top_half(self):
        return self.low_bound_vec_top_half

    def set_low_bound_vec_top_half(self, low_bound_vec_top_half):
        self.low_bound_vec_top_half = low_bound_vec_top_half

    def get_low_bound_vec_bottom_half(self):
        return self.low_bound_vec_bottom_half

    def set_low_bound_vec_bottom_half(self, low_bound_vec_bottom_half):
        self.low_bound_vec_bottom_half = low_bound_vec_bottom_half

    def get_in_box_spec_len(self):
        return self.in_box_spec_len

    def set_in_box_spec_len(self, in_box_spec_len):
        self.in_box_spec_len = in_box_spec_len
        self.blocks_add_const_vxx_0.set_k(((self.below_zero*10),)*(self.low_line_adj)+(0,)*self.in_box_spec_len+((self.below_zero*10),)*(self.fft_size-self.up_line_adj))

    def get_full_band_size(self):
        return self.full_band_size

    def set_full_band_size(self, full_band_size):
        self.full_band_size = full_band_size
        self.blocks_vector_source_x_0.set_data((self.thresh_adj,)*self.full_band_size, [])




def argument_parser():
    parser = ArgumentParser()
    parser.add_argument(
        "--antenna-default", dest="antenna_default", type=str, default='TX/RX',
        help="Set TX/RX [default=%(default)r]")
    parser.add_argument(
        "--channel-default", dest="channel_default", type=str, default='A:A',
        help="Set A:A [default=%(default)r]")
    parser.add_argument(
        "--gain-default", dest="gain_default", type=str, default='65',
        help="Set 65 [default=%(default)r]")
    parser.add_argument(
        "--ip-address", dest="ip_address", type=str, default='',
        help="Set ip_address [default=%(default)r]")
    parser.add_argument(
        "--min-interval", dest="min_interval", type=str, default="1",
        help="Set min_interval [default=%(default)r]")
    parser.add_argument(
        "--rx-freq-default", dest="rx_freq_default", type=str, default='2412000000',
        help="Set 2412000000 [default=%(default)r]")
    parser.add_argument(
        "--sample-rate-default", dest="sample_rate_default", type=str, default='20e6',
        help="Set 20e6 [default=%(default)r]")
    parser.add_argument(
        "--serial", dest="serial", type=str, default='False',
        help="Set False [default=%(default)r]")
    parser.add_argument(
        "--threshold-default", dest="threshold_default", type=str, default='0',
        help="Set 0 [default=%(default)r]")
    return parser


def main(top_block_cls=fixed_threshold_b2x0, options=None):
    if options is None:
        options = argument_parser().parse_args()
    tb = top_block_cls(antenna_default=options.antenna_default, channel_default=options.channel_default, gain_default=options.gain_default, ip_address=options.ip_address, min_interval=options.min_interval, rx_freq_default=options.rx_freq_default, sample_rate_default=options.sample_rate_default, serial=options.serial, threshold_default=options.threshold_default)

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
