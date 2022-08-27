#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#
# SPDX-License-Identifier: GPL-3.0
#
# GNU Radio Python Flow Graph
# Title: Soapy AIS receiver
# Author: Nick Foster
# GNU Radio version: v3.11.0.0git-55-g8526e6f8

import os
import sys
sys.path.append(os.environ.get('GRC_HIER_PATH', os.path.expanduser('~/.grc_gnuradio')))

from ais_rx_core import ais_rx_core  # grc-generated hier_block
from gnuradio import blocks
from gnuradio import gr
from gnuradio.filter import firdes
from gnuradio.fft import window
import signal
from argparse import ArgumentParser
from gnuradio.eng_arg import eng_float, intx
from gnuradio import eng_notation
from gnuradio import soapy
from gnuradio.ais import pdu_to_nmea
import math




class ais_rx(gr.top_block):

    def __init__(self, ant='TX/RX', args="", gain=65, samp_rate=200e3, stream_args="", ted_bw=0.033, threshold=0.83):
        gr.top_block.__init__(self, "Soapy AIS receiver", catch_exceptions=True)

        ##################################################
        # Parameters
        ##################################################
        self.ant = ant
        self.args = args
        self.gain = gain
        self.samp_rate = samp_rate
        self.stream_args = stream_args
        self.ted_bw = ted_bw
        self.threshold = threshold

        ##################################################
        # Blocks
        ##################################################
        self.soapy_rtlsdr_source_0 = None
        dev = 'driver=rtlsdr'
        stream_args = ''
        tune_args = ['']
        settings = ['']

        self.soapy_rtlsdr_source_0 = soapy.source(dev, "fc32", 1, '',
                                  stream_args, tune_args, settings)
        self.soapy_rtlsdr_source_0.set_sample_rate(0, samp_rate)
        self.soapy_rtlsdr_source_0.set_gain_mode(0, False)
        self.soapy_rtlsdr_source_0.set_frequency(0, 162e6)
        self.soapy_rtlsdr_source_0.set_frequency_correction(0, 0)
        self.soapy_rtlsdr_source_0.set_gain(0, 'TUNER', 65)
        self.pdu_to_nmea_0_0 = pdu_to_nmea('B')
        self.pdu_to_nmea_0 = pdu_to_nmea('A')
        self.blocks_rotator_cc_0_0 = blocks.rotator_cc(2*math.pi*(25e3/samp_rate), False)
        self.blocks_rotator_cc_0 = blocks.rotator_cc(2*math.pi*(-25e3/samp_rate), False)
        self.ais_rx_core_0_0 = ais_rx_core(
            bb_sps=4,
            bt=0.4,
            loopbw=ted_bw,
            samp_rate=samp_rate,
            threshold=threshold,
        )
        self.ais_rx_core_0 = ais_rx_core(
            bb_sps=4,
            bt=0.4,
            loopbw=ted_bw,
            samp_rate=samp_rate,
            threshold=threshold,
        )


        ##################################################
        # Connections
        ##################################################
        self.msg_connect((self.ais_rx_core_0, 'out'), (self.pdu_to_nmea_0, 'print'))
        self.msg_connect((self.ais_rx_core_0_0, 'out'), (self.pdu_to_nmea_0_0, 'print'))
        self.connect((self.blocks_rotator_cc_0, 0), (self.ais_rx_core_0, 0))
        self.connect((self.blocks_rotator_cc_0_0, 0), (self.ais_rx_core_0_0, 0))
        self.connect((self.soapy_rtlsdr_source_0, 0), (self.blocks_rotator_cc_0, 0))
        self.connect((self.soapy_rtlsdr_source_0, 0), (self.blocks_rotator_cc_0_0, 0))


    def get_ant(self):
        return self.ant

    def set_ant(self, ant):
        self.ant = ant

    def get_args(self):
        return self.args

    def set_args(self, args):
        self.args = args

    def get_gain(self):
        return self.gain

    def set_gain(self, gain):
        self.gain = gain

    def get_samp_rate(self):
        return self.samp_rate

    def set_samp_rate(self, samp_rate):
        self.samp_rate = samp_rate
        self.ais_rx_core_0.set_samp_rate(self.samp_rate)
        self.ais_rx_core_0_0.set_samp_rate(self.samp_rate)
        self.blocks_rotator_cc_0.set_phase_inc(2*math.pi*(-25e3/self.samp_rate))
        self.blocks_rotator_cc_0_0.set_phase_inc(2*math.pi*(25e3/self.samp_rate))
        self.soapy_rtlsdr_source_0.set_sample_rate(0, self.samp_rate)

    def get_stream_args(self):
        return self.stream_args

    def set_stream_args(self, stream_args):
        self.stream_args = stream_args

    def get_ted_bw(self):
        return self.ted_bw

    def set_ted_bw(self, ted_bw):
        self.ted_bw = ted_bw
        self.ais_rx_core_0.set_loopbw(self.ted_bw)
        self.ais_rx_core_0_0.set_loopbw(self.ted_bw)

    def get_threshold(self):
        return self.threshold

    def set_threshold(self, threshold):
        self.threshold = threshold
        self.ais_rx_core_0.set_threshold(self.threshold)
        self.ais_rx_core_0_0.set_threshold(self.threshold)



def argument_parser():
    parser = ArgumentParser()
    parser.add_argument(
        "--ant", dest="ant", type=str, default='TX/RX',
        help="Set Antenna [default=%(default)r]")
    parser.add_argument(
        "--args", dest="args", type=str, default="",
        help="Set Device args [default=%(default)r]")
    parser.add_argument(
        "--gain", dest="gain", type=intx, default=65,
        help="Set Gain [default=%(default)r]")
    parser.add_argument(
        "--samp-rate", dest="samp_rate", type=eng_float, default=eng_notation.num_to_str(float(200e3)),
        help="Set Sample rate [default=%(default)r]")
    parser.add_argument(
        "--stream-args", dest="stream_args", type=str, default="",
        help="Set Stream args [default=%(default)r]")
    parser.add_argument(
        "--ted-bw", dest="ted_bw", type=eng_float, default=eng_notation.num_to_str(float(0.033)),
        help="Set TED bandwidth [default=%(default)r]")
    parser.add_argument(
        "--threshold", dest="threshold", type=eng_float, default=eng_notation.num_to_str(float(0.83)),
        help="Set Correlator threshold [default=%(default)r]")
    return parser


def main(top_block_cls=ais_rx, options=None):
    if options is None:
        options = argument_parser().parse_args()
    tb = top_block_cls(ant=options.ant, args=options.args, gain=options.gain, samp_rate=options.samp_rate, stream_args=options.stream_args, ted_bw=options.ted_bw, threshold=options.threshold)

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
