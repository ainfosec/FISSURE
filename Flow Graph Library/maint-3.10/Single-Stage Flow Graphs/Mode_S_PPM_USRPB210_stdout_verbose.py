#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#
# SPDX-License-Identifier: GPL-3.0
#
# GNU Radio Python Flow Graph
# Title: Mode S Ppm Usrpb210 Stdout Verbose
# GNU Radio version: 3.10.7.0

from gnuradio import blocks
from gnuradio import gr
from gnuradio.filter import firdes
from gnuradio.fft import window
import sys
import signal
from argparse import ArgumentParser
from gnuradio.eng_arg import eng_float, intx
from gnuradio import eng_notation
from gnuradio import uhd
import time
import gnuradio.adsb as adsb




class Mode_S_PPM_USRPB210_stdout_verbose(gr.top_block):

    def __init__(self, antenna="TX/RX", channel="A:A", freq='1090e6', gain='70', samp_rate='2e6', serial="False", threshold='0.01'):
        gr.top_block.__init__(self, "Mode S Ppm Usrpb210 Stdout Verbose", catch_exceptions=True)

        ##################################################
        # Parameters
        ##################################################
        self.antenna = antenna
        self.channel = channel
        self.freq = freq
        self.gain = gain
        self.samp_rate = samp_rate
        self.serial = serial
        self.threshold = threshold

        ##################################################
        # Variables
        ##################################################
        self.notes = notes = "Prints formatted decoded ADSB data (gr-adsb) originating from an SDR (2 MS/s) to stdout with the verbose option selected."

        ##################################################
        # Blocks
        ##################################################

        self.uhd_usrp_source_0 = uhd.usrp_source(
            ",".join((str(serial), "")),
            uhd.stream_args(
                cpu_format="fc32",
                args='',
                channels=list(range(0,1)),
            ),
        )
        self.uhd_usrp_source_0.set_subdev_spec(str(channel), 0)
        self.uhd_usrp_source_0.set_samp_rate(float(samp_rate))
        self.uhd_usrp_source_0.set_time_unknown_pps(uhd.time_spec(0))

        self.uhd_usrp_source_0.set_center_freq(float(freq), 0)
        self.uhd_usrp_source_0.set_antenna(str(antenna), 0)
        self.uhd_usrp_source_0.set_gain(float(gain), 0)
        self.blocks_null_sink_0 = blocks.null_sink(gr.sizeof_float*1)
        self.blocks_complex_to_mag_squared_0 = blocks.complex_to_mag_squared(1)
        self.adsb_framer_1 = adsb.framer(float(samp_rate), float(threshold))
        self.adsb_demod_0 = adsb.demod(float(samp_rate))
        self.adsb_decoder_0_0 = adsb.decoder("All Messages", "None", "Verbose")


        ##################################################
        # Connections
        ##################################################
        self.msg_connect((self.adsb_demod_0, 'demodulated'), (self.adsb_decoder_0_0, 'demodulated'))
        self.connect((self.adsb_demod_0, 0), (self.blocks_null_sink_0, 0))
        self.connect((self.adsb_framer_1, 0), (self.adsb_demod_0, 0))
        self.connect((self.blocks_complex_to_mag_squared_0, 0), (self.adsb_framer_1, 0))
        self.connect((self.uhd_usrp_source_0, 0), (self.blocks_complex_to_mag_squared_0, 0))


    def get_antenna(self):
        return self.antenna

    def set_antenna(self, antenna):
        self.antenna = antenna
        self.uhd_usrp_source_0.set_antenna(str(self.antenna), 0)

    def get_channel(self):
        return self.channel

    def set_channel(self, channel):
        self.channel = channel

    def get_freq(self):
        return self.freq

    def set_freq(self, freq):
        self.freq = freq
        self.uhd_usrp_source_0.set_center_freq(float(self.freq), 0)

    def get_gain(self):
        return self.gain

    def set_gain(self, gain):
        self.gain = gain
        self.uhd_usrp_source_0.set_gain(float(self.gain), 0)

    def get_samp_rate(self):
        return self.samp_rate

    def set_samp_rate(self, samp_rate):
        self.samp_rate = samp_rate
        self.uhd_usrp_source_0.set_samp_rate(float(self.samp_rate))

    def get_serial(self):
        return self.serial

    def set_serial(self, serial):
        self.serial = serial

    def get_threshold(self):
        return self.threshold

    def set_threshold(self, threshold):
        self.threshold = threshold
        self.adsb_framer_1.set_threshold(float(self.threshold))

    def get_notes(self):
        return self.notes

    def set_notes(self, notes):
        self.notes = notes



def argument_parser():
    parser = ArgumentParser()
    parser.add_argument(
        "--antenna", dest="antenna", type=str, default="TX/RX",
        help="Set antenna [default=%(default)r]")
    parser.add_argument(
        "--channel", dest="channel", type=str, default="A:A",
        help="Set channel [default=%(default)r]")
    parser.add_argument(
        "--freq", dest="freq", type=str, default='1090e6',
        help="Set freq [default=%(default)r]")
    parser.add_argument(
        "--gain", dest="gain", type=str, default='70',
        help="Set gain [default=%(default)r]")
    parser.add_argument(
        "--samp-rate", dest="samp_rate", type=str, default='2e6',
        help="Set samp_rate [default=%(default)r]")
    parser.add_argument(
        "--serial", dest="serial", type=str, default="False",
        help="Set serial [default=%(default)r]")
    parser.add_argument(
        "--threshold", dest="threshold", type=str, default='0.01',
        help="Set threshold [default=%(default)r]")
    return parser


def main(top_block_cls=Mode_S_PPM_USRPB210_stdout_verbose, options=None):
    if options is None:
        options = argument_parser().parse_args()
    tb = top_block_cls(antenna=options.antenna, channel=options.channel, freq=options.freq, gain=options.gain, samp_rate=options.samp_rate, serial=options.serial, threshold=options.threshold)

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
