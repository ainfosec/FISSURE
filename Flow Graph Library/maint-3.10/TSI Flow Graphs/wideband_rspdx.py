#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#
# SPDX-License-Identifier: GPL-3.0
#
# GNU Radio Python Flow Graph
# Title: Wideband Rspdx
# GNU Radio version: 3.10.7.0

from gnuradio import analog
from gnuradio import blocks
from gnuradio import fft
from gnuradio.fft import window
from gnuradio import gr
from gnuradio.filter import firdes
import sys
import signal
from argparse import ArgumentParser
from gnuradio.eng_arg import eng_float, intx
from gnuradio import eng_notation
from gnuradio import sdrplay3
import gnuradio.ainfosec as ainfosec




class wideband_rspdx(gr.top_block):

    def __init__(self):
        gr.top_block.__init__(self, "Wideband Rspdx", catch_exceptions=True)

        ##################################################
        # Variables
        ##################################################
        self.threshold = threshold = -70
        self.serial = serial = "0"
        self.sample_rate = sample_rate = 2000000
        self.rx_freq = rx_freq = 1200e6
        self.ip_address = ip_address = "N/A"
        self.gain = gain = 0
        self.fft_size = fft_size = 512*1
        self.channel = channel = "N/A"
        self.antenna = antenna = "N/A"

        ##################################################
        # Blocks
        ##################################################

        self.sdrplay3_rspdx_0 = sdrplay3.rspdx(
            str(serial),
            stream_args=sdrplay3.stream_args(
                output_type='fc32',
                channels_size=1
            ),
        )
        self.sdrplay3_rspdx_0.set_sample_rate(float(sample_rate), False)
        self.sdrplay3_rspdx_0.set_center_freq(float(rx_freq), False)
        self.sdrplay3_rspdx_0.set_bandwidth(0)
        self.sdrplay3_rspdx_0.set_antenna('Antenna A')
        self.sdrplay3_rspdx_0.set_gain_mode(False)
        self.sdrplay3_rspdx_0.set_gain(-((59-float(gain))), 'IF', False)
        self.sdrplay3_rspdx_0.set_gain(-(0), 'RF', False)
        self.sdrplay3_rspdx_0.set_freq_corr(0)
        self.sdrplay3_rspdx_0.set_dc_offset_mode(False)
        self.sdrplay3_rspdx_0.set_iq_balance_mode(False)
        self.sdrplay3_rspdx_0.set_agc_setpoint((-30))
        self.sdrplay3_rspdx_0.set_hdr_mode(False)
        self.sdrplay3_rspdx_0.set_rf_notch_filter(False)
        self.sdrplay3_rspdx_0.set_dab_notch_filter(False)
        self.sdrplay3_rspdx_0.set_biasT(False)
        self.sdrplay3_rspdx_0.set_debug_mode(False)
        self.sdrplay3_rspdx_0.set_sample_sequence_gaps_check(False)
        self.sdrplay3_rspdx_0.set_show_gain_changes(False)
        self.fft_vxx_0 = fft.fft_vcc(fft_size, True, window.blackmanharris(fft_size), True, 1)
        self.blocks_vector_to_stream_0 = blocks.vector_to_stream(gr.sizeof_gr_complex*1, fft_size)
        self.blocks_stream_to_vector_1 = blocks.stream_to_vector(gr.sizeof_gr_complex*1, fft_size)
        self.blocks_nlog10_ff_0 = blocks.nlog10_ff(10, 1, 0)
        self.blocks_complex_to_mag_squared_0 = blocks.complex_to_mag_squared(1)
        self.analog_pwr_squelch_xx_0 = analog.pwr_squelch_cc((-70), (1e-4), 0, True)
        self.ainfosec_wideband_detector1_0 = ainfosec.wideband_detector1("tcp://127.0.0.1:5060",rx_freq,fft_size,sample_rate)


        ##################################################
        # Connections
        ##################################################
        self.connect((self.analog_pwr_squelch_xx_0, 0), (self.blocks_stream_to_vector_1, 0))
        self.connect((self.blocks_complex_to_mag_squared_0, 0), (self.blocks_nlog10_ff_0, 0))
        self.connect((self.blocks_nlog10_ff_0, 0), (self.ainfosec_wideband_detector1_0, 0))
        self.connect((self.blocks_stream_to_vector_1, 0), (self.fft_vxx_0, 0))
        self.connect((self.blocks_vector_to_stream_0, 0), (self.blocks_complex_to_mag_squared_0, 0))
        self.connect((self.fft_vxx_0, 0), (self.blocks_vector_to_stream_0, 0))
        self.connect((self.sdrplay3_rspdx_0, 0), (self.analog_pwr_squelch_xx_0, 0))


    def get_threshold(self):
        return self.threshold

    def set_threshold(self, threshold):
        self.threshold = threshold

    def get_serial(self):
        return self.serial

    def set_serial(self, serial):
        self.serial = serial

    def get_sample_rate(self):
        return self.sample_rate

    def set_sample_rate(self, sample_rate):
        self.sample_rate = sample_rate
        self.ainfosec_wideband_detector1_0.set_sample_rate(self.sample_rate)
        self.sdrplay3_rspdx_0.set_sample_rate(float(self.sample_rate), False)

    def get_rx_freq(self):
        return self.rx_freq

    def set_rx_freq(self, rx_freq):
        self.rx_freq = rx_freq
        self.ainfosec_wideband_detector1_0.set_rx_freq(self.rx_freq)
        self.sdrplay3_rspdx_0.set_center_freq(float(self.rx_freq), False)

    def get_ip_address(self):
        return self.ip_address

    def set_ip_address(self, ip_address):
        self.ip_address = ip_address

    def get_gain(self):
        return self.gain

    def set_gain(self, gain):
        self.gain = gain
        self.sdrplay3_rspdx_0.set_gain(-((59-float(self.gain))), 'IF', False)

    def get_fft_size(self):
        return self.fft_size

    def set_fft_size(self, fft_size):
        self.fft_size = fft_size
        self.ainfosec_wideband_detector1_0.set_fft_size(self.fft_size)

    def get_channel(self):
        return self.channel

    def set_channel(self, channel):
        self.channel = channel

    def get_antenna(self):
        return self.antenna

    def set_antenna(self, antenna):
        self.antenna = antenna




def main(top_block_cls=wideband_rspdx, options=None):
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
