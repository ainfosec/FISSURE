#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#
# SPDX-License-Identifier: GPL-3.0
#
# GNU Radio Python Flow Graph
# Title: Dect Gfsk Usrpx310 Audio Sink
# GNU Radio version: 3.8.1.0

from gnuradio import audio
from gnuradio import blocks
from gnuradio import filter
from gnuradio.filter import firdes
from gnuradio import gr
import sys
import signal
from argparse import ArgumentParser
from gnuradio.eng_arg import eng_float, intx
from gnuradio import eng_notation
from gnuradio import uhd
import time
from gnuradio import vocoder
import dect2

class DECT_GFSK_USRPX310_Audio_Sink(gr.top_block):

    def __init__(self):
        gr.top_block.__init__(self, "Dect Gfsk Usrpx310 Audio Sink")

        ##################################################
        # Variables
        ##################################################
        self.tx_usrp_gain = tx_usrp_gain = 20
        self.tx_usrp_channel = tx_usrp_channel = "A:0"
        self.tx_usrp_antenna = tx_usrp_antenna = "TX/RX"
        self.sample_rate = sample_rate = 3125000
        self.rx_gain = rx_gain = 0
        self.rx_freq = rx_freq = 1923.264e6
        self.part_id = part_id = 0
        self.notes = notes = "Plays DECT audio using gr-dect2 blocks."
        self.ip_address = ip_address = "192.168.40.2"
        self.dect_symbol_rate = dect_symbol_rate = 1152000
        self.dect_occupied_bandwidth = dect_occupied_bandwidth = 1382400
        self.dect_channel_bandwidth = dect_channel_bandwidth = 1.728e6
        self.baseband_sampling_rate = baseband_sampling_rate = 3125000

        ##################################################
        # Blocks
        ##################################################
        self.vocoder_g721_decode_bs_0 = vocoder.g721_decode_bs()
        self.uhd_usrp_source_0 = uhd.usrp_source(
            ",".join(('', "addr="+ip_address)),
            uhd.stream_args(
                cpu_format="fc32",
                args='',
                channels=list(range(0,1)),
            ),
        )
        self.uhd_usrp_source_0.set_center_freq(rx_freq, 0)
        self.uhd_usrp_source_0.set_gain(rx_gain, 0)
        self.uhd_usrp_source_0.set_antenna('RX2', 0)
        self.uhd_usrp_source_0.set_samp_rate(baseband_sampling_rate)
        self.uhd_usrp_source_0.set_time_unknown_pps(uhd.time_spec())
        self.rational_resampler_xxx_0 = filter.rational_resampler_fff(
                interpolation=6,
                decimation=1,
                taps=None,
                fractional_bw=None)
        self.rational_resampler = filter.rational_resampler_base_ccc(3, 2, firdes.low_pass_2(1, 3*baseband_sampling_rate, dect_occupied_bandwidth/2, (dect_channel_bandwidth - dect_occupied_bandwidth)/2, 30))
        self.mmse_resampler_xx_0 = filter.mmse_resampler_cc(0, (3.0*baseband_sampling_rate/2.0)/dect_symbol_rate/4.0)
        self.dect2_phase_diff_0 = dect2.phase_diff()
        self.dect2_packet_receiver_0 = dect2.packet_receiver()
        self.dect2_packet_decoder_0 = dect2.packet_decoder()
        self.blocks_short_to_float_0 = blocks.short_to_float(1, 32768)
        self.audio_sink_0 = audio.sink(48000, '', True)



        ##################################################
        # Connections
        ##################################################
        self.msg_connect((self.dect2_packet_receiver_0, 'rcvr_msg_out'), (self.dect2_packet_decoder_0, 'rcvr_msg_in'))
        self.connect((self.blocks_short_to_float_0, 0), (self.rational_resampler_xxx_0, 0))
        self.connect((self.dect2_packet_decoder_0, 0), (self.vocoder_g721_decode_bs_0, 0))
        self.connect((self.dect2_packet_receiver_0, 0), (self.dect2_packet_decoder_0, 0))
        self.connect((self.dect2_phase_diff_0, 0), (self.dect2_packet_receiver_0, 0))
        self.connect((self.mmse_resampler_xx_0, 0), (self.dect2_phase_diff_0, 0))
        self.connect((self.rational_resampler, 0), (self.mmse_resampler_xx_0, 0))
        self.connect((self.rational_resampler_xxx_0, 0), (self.audio_sink_0, 0))
        self.connect((self.uhd_usrp_source_0, 0), (self.rational_resampler, 0))
        self.connect((self.vocoder_g721_decode_bs_0, 0), (self.blocks_short_to_float_0, 0))

    def get_tx_usrp_gain(self):
        return self.tx_usrp_gain

    def set_tx_usrp_gain(self, tx_usrp_gain):
        self.tx_usrp_gain = tx_usrp_gain

    def get_tx_usrp_channel(self):
        return self.tx_usrp_channel

    def set_tx_usrp_channel(self, tx_usrp_channel):
        self.tx_usrp_channel = tx_usrp_channel

    def get_tx_usrp_antenna(self):
        return self.tx_usrp_antenna

    def set_tx_usrp_antenna(self, tx_usrp_antenna):
        self.tx_usrp_antenna = tx_usrp_antenna

    def get_sample_rate(self):
        return self.sample_rate

    def set_sample_rate(self, sample_rate):
        self.sample_rate = sample_rate

    def get_rx_gain(self):
        return self.rx_gain

    def set_rx_gain(self, rx_gain):
        self.rx_gain = rx_gain
        self.uhd_usrp_source_0.set_gain(self.rx_gain, 0)

    def get_rx_freq(self):
        return self.rx_freq

    def set_rx_freq(self, rx_freq):
        self.rx_freq = rx_freq
        self.uhd_usrp_source_0.set_center_freq(self.rx_freq, 0)

    def get_part_id(self):
        return self.part_id

    def set_part_id(self, part_id):
        self.part_id = part_id
        self.dect2_packet_decoder_0.select_rx_part(int(self.part_id))

    def get_notes(self):
        return self.notes

    def set_notes(self, notes):
        self.notes = notes

    def get_ip_address(self):
        return self.ip_address

    def set_ip_address(self, ip_address):
        self.ip_address = ip_address

    def get_dect_symbol_rate(self):
        return self.dect_symbol_rate

    def set_dect_symbol_rate(self, dect_symbol_rate):
        self.dect_symbol_rate = dect_symbol_rate
        self.mmse_resampler_xx_0.set_resamp_ratio((3.0*self.baseband_sampling_rate/2.0)/self.dect_symbol_rate/4.0)

    def get_dect_occupied_bandwidth(self):
        return self.dect_occupied_bandwidth

    def set_dect_occupied_bandwidth(self, dect_occupied_bandwidth):
        self.dect_occupied_bandwidth = dect_occupied_bandwidth
        self.rational_resampler.set_taps(firdes.low_pass_2(1, 3*self.baseband_sampling_rate, self.dect_occupied_bandwidth/2, (self.dect_channel_bandwidth - self.dect_occupied_bandwidth)/2, 30))

    def get_dect_channel_bandwidth(self):
        return self.dect_channel_bandwidth

    def set_dect_channel_bandwidth(self, dect_channel_bandwidth):
        self.dect_channel_bandwidth = dect_channel_bandwidth
        self.rational_resampler.set_taps(firdes.low_pass_2(1, 3*self.baseband_sampling_rate, self.dect_occupied_bandwidth/2, (self.dect_channel_bandwidth - self.dect_occupied_bandwidth)/2, 30))

    def get_baseband_sampling_rate(self):
        return self.baseband_sampling_rate

    def set_baseband_sampling_rate(self, baseband_sampling_rate):
        self.baseband_sampling_rate = baseband_sampling_rate
        self.mmse_resampler_xx_0.set_resamp_ratio((3.0*self.baseband_sampling_rate/2.0)/self.dect_symbol_rate/4.0)
        self.rational_resampler.set_taps(firdes.low_pass_2(1, 3*self.baseband_sampling_rate, self.dect_occupied_bandwidth/2, (self.dect_channel_bandwidth - self.dect_occupied_bandwidth)/2, 30))
        self.uhd_usrp_source_0.set_samp_rate(self.baseband_sampling_rate)



def main(top_block_cls=DECT_GFSK_USRPX310_Audio_Sink, options=None):
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
