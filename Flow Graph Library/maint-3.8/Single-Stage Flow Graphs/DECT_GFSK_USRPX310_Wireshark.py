#!/usr/bin/env python2
# -*- coding: utf-8 -*-
##################################################
# GNU Radio Python Flow Graph
# Title: Dect Gfsk Usrpx310 Wireshark
# Generated: Sun Jan  9 14:23:37 2022
##################################################


if __name__ == '__main__':
    import ctypes
    import sys
    if sys.platform.startswith('linux'):
        try:
            x11 = ctypes.cdll.LoadLibrary('libX11.so')
            x11.XInitThreads()
        except:
            print "Warning: failed to XInitThreads()"

from gnuradio import blocks
from gnuradio import eng_notation
from gnuradio import filter
from gnuradio import gr
from gnuradio import uhd
from gnuradio.eng_option import eng_option
from gnuradio.filter import firdes
from grc_gnuradio import wxgui as grc_wxgui
from optparse import OptionParser
import ainfosec
import dect2
import time
import wx


class DECT_GFSK_USRPX310_Wireshark(grc_wxgui.top_block_gui):

    def __init__(self):
        grc_wxgui.top_block_gui.__init__(self, title="Dect Gfsk Usrpx310 Wireshark")
        _icon_path = "/usr/share/icons/hicolor/32x32/apps/gnuradio-grc.png"
        self.SetIcon(wx.Icon(_icon_path, wx.BITMAP_TYPE_ANY))

        ##################################################
        # Variables
        ##################################################
        self.rx_usrp_channel = rx_usrp_channel = "A:0"
        self.rx_usrp_antenna = rx_usrp_antenna = "TX/RX"
        self.rx_gain = rx_gain = 20
        self.rx_freq = rx_freq = 1921.536e6
        self.notes = notes = "Captures DECT signals and pipes the messages to Wireshark."
        self.ip_address = ip_address = "192.168.40.2"
        self.dect_symbol_rate = dect_symbol_rate = 1152000
        self.dect_occupied_bandwidth = dect_occupied_bandwidth = 1382400
        self.dect_channel_bandwidth = dect_channel_bandwidth = 1.728e6
        self.baseband_sampling_rate = baseband_sampling_rate = 3125000

        ##################################################
        # Blocks
        ##################################################
        self.uhd_usrp_source_0 = uhd.usrp_source(
        	",".join(('', "addr=" + ip_address)),
        	uhd.stream_args(
        		cpu_format="fc32",
        		channels=range(1),
        	),
        )
        self.uhd_usrp_source_0.set_subdev_spec(rx_usrp_channel, 0)
        self.uhd_usrp_source_0.set_samp_rate(baseband_sampling_rate)
        self.uhd_usrp_source_0.set_center_freq(rx_freq, 0)
        self.uhd_usrp_source_0.set_gain(rx_gain, 0)
        self.uhd_usrp_source_0.set_antenna(rx_usrp_antenna, 0)
        self.rational_resampler = filter.rational_resampler_base_ccc(3, 2, (firdes.low_pass_2(1, 3*baseband_sampling_rate, dect_occupied_bandwidth/2, (dect_channel_bandwidth - dect_occupied_bandwidth)/2, 30)))
        self.fractional_resampler = filter.fractional_resampler_cc(0, (3.0*baseband_sampling_rate/2.0)/dect_symbol_rate/4.0)
        self.dect2_phase_diff_0 = dect2.phase_diff()
        self.dect2_packet_receiver_0 = dect2.packet_receiver()
        self.blocks_vector_source_x_0 = blocks.vector_source_b((0,0,0,0,0,0,170,170,170,233,138), True, 1, [])
        self.blocks_stream_to_tagged_stream_1 = blocks.stream_to_tagged_stream(gr.sizeof_char, 1, 59, "packet_len")
        self.blocks_stream_mux_0 = blocks.stream_mux(gr.sizeof_char*1, (11, 48))
        self.blocks_pack_k_bits_bb_0 = blocks.pack_k_bits_bb(8)
        self.blocks_keep_m_in_n_0 = blocks.keep_m_in_n(gr.sizeof_char, 384, 388, 0)
        self.ainfosec_pcap_fifo_0 = ainfosec.pcap_fifo(50000)

        ##################################################
        # Connections
        ##################################################
        self.connect((self.blocks_keep_m_in_n_0, 0), (self.blocks_pack_k_bits_bb_0, 0))
        self.connect((self.blocks_pack_k_bits_bb_0, 0), (self.blocks_stream_mux_0, 1))
        self.connect((self.blocks_stream_mux_0, 0), (self.blocks_stream_to_tagged_stream_1, 0))
        self.connect((self.blocks_stream_to_tagged_stream_1, 0), (self.ainfosec_pcap_fifo_0, 0))
        self.connect((self.blocks_vector_source_x_0, 0), (self.blocks_stream_mux_0, 0))
        self.connect((self.dect2_packet_receiver_0, 0), (self.blocks_keep_m_in_n_0, 0))
        self.connect((self.dect2_phase_diff_0, 0), (self.dect2_packet_receiver_0, 0))
        self.connect((self.fractional_resampler, 0), (self.dect2_phase_diff_0, 0))
        self.connect((self.rational_resampler, 0), (self.fractional_resampler, 0))
        self.connect((self.uhd_usrp_source_0, 0), (self.rational_resampler, 0))

    def get_rx_usrp_channel(self):
        return self.rx_usrp_channel

    def set_rx_usrp_channel(self, rx_usrp_channel):
        self.rx_usrp_channel = rx_usrp_channel

    def get_rx_usrp_antenna(self):
        return self.rx_usrp_antenna

    def set_rx_usrp_antenna(self, rx_usrp_antenna):
        self.rx_usrp_antenna = rx_usrp_antenna
        self.uhd_usrp_source_0.set_antenna(self.rx_usrp_antenna, 0)

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
        self.fractional_resampler.set_resamp_ratio((3.0*self.baseband_sampling_rate/2.0)/self.dect_symbol_rate/4.0)

    def get_dect_occupied_bandwidth(self):
        return self.dect_occupied_bandwidth

    def set_dect_occupied_bandwidth(self, dect_occupied_bandwidth):
        self.dect_occupied_bandwidth = dect_occupied_bandwidth
        self.rational_resampler.set_taps((firdes.low_pass_2(1, 3*self.baseband_sampling_rate, self.dect_occupied_bandwidth/2, (self.dect_channel_bandwidth - self.dect_occupied_bandwidth)/2, 30)))

    def get_dect_channel_bandwidth(self):
        return self.dect_channel_bandwidth

    def set_dect_channel_bandwidth(self, dect_channel_bandwidth):
        self.dect_channel_bandwidth = dect_channel_bandwidth
        self.rational_resampler.set_taps((firdes.low_pass_2(1, 3*self.baseband_sampling_rate, self.dect_occupied_bandwidth/2, (self.dect_channel_bandwidth - self.dect_occupied_bandwidth)/2, 30)))

    def get_baseband_sampling_rate(self):
        return self.baseband_sampling_rate

    def set_baseband_sampling_rate(self, baseband_sampling_rate):
        self.baseband_sampling_rate = baseband_sampling_rate
        self.uhd_usrp_source_0.set_samp_rate(self.baseband_sampling_rate)
        self.rational_resampler.set_taps((firdes.low_pass_2(1, 3*self.baseband_sampling_rate, self.dect_occupied_bandwidth/2, (self.dect_channel_bandwidth - self.dect_occupied_bandwidth)/2, 30)))
        self.fractional_resampler.set_resamp_ratio((3.0*self.baseband_sampling_rate/2.0)/self.dect_symbol_rate/4.0)


def main(top_block_cls=DECT_GFSK_USRPX310_Wireshark, options=None):

    tb = top_block_cls()
    tb.Start(True)
    tb.Wait()


if __name__ == '__main__':
    main()
