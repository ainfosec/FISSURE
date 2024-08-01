#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#
# SPDX-License-Identifier: GPL-3.0
#
# GNU Radio Python Flow Graph
# Title: Dect Gfsk Usrpx310 Wireshark
# GNU Radio version: 3.10.7.0

from packaging.version import Version as StrictVersion
from PyQt5 import Qt
from gnuradio import qtgui
from gnuradio import blocks
from gnuradio import filter
from gnuradio.filter import firdes
from gnuradio import gr
from gnuradio.fft import window
import sys
import signal
from PyQt5 import Qt
from argparse import ArgumentParser
from gnuradio.eng_arg import eng_float, intx
from gnuradio import eng_notation
from gnuradio import uhd
import time
import gnuradio.ainfosec as ainfosec
import gnuradio.dect2 as dect2



class DECT_GFSK_USRPX310_Wireshark(gr.top_block, Qt.QWidget):

    def __init__(self):
        gr.top_block.__init__(self, "Dect Gfsk Usrpx310 Wireshark", catch_exceptions=True)
        Qt.QWidget.__init__(self)
        self.setWindowTitle("Dect Gfsk Usrpx310 Wireshark")
        qtgui.util.check_set_qss()
        try:
            self.setWindowIcon(Qt.QIcon.fromTheme('gnuradio-grc'))
        except BaseException as exc:
            print(f"Qt GUI: Could not set Icon: {str(exc)}", file=sys.stderr)
        self.top_scroll_layout = Qt.QVBoxLayout()
        self.setLayout(self.top_scroll_layout)
        self.top_scroll = Qt.QScrollArea()
        self.top_scroll.setFrameStyle(Qt.QFrame.NoFrame)
        self.top_scroll_layout.addWidget(self.top_scroll)
        self.top_scroll.setWidgetResizable(True)
        self.top_widget = Qt.QWidget()
        self.top_scroll.setWidget(self.top_widget)
        self.top_layout = Qt.QVBoxLayout(self.top_widget)
        self.top_grid_layout = Qt.QGridLayout()
        self.top_layout.addLayout(self.top_grid_layout)

        self.settings = Qt.QSettings("GNU Radio", "DECT_GFSK_USRPX310_Wireshark")

        try:
            if StrictVersion(Qt.qVersion()) < StrictVersion("5.0.0"):
                self.restoreGeometry(self.settings.value("geometry").toByteArray())
            else:
                self.restoreGeometry(self.settings.value("geometry"))
        except BaseException as exc:
            print(f"Qt GUI: Could not restore geometry: {str(exc)}", file=sys.stderr)

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
                args='',
                channels=list(range(0,1)),
            ),
        )
        self.uhd_usrp_source_0.set_subdev_spec(rx_usrp_channel, 0)
        self.uhd_usrp_source_0.set_samp_rate(baseband_sampling_rate)
        self.uhd_usrp_source_0.set_time_unknown_pps(uhd.time_spec(0))

        self.uhd_usrp_source_0.set_center_freq(rx_freq, 0)
        self.uhd_usrp_source_0.set_antenna(rx_usrp_antenna, 0)
        self.uhd_usrp_source_0.set_gain(rx_gain, 0)
        self.rational_resampler_xxx_0 = filter.rational_resampler_ccc(
                interpolation=3,
                decimation=2,
                taps=firdes.low_pass_2(1, 3*baseband_sampling_rate, dect_occupied_bandwidth/2, (dect_channel_bandwidth - dect_occupied_bandwidth)/2, 30),
                fractional_bw=0)
        self.mmse_resampler_xx_0 = filter.mmse_resampler_cc(0, ((3.0*baseband_sampling_rate/2.0)/dect_symbol_rate/4.0))
        self.dect2_phase_diff_0 = dect2.phase_diff()
        self.dect2_packet_receiver_0 = dect2.packet_receiver()
        self.blocks_vector_source_x_0 = blocks.vector_source_b((0,0,0,0,0,0,170,170,170,233,138), True, 1, [])
        self.blocks_stream_to_tagged_stream_1 = blocks.stream_to_tagged_stream(gr.sizeof_char, 1, 59, "packet_len")
        self.blocks_stream_mux_0 = blocks.stream_mux(gr.sizeof_char*1, 11, 48)
        self.blocks_pack_k_bits_bb_0 = blocks.pack_k_bits_bb(8)
        self.blocks_keep_m_in_n_0 = blocks.keep_m_in_n(gr.sizeof_char, 384, 388, 0)
        self.ainfosec_UDP_to_Wireshark_0 = ainfosec.UDP_to_Wireshark(50000)


        ##################################################
        # Connections
        ##################################################
        self.connect((self.blocks_keep_m_in_n_0, 0), (self.blocks_pack_k_bits_bb_0, 0))
        self.connect((self.blocks_pack_k_bits_bb_0, 0), (self.blocks_stream_mux_0, 1))
        self.connect((self.blocks_stream_mux_0, 0), (self.blocks_stream_to_tagged_stream_1, 0))
        self.connect((self.blocks_stream_to_tagged_stream_1, 0), (self.ainfosec_UDP_to_Wireshark_0, 0))
        self.connect((self.blocks_vector_source_x_0, 0), (self.blocks_stream_mux_0, 0))
        self.connect((self.dect2_packet_receiver_0, 0), (self.blocks_keep_m_in_n_0, 0))
        self.connect((self.dect2_phase_diff_0, 0), (self.dect2_packet_receiver_0, 0))
        self.connect((self.mmse_resampler_xx_0, 0), (self.dect2_phase_diff_0, 0))
        self.connect((self.rational_resampler_xxx_0, 0), (self.mmse_resampler_xx_0, 0))
        self.connect((self.uhd_usrp_source_0, 0), (self.rational_resampler_xxx_0, 0))


    def closeEvent(self, event):
        self.settings = Qt.QSettings("GNU Radio", "DECT_GFSK_USRPX310_Wireshark")
        self.settings.setValue("geometry", self.saveGeometry())
        self.stop()
        self.wait()

        event.accept()

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
        self.mmse_resampler_xx_0.set_resamp_ratio(((3.0*self.baseband_sampling_rate/2.0)/self.dect_symbol_rate/4.0))

    def get_dect_occupied_bandwidth(self):
        return self.dect_occupied_bandwidth

    def set_dect_occupied_bandwidth(self, dect_occupied_bandwidth):
        self.dect_occupied_bandwidth = dect_occupied_bandwidth
        self.rational_resampler_xxx_0.set_taps(firdes.low_pass_2(1, 3*self.baseband_sampling_rate, self.dect_occupied_bandwidth/2, (self.dect_channel_bandwidth - self.dect_occupied_bandwidth)/2, 30))

    def get_dect_channel_bandwidth(self):
        return self.dect_channel_bandwidth

    def set_dect_channel_bandwidth(self, dect_channel_bandwidth):
        self.dect_channel_bandwidth = dect_channel_bandwidth
        self.rational_resampler_xxx_0.set_taps(firdes.low_pass_2(1, 3*self.baseband_sampling_rate, self.dect_occupied_bandwidth/2, (self.dect_channel_bandwidth - self.dect_occupied_bandwidth)/2, 30))

    def get_baseband_sampling_rate(self):
        return self.baseband_sampling_rate

    def set_baseband_sampling_rate(self, baseband_sampling_rate):
        self.baseband_sampling_rate = baseband_sampling_rate
        self.mmse_resampler_xx_0.set_resamp_ratio(((3.0*self.baseband_sampling_rate/2.0)/self.dect_symbol_rate/4.0))
        self.rational_resampler_xxx_0.set_taps(firdes.low_pass_2(1, 3*self.baseband_sampling_rate, self.dect_occupied_bandwidth/2, (self.dect_channel_bandwidth - self.dect_occupied_bandwidth)/2, 30))
        self.uhd_usrp_source_0.set_samp_rate(self.baseband_sampling_rate)




def main(top_block_cls=DECT_GFSK_USRPX310_Wireshark, options=None):

    if StrictVersion("4.5.0") <= StrictVersion(Qt.qVersion()) < StrictVersion("5.0.0"):
        style = gr.prefs().get_string('qtgui', 'style', 'raster')
        Qt.QApplication.setGraphicsSystem(style)
    qapp = Qt.QApplication(sys.argv)

    tb = top_block_cls()

    tb.start()

    tb.show()

    def sig_handler(sig=None, frame=None):
        tb.stop()
        tb.wait()

        Qt.QApplication.quit()

    signal.signal(signal.SIGINT, sig_handler)
    signal.signal(signal.SIGTERM, sig_handler)

    timer = Qt.QTimer()
    timer.start(500)
    timer.timeout.connect(lambda: None)

    qapp.exec_()

if __name__ == '__main__':
    main()
