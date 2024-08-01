#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#
# SPDX-License-Identifier: GPL-3.0
#
# GNU Radio Python Flow Graph
# Title: Rds Tx
# GNU Radio version: 3.10.7.0

from packaging.version import Version as StrictVersion
from PyQt5 import Qt
from gnuradio import qtgui
from gnuradio import analog
from gnuradio import audio
from gnuradio import blocks
from gnuradio import digital
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
from gnuradio import network
import math
import osmosdr
import time
import rds
import sip



class rds_tx(gr.top_block, Qt.QWidget):

    def __init__(self):
        gr.top_block.__init__(self, "Rds Tx", catch_exceptions=True)
        Qt.QWidget.__init__(self)
        self.setWindowTitle("Rds Tx")
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

        self.settings = Qt.QSettings("GNU Radio", "rds_tx")

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
        self.fm_max_dev = fm_max_dev = 75e3
        self.usrp_rate = usrp_rate = 19e3*20
        self.rds_gain = rds_gain = 2000 / fm_max_dev
        self.pilot_gain = pilot_gain = 0.1
        self.outbuffer = outbuffer = 10
        self.input_gain = input_gain = 0.26
        self.freq = freq = 87.5e6

        ##################################################
        # Blocks
        ##################################################

        self.root_raised_cosine_filter_0 = filter.interp_fir_filter_fff(
            160,
            firdes.root_raised_cosine(
                111,
                usrp_rate,
                2375,
                1,
                (160*11)))
        self.rds_encoder_0 = rds.encoder(0, 14, True, 'WDR 3', 89.8e6,
        			True, False, 13, 3,
        			147, 'GNU Radio <3')

        self.rational_resampler_xxx_1 = filter.rational_resampler_ccc(
                interpolation=100,
                decimation=38,
                taps=[],
                fractional_bw=0)
        self.rational_resampler_xxx_0_0 = filter.rational_resampler_fff(
                interpolation=380,
                decimation=48,
                taps=[],
                fractional_bw=0)
        self.rational_resampler_xxx_0 = filter.rational_resampler_fff(
                interpolation=380,
                decimation=48,
                taps=[],
                fractional_bw=0)
        self.qtgui_freq_sink_x_0 = qtgui.freq_sink_f(
            1024, #size
            window.WIN_BLACKMAN_hARRIS, #wintype
            0, #fc
            380000, #bw
            "", #name
            1,
            None # parent
        )
        self.qtgui_freq_sink_x_0.set_update_time(0.10)
        self.qtgui_freq_sink_x_0.set_y_axis((-140), 10)
        self.qtgui_freq_sink_x_0.set_y_label('Relative Gain', 'dB')
        self.qtgui_freq_sink_x_0.set_trigger_mode(qtgui.TRIG_MODE_FREE, 0.0, 0, "")
        self.qtgui_freq_sink_x_0.enable_autoscale(False)
        self.qtgui_freq_sink_x_0.enable_grid(False)
        self.qtgui_freq_sink_x_0.set_fft_average(1.0)
        self.qtgui_freq_sink_x_0.enable_axis_labels(True)
        self.qtgui_freq_sink_x_0.enable_control_panel(False)
        self.qtgui_freq_sink_x_0.set_fft_window_normalized(False)


        self.qtgui_freq_sink_x_0.set_plot_pos_half(not False)

        labels = ['', '', '', '', '',
            '', '', '', '', '']
        widths = [1, 1, 1, 1, 1,
            1, 1, 1, 1, 1]
        colors = ["blue", "red", "green", "black", "cyan",
            "magenta", "yellow", "dark red", "dark green", "dark blue"]
        alphas = [1.0, 1.0, 1.0, 1.0, 1.0,
            1.0, 1.0, 1.0, 1.0, 1.0]

        for i in range(1):
            if len(labels[i]) == 0:
                self.qtgui_freq_sink_x_0.set_line_label(i, "Data {0}".format(i))
            else:
                self.qtgui_freq_sink_x_0.set_line_label(i, labels[i])
            self.qtgui_freq_sink_x_0.set_line_width(i, widths[i])
            self.qtgui_freq_sink_x_0.set_line_color(i, colors[i])
            self.qtgui_freq_sink_x_0.set_line_alpha(i, alphas[i])

        self._qtgui_freq_sink_x_0_win = sip.wrapinstance(self.qtgui_freq_sink_x_0.qwidget(), Qt.QWidget)
        self.top_layout.addWidget(self._qtgui_freq_sink_x_0_win)
        self.osmosdr_sink_0 = osmosdr.sink(
            args="numchan=" + str(1) + " " + ''
        )
        self.osmosdr_sink_0.set_time_unknown_pps(osmosdr.time_spec_t())
        self.osmosdr_sink_0.set_sample_rate(1e6)
        self.osmosdr_sink_0.set_center_freq(freq, 0)
        self.osmosdr_sink_0.set_freq_corr(0, 0)
        self.osmosdr_sink_0.set_gain(10, 0)
        self.osmosdr_sink_0.set_if_gain(30, 0)
        self.osmosdr_sink_0.set_bb_gain(20, 0)
        self.osmosdr_sink_0.set_antenna('', 0)
        self.osmosdr_sink_0.set_bandwidth(0, 0)
        self.network_socket_pdu_0 = network.socket_pdu('TCP_SERVER', '', '52001', 10000, False)
        self.low_pass_filter_0_0_0 = filter.interp_fir_filter_fff(
            1,
            firdes.low_pass(
                input_gain,
                usrp_rate,
                15e3,
                2e3,
                window.WIN_HAMMING,
                6.76))
        self.low_pass_filter_0_0 = filter.interp_fir_filter_fff(
            1,
            firdes.low_pass(
                input_gain,
                usrp_rate,
                15e3,
                2e3,
                window.WIN_HAMMING,
                6.76))
        self.gr_unpack_k_bits_bb_0 = blocks.unpack_k_bits_bb(2)
        self.gr_unpack_k_bits_bb_0.set_max_output_buffer(outbuffer)
        self.gr_sub_xx_0 = blocks.sub_ff(1)
        self.gr_sig_source_x_0_1 = analog.sig_source_f(usrp_rate, analog.GR_SIN_WAVE, 19e3, pilot_gain, 0, 0)
        self.gr_sig_source_x_0_0 = analog.sig_source_f(usrp_rate, analog.GR_SIN_WAVE, 57e3, rds_gain, 0, 0)
        self.gr_sig_source_x_0 = analog.sig_source_f(usrp_rate, analog.GR_SIN_WAVE, 38e3, 1, 0, 0)
        self.gr_multiply_xx_1 = blocks.multiply_vff(1)
        self.gr_multiply_xx_0 = blocks.multiply_vff(1)
        self.gr_multiply_xx_0.set_max_output_buffer(outbuffer)
        self.gr_map_bb_1 = digital.map_bb([1,2])
        self.gr_map_bb_1.set_max_output_buffer(outbuffer)
        self.gr_frequency_modulator_fc_0 = analog.frequency_modulator_fc((2*math.pi*fm_max_dev/usrp_rate))
        self.gr_frequency_modulator_fc_0.set_max_output_buffer(outbuffer)
        self.gr_diff_encoder_bb_0 = digital.diff_encoder_bb(2, digital.DIFF_DIFFERENTIAL)
        self.gr_diff_encoder_bb_0.set_max_output_buffer(outbuffer)
        self.gr_add_xx_1 = blocks.add_vff(1)
        self.gr_add_xx_1.set_max_output_buffer(outbuffer)
        self.gr_add_xx_0 = blocks.add_vff(1)
        self.digital_chunks_to_symbols_xx_0 = digital.chunks_to_symbols_bf([-1, 1], 1)
        self.audio_source_0 = audio.source(48000, '', False)


        ##################################################
        # Connections
        ##################################################
        self.msg_connect((self.network_socket_pdu_0, 'pdus'), (self.rds_encoder_0, 'rds in'))
        self.connect((self.audio_source_0, 0), (self.rational_resampler_xxx_0, 0))
        self.connect((self.audio_source_0, 1), (self.rational_resampler_xxx_0_0, 0))
        self.connect((self.digital_chunks_to_symbols_xx_0, 0), (self.root_raised_cosine_filter_0, 0))
        self.connect((self.gr_add_xx_0, 0), (self.low_pass_filter_0_0, 0))
        self.connect((self.gr_add_xx_1, 0), (self.gr_frequency_modulator_fc_0, 0))
        self.connect((self.gr_add_xx_1, 0), (self.qtgui_freq_sink_x_0, 0))
        self.connect((self.gr_diff_encoder_bb_0, 0), (self.gr_map_bb_1, 0))
        self.connect((self.gr_frequency_modulator_fc_0, 0), (self.rational_resampler_xxx_1, 0))
        self.connect((self.gr_map_bb_1, 0), (self.gr_unpack_k_bits_bb_0, 0))
        self.connect((self.gr_multiply_xx_0, 0), (self.gr_add_xx_1, 0))
        self.connect((self.gr_multiply_xx_1, 0), (self.gr_add_xx_1, 2))
        self.connect((self.gr_sig_source_x_0, 0), (self.gr_multiply_xx_1, 0))
        self.connect((self.gr_sig_source_x_0_0, 0), (self.gr_multiply_xx_0, 0))
        self.connect((self.gr_sig_source_x_0_1, 0), (self.gr_add_xx_1, 1))
        self.connect((self.gr_sub_xx_0, 0), (self.low_pass_filter_0_0_0, 0))
        self.connect((self.gr_unpack_k_bits_bb_0, 0), (self.digital_chunks_to_symbols_xx_0, 0))
        self.connect((self.low_pass_filter_0_0, 0), (self.gr_add_xx_1, 3))
        self.connect((self.low_pass_filter_0_0_0, 0), (self.gr_multiply_xx_1, 1))
        self.connect((self.rational_resampler_xxx_0, 0), (self.gr_add_xx_0, 0))
        self.connect((self.rational_resampler_xxx_0, 0), (self.gr_sub_xx_0, 0))
        self.connect((self.rational_resampler_xxx_0_0, 0), (self.gr_add_xx_0, 1))
        self.connect((self.rational_resampler_xxx_0_0, 0), (self.gr_sub_xx_0, 1))
        self.connect((self.rational_resampler_xxx_1, 0), (self.osmosdr_sink_0, 0))
        self.connect((self.rds_encoder_0, 0), (self.gr_diff_encoder_bb_0, 0))
        self.connect((self.root_raised_cosine_filter_0, 0), (self.gr_multiply_xx_0, 1))


    def closeEvent(self, event):
        self.settings = Qt.QSettings("GNU Radio", "rds_tx")
        self.settings.setValue("geometry", self.saveGeometry())
        self.stop()
        self.wait()

        event.accept()

    def get_fm_max_dev(self):
        return self.fm_max_dev

    def set_fm_max_dev(self, fm_max_dev):
        self.fm_max_dev = fm_max_dev
        self.set_rds_gain(2000 / self.fm_max_dev)
        self.gr_frequency_modulator_fc_0.set_sensitivity((2*math.pi*self.fm_max_dev/self.usrp_rate))

    def get_usrp_rate(self):
        return self.usrp_rate

    def set_usrp_rate(self, usrp_rate):
        self.usrp_rate = usrp_rate
        self.gr_frequency_modulator_fc_0.set_sensitivity((2*math.pi*self.fm_max_dev/self.usrp_rate))
        self.gr_sig_source_x_0.set_sampling_freq(self.usrp_rate)
        self.gr_sig_source_x_0_0.set_sampling_freq(self.usrp_rate)
        self.gr_sig_source_x_0_1.set_sampling_freq(self.usrp_rate)
        self.low_pass_filter_0_0.set_taps(firdes.low_pass(self.input_gain, self.usrp_rate, 15e3, 2e3, window.WIN_HAMMING, 6.76))
        self.low_pass_filter_0_0_0.set_taps(firdes.low_pass(self.input_gain, self.usrp_rate, 15e3, 2e3, window.WIN_HAMMING, 6.76))
        self.root_raised_cosine_filter_0.set_taps(firdes.root_raised_cosine(111, self.usrp_rate, 2375, 1, (160*11)))

    def get_rds_gain(self):
        return self.rds_gain

    def set_rds_gain(self, rds_gain):
        self.rds_gain = rds_gain
        self.gr_sig_source_x_0_0.set_amplitude(self.rds_gain)

    def get_pilot_gain(self):
        return self.pilot_gain

    def set_pilot_gain(self, pilot_gain):
        self.pilot_gain = pilot_gain
        self.gr_sig_source_x_0_1.set_amplitude(self.pilot_gain)

    def get_outbuffer(self):
        return self.outbuffer

    def set_outbuffer(self, outbuffer):
        self.outbuffer = outbuffer

    def get_input_gain(self):
        return self.input_gain

    def set_input_gain(self, input_gain):
        self.input_gain = input_gain
        self.low_pass_filter_0_0.set_taps(firdes.low_pass(self.input_gain, self.usrp_rate, 15e3, 2e3, window.WIN_HAMMING, 6.76))
        self.low_pass_filter_0_0_0.set_taps(firdes.low_pass(self.input_gain, self.usrp_rate, 15e3, 2e3, window.WIN_HAMMING, 6.76))

    def get_freq(self):
        return self.freq

    def set_freq(self, freq):
        self.freq = freq
        self.osmosdr_sink_0.set_center_freq(self.freq, 0)




def main(top_block_cls=rds_tx, options=None):

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
