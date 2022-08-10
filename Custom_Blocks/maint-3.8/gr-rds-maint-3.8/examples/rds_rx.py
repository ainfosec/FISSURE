#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#
# SPDX-License-Identifier: GPL-3.0
#
# GNU Radio Python Flow Graph
# Title: Stereo FM receiver and RDS Decoder
# GNU Radio version: 3.8.1.0

from distutils.version import StrictVersion

if __name__ == '__main__':
    import ctypes
    import sys
    if sys.platform.startswith('linux'):
        try:
            x11 = ctypes.cdll.LoadLibrary('libX11.so')
            x11.XInitThreads()
        except:
            print("Warning: failed to XInitThreads()")

from PyQt5 import Qt
from gnuradio import qtgui
from gnuradio.filter import firdes
import sip
from gnuradio import analog
from gnuradio import audio
from gnuradio import blocks
from gnuradio import digital
from gnuradio import filter
from gnuradio import gr
import sys
import signal
from argparse import ArgumentParser
from gnuradio.eng_arg import eng_float, intx
from gnuradio import eng_notation
from gnuradio import uhd
import time
from gnuradio.filter import pfb
from gnuradio.qtgui import Range, RangeWidget
import math
import rds
from gnuradio import qtgui

class rds_rx(gr.top_block, Qt.QWidget):

    def __init__(self):
        gr.top_block.__init__(self, "Stereo FM receiver and RDS Decoder")
        Qt.QWidget.__init__(self)
        self.setWindowTitle("Stereo FM receiver and RDS Decoder")
        qtgui.util.check_set_qss()
        try:
            self.setWindowIcon(Qt.QIcon.fromTheme('gnuradio-grc'))
        except:
            pass
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

        self.settings = Qt.QSettings("GNU Radio", "rds_rx")

        try:
            if StrictVersion(Qt.qVersion()) < StrictVersion("5.0.0"):
                self.restoreGeometry(self.settings.value("geometry").toByteArray())
            else:
                self.restoreGeometry(self.settings.value("geometry"))
        except:
            pass

        ##################################################
        # Variables
        ##################################################
        self.freq_offset = freq_offset = 250000
        self.freq = freq = 97e6
        self.volume = volume = -3
        self.samp_rate = samp_rate = 2000000
        self.gain = gain = 35
        self.freq_tune = freq_tune = freq - freq_offset

        ##################################################
        # Blocks
        ##################################################
        self._volume_range = Range(-20, 5, 1, -3, 200)
        self._volume_win = RangeWidget(self._volume_range, self.set_volume, 'volume', "counter_slider", float)
        self.top_grid_layout.addWidget(self._volume_win)
        self.tabs = Qt.QTabWidget()
        self.tabs_widget_0 = Qt.QWidget()
        self.tabs_layout_0 = Qt.QBoxLayout(Qt.QBoxLayout.TopToBottom, self.tabs_widget_0)
        self.tabs_grid_layout_0 = Qt.QGridLayout()
        self.tabs_layout_0.addLayout(self.tabs_grid_layout_0)
        self.tabs.addTab(self.tabs_widget_0, 'BB')
        self.tabs_widget_1 = Qt.QWidget()
        self.tabs_layout_1 = Qt.QBoxLayout(Qt.QBoxLayout.TopToBottom, self.tabs_widget_1)
        self.tabs_grid_layout_1 = Qt.QGridLayout()
        self.tabs_layout_1.addLayout(self.tabs_grid_layout_1)
        self.tabs.addTab(self.tabs_widget_1, 'Demod')
        self.tabs_widget_2 = Qt.QWidget()
        self.tabs_layout_2 = Qt.QBoxLayout(Qt.QBoxLayout.TopToBottom, self.tabs_widget_2)
        self.tabs_grid_layout_2 = Qt.QGridLayout()
        self.tabs_layout_2.addLayout(self.tabs_grid_layout_2)
        self.tabs.addTab(self.tabs_widget_2, 'Waterfall')
        self.tabs_widget_3 = Qt.QWidget()
        self.tabs_layout_3 = Qt.QBoxLayout(Qt.QBoxLayout.TopToBottom, self.tabs_widget_3)
        self.tabs_grid_layout_3 = Qt.QGridLayout()
        self.tabs_layout_3.addLayout(self.tabs_grid_layout_3)
        self.tabs.addTab(self.tabs_widget_3, 'L+R')
        self.tabs_widget_4 = Qt.QWidget()
        self.tabs_layout_4 = Qt.QBoxLayout(Qt.QBoxLayout.TopToBottom, self.tabs_widget_4)
        self.tabs_grid_layout_4 = Qt.QGridLayout()
        self.tabs_layout_4.addLayout(self.tabs_grid_layout_4)
        self.tabs.addTab(self.tabs_widget_4, 'L-R')
        self.tabs_widget_5 = Qt.QWidget()
        self.tabs_layout_5 = Qt.QBoxLayout(Qt.QBoxLayout.TopToBottom, self.tabs_widget_5)
        self.tabs_grid_layout_5 = Qt.QGridLayout()
        self.tabs_layout_5.addLayout(self.tabs_grid_layout_5)
        self.tabs.addTab(self.tabs_widget_5, 'RDS')
        self.tabs_widget_6 = Qt.QWidget()
        self.tabs_layout_6 = Qt.QBoxLayout(Qt.QBoxLayout.TopToBottom, self.tabs_widget_6)
        self.tabs_grid_layout_6 = Qt.QGridLayout()
        self.tabs_layout_6.addLayout(self.tabs_grid_layout_6)
        self.tabs.addTab(self.tabs_widget_6, 'Const')
        self.top_grid_layout.addWidget(self.tabs)
        self._gain_range = Range(0, 50, 1, 35, 200)
        self._gain_win = RangeWidget(self._gain_range, self.set_gain, 'gain', "counter_slider", float)
        self.top_grid_layout.addWidget(self._gain_win)
        self.uhd_usrp_source_0 = uhd.usrp_source(
            ",".join(('', "")),
            uhd.stream_args(
                cpu_format="fc32",
                args='',
                channels=list(range(0,1)),
            ),
        )
        self.uhd_usrp_source_0.set_center_freq(freq_tune, 0)
        self.uhd_usrp_source_0.set_gain(gain, 0)
        self.uhd_usrp_source_0.set_antenna('TX/RX', 0)
        self.uhd_usrp_source_0.set_samp_rate(samp_rate)
        self.uhd_usrp_source_0.set_time_unknown_pps(uhd.time_spec())
        self.root_raised_cosine_filter_0 = filter.fir_filter_ccf(
            2,
            firdes.root_raised_cosine(
                1,
                19000,
                2375,
                1,
                100))
        self.rds_parser_0 = rds.parser(False, False, 0)
        self.rds_panel_0 = rds.rdsPanel(0)
        self._rds_panel_0_win = self.rds_panel_0
        self.top_grid_layout.addWidget(self._rds_panel_0_win)
        self.rds_decoder_0 = rds.decoder(False, False)
        self.qtgui_waterfall_sink_x_0 = qtgui.waterfall_sink_f(
            1024, #size
            firdes.WIN_BLACKMAN_hARRIS, #wintype
            0, #fc
            250000, #bw
            "", #name
            1 #number of inputs
        )
        self.qtgui_waterfall_sink_x_0.set_update_time(0.10)
        self.qtgui_waterfall_sink_x_0.enable_grid(False)
        self.qtgui_waterfall_sink_x_0.enable_axis_labels(True)


        self.qtgui_waterfall_sink_x_0.set_plot_pos_half(not True)

        labels = ['', '', '', '', '',
                  '', '', '', '', '']
        colors = [0, 0, 0, 0, 0,
                  0, 0, 0, 0, 0]
        alphas = [1.0, 1.0, 1.0, 1.0, 1.0,
                  1.0, 1.0, 1.0, 1.0, 1.0]

        for i in range(1):
            if len(labels[i]) == 0:
                self.qtgui_waterfall_sink_x_0.set_line_label(i, "Data {0}".format(i))
            else:
                self.qtgui_waterfall_sink_x_0.set_line_label(i, labels[i])
            self.qtgui_waterfall_sink_x_0.set_color_map(i, colors[i])
            self.qtgui_waterfall_sink_x_0.set_line_alpha(i, alphas[i])

        self.qtgui_waterfall_sink_x_0.set_intensity_range(-140, 10)

        self._qtgui_waterfall_sink_x_0_win = sip.wrapinstance(self.qtgui_waterfall_sink_x_0.pyqwidget(), Qt.QWidget)
        self.tabs_layout_2.addWidget(self._qtgui_waterfall_sink_x_0_win)
        self.qtgui_freq_sink_x_4 = qtgui.freq_sink_f(
            1024, #size
            firdes.WIN_BLACKMAN_hARRIS, #wintype
            0, #fc
            48000, #bw
            "", #name
            1
        )
        self.qtgui_freq_sink_x_4.set_update_time(0.10)
        self.qtgui_freq_sink_x_4.set_y_axis(-140, 10)
        self.qtgui_freq_sink_x_4.set_y_label('Relative Gain', 'dB')
        self.qtgui_freq_sink_x_4.set_trigger_mode(qtgui.TRIG_MODE_FREE, 0.0, 0, "")
        self.qtgui_freq_sink_x_4.enable_autoscale(False)
        self.qtgui_freq_sink_x_4.enable_grid(False)
        self.qtgui_freq_sink_x_4.set_fft_average(1.0)
        self.qtgui_freq_sink_x_4.enable_axis_labels(True)
        self.qtgui_freq_sink_x_4.enable_control_panel(False)


        self.qtgui_freq_sink_x_4.set_plot_pos_half(not True)

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
                self.qtgui_freq_sink_x_4.set_line_label(i, "Data {0}".format(i))
            else:
                self.qtgui_freq_sink_x_4.set_line_label(i, labels[i])
            self.qtgui_freq_sink_x_4.set_line_width(i, widths[i])
            self.qtgui_freq_sink_x_4.set_line_color(i, colors[i])
            self.qtgui_freq_sink_x_4.set_line_alpha(i, alphas[i])

        self._qtgui_freq_sink_x_4_win = sip.wrapinstance(self.qtgui_freq_sink_x_4.pyqwidget(), Qt.QWidget)
        self.tabs_layout_4.addWidget(self._qtgui_freq_sink_x_4_win)
        self.qtgui_freq_sink_x_2_0 = qtgui.freq_sink_f(
            1024, #size
            firdes.WIN_BLACKMAN_hARRIS, #wintype
            0, #fc
            240000, #bw
            "", #name
            1
        )
        self.qtgui_freq_sink_x_2_0.set_update_time(0.10)
        self.qtgui_freq_sink_x_2_0.set_y_axis(-140, 10)
        self.qtgui_freq_sink_x_2_0.set_y_label('Relative Gain', 'dB')
        self.qtgui_freq_sink_x_2_0.set_trigger_mode(qtgui.TRIG_MODE_FREE, 0.0, 0, "")
        self.qtgui_freq_sink_x_2_0.enable_autoscale(False)
        self.qtgui_freq_sink_x_2_0.enable_grid(False)
        self.qtgui_freq_sink_x_2_0.set_fft_average(1.0)
        self.qtgui_freq_sink_x_2_0.enable_axis_labels(True)
        self.qtgui_freq_sink_x_2_0.enable_control_panel(False)


        self.qtgui_freq_sink_x_2_0.set_plot_pos_half(not True)

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
                self.qtgui_freq_sink_x_2_0.set_line_label(i, "Data {0}".format(i))
            else:
                self.qtgui_freq_sink_x_2_0.set_line_label(i, labels[i])
            self.qtgui_freq_sink_x_2_0.set_line_width(i, widths[i])
            self.qtgui_freq_sink_x_2_0.set_line_color(i, colors[i])
            self.qtgui_freq_sink_x_2_0.set_line_alpha(i, alphas[i])

        self._qtgui_freq_sink_x_2_0_win = sip.wrapinstance(self.qtgui_freq_sink_x_2_0.pyqwidget(), Qt.QWidget)
        self.tabs_layout_3.addWidget(self._qtgui_freq_sink_x_2_0_win)
        self.qtgui_freq_sink_x_2 = qtgui.freq_sink_c(
            1024, #size
            firdes.WIN_BLACKMAN_hARRIS, #wintype
            0, #fc
            19000, #bw
            "", #name
            1
        )
        self.qtgui_freq_sink_x_2.set_update_time(0.10)
        self.qtgui_freq_sink_x_2.set_y_axis(-140, 10)
        self.qtgui_freq_sink_x_2.set_y_label('Relative Gain', 'dB')
        self.qtgui_freq_sink_x_2.set_trigger_mode(qtgui.TRIG_MODE_FREE, 0.0, 0, "")
        self.qtgui_freq_sink_x_2.enable_autoscale(False)
        self.qtgui_freq_sink_x_2.enable_grid(False)
        self.qtgui_freq_sink_x_2.set_fft_average(1.0)
        self.qtgui_freq_sink_x_2.enable_axis_labels(True)
        self.qtgui_freq_sink_x_2.enable_control_panel(False)



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
                self.qtgui_freq_sink_x_2.set_line_label(i, "Data {0}".format(i))
            else:
                self.qtgui_freq_sink_x_2.set_line_label(i, labels[i])
            self.qtgui_freq_sink_x_2.set_line_width(i, widths[i])
            self.qtgui_freq_sink_x_2.set_line_color(i, colors[i])
            self.qtgui_freq_sink_x_2.set_line_alpha(i, alphas[i])

        self._qtgui_freq_sink_x_2_win = sip.wrapinstance(self.qtgui_freq_sink_x_2.pyqwidget(), Qt.QWidget)
        self.tabs_layout_5.addWidget(self._qtgui_freq_sink_x_2_win)
        self.qtgui_freq_sink_x_1 = qtgui.freq_sink_f(
            1024, #size
            firdes.WIN_BLACKMAN_hARRIS, #wintype
            0, #fc
            250000, #bw
            "", #name
            1
        )
        self.qtgui_freq_sink_x_1.set_update_time(0.10)
        self.qtgui_freq_sink_x_1.set_y_axis(-140, 10)
        self.qtgui_freq_sink_x_1.set_y_label('Relative Gain', 'dB')
        self.qtgui_freq_sink_x_1.set_trigger_mode(qtgui.TRIG_MODE_FREE, 0.0, 0, "")
        self.qtgui_freq_sink_x_1.enable_autoscale(False)
        self.qtgui_freq_sink_x_1.enable_grid(False)
        self.qtgui_freq_sink_x_1.set_fft_average(1.0)
        self.qtgui_freq_sink_x_1.enable_axis_labels(True)
        self.qtgui_freq_sink_x_1.enable_control_panel(False)


        self.qtgui_freq_sink_x_1.set_plot_pos_half(not True)

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
                self.qtgui_freq_sink_x_1.set_line_label(i, "Data {0}".format(i))
            else:
                self.qtgui_freq_sink_x_1.set_line_label(i, labels[i])
            self.qtgui_freq_sink_x_1.set_line_width(i, widths[i])
            self.qtgui_freq_sink_x_1.set_line_color(i, colors[i])
            self.qtgui_freq_sink_x_1.set_line_alpha(i, alphas[i])

        self._qtgui_freq_sink_x_1_win = sip.wrapinstance(self.qtgui_freq_sink_x_1.pyqwidget(), Qt.QWidget)
        self.tabs_layout_1.addWidget(self._qtgui_freq_sink_x_1_win)
        self.qtgui_freq_sink_x_0 = qtgui.freq_sink_c(
            1024, #size
            firdes.WIN_BLACKMAN_hARRIS, #wintype
            0, #fc
            samp_rate, #bw
            "", #name
            1
        )
        self.qtgui_freq_sink_x_0.set_update_time(0.10)
        self.qtgui_freq_sink_x_0.set_y_axis(-140, 10)
        self.qtgui_freq_sink_x_0.set_y_label('Relative Gain', 'dB')
        self.qtgui_freq_sink_x_0.set_trigger_mode(qtgui.TRIG_MODE_FREE, 0.0, 0, "")
        self.qtgui_freq_sink_x_0.enable_autoscale(False)
        self.qtgui_freq_sink_x_0.enable_grid(False)
        self.qtgui_freq_sink_x_0.set_fft_average(1.0)
        self.qtgui_freq_sink_x_0.enable_axis_labels(True)
        self.qtgui_freq_sink_x_0.enable_control_panel(False)



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

        self._qtgui_freq_sink_x_0_win = sip.wrapinstance(self.qtgui_freq_sink_x_0.pyqwidget(), Qt.QWidget)
        self.tabs_layout_0.addWidget(self._qtgui_freq_sink_x_0_win)
        self.qtgui_const_sink_x_0 = qtgui.const_sink_c(
            1024, #size
            "", #name
            1 #number of inputs
        )
        self.qtgui_const_sink_x_0.set_update_time(0.10)
        self.qtgui_const_sink_x_0.set_y_axis(-2, 2)
        self.qtgui_const_sink_x_0.set_x_axis(-2, 2)
        self.qtgui_const_sink_x_0.set_trigger_mode(qtgui.TRIG_MODE_FREE, qtgui.TRIG_SLOPE_POS, 0.0, 0, "")
        self.qtgui_const_sink_x_0.enable_autoscale(False)
        self.qtgui_const_sink_x_0.enable_grid(False)
        self.qtgui_const_sink_x_0.enable_axis_labels(True)


        labels = ['', '', '', '', '',
            '', '', '', '', '']
        widths = [1, 1, 1, 1, 1,
            1, 1, 1, 1, 1]
        colors = ["blue", "red", "red", "red", "red",
            "red", "red", "red", "red", "red"]
        styles = [0, 0, 0, 0, 0,
            0, 0, 0, 0, 0]
        markers = [0, 0, 0, 0, 0,
            0, 0, 0, 0, 0]
        alphas = [1.0, 1.0, 1.0, 1.0, 1.0,
            1.0, 1.0, 1.0, 1.0, 1.0]

        for i in range(1):
            if len(labels[i]) == 0:
                self.qtgui_const_sink_x_0.set_line_label(i, "Data {0}".format(i))
            else:
                self.qtgui_const_sink_x_0.set_line_label(i, labels[i])
            self.qtgui_const_sink_x_0.set_line_width(i, widths[i])
            self.qtgui_const_sink_x_0.set_line_color(i, colors[i])
            self.qtgui_const_sink_x_0.set_line_style(i, styles[i])
            self.qtgui_const_sink_x_0.set_line_marker(i, markers[i])
            self.qtgui_const_sink_x_0.set_line_alpha(i, alphas[i])

        self._qtgui_const_sink_x_0_win = sip.wrapinstance(self.qtgui_const_sink_x_0.pyqwidget(), Qt.QWidget)
        self.tabs_layout_6.addWidget(self._qtgui_const_sink_x_0_win)
        self.pfb_arb_resampler_xxx_1 = pfb.arb_resampler_fff(
            240000.0/250000,
            taps=None,
            flt_size=32)
        self.pfb_arb_resampler_xxx_1.declare_sample_delay(0)
        self.pfb_arb_resampler_xxx_0 = pfb.arb_resampler_ccf(
            19000/250e3,
            taps=None,
            flt_size=32)
        self.pfb_arb_resampler_xxx_0.declare_sample_delay(0)
        self.freq_xlating_fir_filter_xxx_2 = filter.freq_xlating_fir_filter_fcf(5, firdes.low_pass(1.0,240000,13e3,3e3,firdes.WIN_HAMMING), 38000, 240000)
        self.freq_xlating_fir_filter_xxx_1 = filter.freq_xlating_fir_filter_fcc(1, firdes.low_pass(2500.0,250000,2.6e3,2e3,firdes.WIN_HAMMING), 57e3, 250000)
        self.freq_xlating_fir_filter_xxx_0 = filter.freq_xlating_fir_filter_ccc(1, firdes.low_pass(1, samp_rate, 80000, 20000), freq_offset, samp_rate)
        self._freq_range = Range(88.0e6, 108.0e6, 0.1e6, 97e6, 200)
        self._freq_win = RangeWidget(self._freq_range, self.set_freq, 'freq', "counter_slider", float)
        self.top_grid_layout.addWidget(self._freq_win)
        self.fir_filter_xxx_1 = filter.fir_filter_fff(5, firdes.low_pass(1.0,240000,13e3,3e3,firdes.WIN_HAMMING))
        self.fir_filter_xxx_1.declare_sample_delay(0)
        self.digital_psk_demod_0 = digital.psk.psk_demod(
            constellation_points=2,
            differential=False,
            samples_per_symbol=4,
            excess_bw=0.35,
            phase_bw=6.28/100.0,
            timing_bw=6.28/100.0,
            mod_code="gray",
            verbose=False,
            log=False)
        self.digital_diff_decoder_bb_0 = digital.diff_decoder_bb(2)
        self.blocks_sub_xx_0 = blocks.sub_ff(1)
        self.blocks_multiply_const_vxx_0_0 = blocks.multiply_const_ff(10**(1.*(volume)/10))
        self.blocks_multiply_const_vxx_0 = blocks.multiply_const_ff(10**(1.*(volume)/10))
        self.blocks_keep_one_in_n_0 = blocks.keep_one_in_n(gr.sizeof_char*1, 2)
        self.blocks_complex_to_real_0 = blocks.complex_to_real(1)
        self.blocks_add_xx_0 = blocks.add_vff(1)
        self.audio_sink_0 = audio.sink(48000, '', True)
        self.analog_wfm_rcv_0 = analog.wfm_rcv(
        	quad_rate=samp_rate,
        	audio_decimation=8,
        )
        self.analog_fm_deemph_0_0_0 = analog.fm_deemph(fs=48000, tau=75e-6)
        self.analog_fm_deemph_0_0 = analog.fm_deemph(fs=48000, tau=75e-6)



        ##################################################
        # Connections
        ##################################################
        self.msg_connect((self.rds_decoder_0, 'out'), (self.rds_parser_0, 'in'))
        self.msg_connect((self.rds_parser_0, 'out'), (self.rds_panel_0, 'in'))
        self.connect((self.analog_fm_deemph_0_0, 0), (self.blocks_multiply_const_vxx_0_0, 0))
        self.connect((self.analog_fm_deemph_0_0_0, 0), (self.blocks_multiply_const_vxx_0, 0))
        self.connect((self.analog_wfm_rcv_0, 0), (self.freq_xlating_fir_filter_xxx_1, 0))
        self.connect((self.analog_wfm_rcv_0, 0), (self.pfb_arb_resampler_xxx_1, 0))
        self.connect((self.analog_wfm_rcv_0, 0), (self.qtgui_freq_sink_x_1, 0))
        self.connect((self.analog_wfm_rcv_0, 0), (self.qtgui_waterfall_sink_x_0, 0))
        self.connect((self.blocks_add_xx_0, 0), (self.analog_fm_deemph_0_0_0, 0))
        self.connect((self.blocks_complex_to_real_0, 0), (self.blocks_add_xx_0, 1))
        self.connect((self.blocks_complex_to_real_0, 0), (self.blocks_sub_xx_0, 1))
        self.connect((self.blocks_complex_to_real_0, 0), (self.qtgui_freq_sink_x_4, 0))
        self.connect((self.blocks_keep_one_in_n_0, 0), (self.digital_diff_decoder_bb_0, 0))
        self.connect((self.blocks_multiply_const_vxx_0, 0), (self.audio_sink_0, 0))
        self.connect((self.blocks_multiply_const_vxx_0_0, 0), (self.audio_sink_0, 1))
        self.connect((self.blocks_sub_xx_0, 0), (self.analog_fm_deemph_0_0, 0))
        self.connect((self.digital_diff_decoder_bb_0, 0), (self.rds_decoder_0, 0))
        self.connect((self.digital_psk_demod_0, 0), (self.blocks_keep_one_in_n_0, 0))
        self.connect((self.fir_filter_xxx_1, 0), (self.blocks_add_xx_0, 0))
        self.connect((self.fir_filter_xxx_1, 0), (self.blocks_sub_xx_0, 0))
        self.connect((self.fir_filter_xxx_1, 0), (self.qtgui_freq_sink_x_2_0, 0))
        self.connect((self.freq_xlating_fir_filter_xxx_0, 0), (self.analog_wfm_rcv_0, 0))
        self.connect((self.freq_xlating_fir_filter_xxx_0, 0), (self.qtgui_freq_sink_x_0, 0))
        self.connect((self.freq_xlating_fir_filter_xxx_1, 0), (self.pfb_arb_resampler_xxx_0, 0))
        self.connect((self.freq_xlating_fir_filter_xxx_2, 0), (self.blocks_complex_to_real_0, 0))
        self.connect((self.pfb_arb_resampler_xxx_0, 0), (self.qtgui_freq_sink_x_2, 0))
        self.connect((self.pfb_arb_resampler_xxx_0, 0), (self.root_raised_cosine_filter_0, 0))
        self.connect((self.pfb_arb_resampler_xxx_1, 0), (self.fir_filter_xxx_1, 0))
        self.connect((self.pfb_arb_resampler_xxx_1, 0), (self.freq_xlating_fir_filter_xxx_2, 0))
        self.connect((self.root_raised_cosine_filter_0, 0), (self.digital_psk_demod_0, 0))
        self.connect((self.root_raised_cosine_filter_0, 0), (self.qtgui_const_sink_x_0, 0))
        self.connect((self.uhd_usrp_source_0, 0), (self.freq_xlating_fir_filter_xxx_0, 0))

    def closeEvent(self, event):
        self.settings = Qt.QSettings("GNU Radio", "rds_rx")
        self.settings.setValue("geometry", self.saveGeometry())
        event.accept()

    def get_freq_offset(self):
        return self.freq_offset

    def set_freq_offset(self, freq_offset):
        self.freq_offset = freq_offset
        self.set_freq_tune(self.freq - self.freq_offset)
        self.freq_xlating_fir_filter_xxx_0.set_center_freq(self.freq_offset)

    def get_freq(self):
        return self.freq

    def set_freq(self, freq):
        self.freq = freq
        self.set_freq_tune(self.freq - self.freq_offset)

    def get_volume(self):
        return self.volume

    def set_volume(self, volume):
        self.volume = volume
        self.blocks_multiply_const_vxx_0.set_k(10**(1.*(self.volume)/10))
        self.blocks_multiply_const_vxx_0_0.set_k(10**(1.*(self.volume)/10))

    def get_samp_rate(self):
        return self.samp_rate

    def set_samp_rate(self, samp_rate):
        self.samp_rate = samp_rate
        self.freq_xlating_fir_filter_xxx_0.set_taps(firdes.low_pass(1, self.samp_rate, 80000, 20000))
        self.qtgui_freq_sink_x_0.set_frequency_range(0, self.samp_rate)
        self.uhd_usrp_source_0.set_samp_rate(self.samp_rate)

    def get_gain(self):
        return self.gain

    def set_gain(self, gain):
        self.gain = gain
        self.uhd_usrp_source_0.set_gain(self.gain, 0)

    def get_freq_tune(self):
        return self.freq_tune

    def set_freq_tune(self, freq_tune):
        self.freq_tune = freq_tune
        self.uhd_usrp_source_0.set_center_freq(self.freq_tune, 0)



def main(top_block_cls=rds_rx, options=None):

    if StrictVersion("4.5.0") <= StrictVersion(Qt.qVersion()) < StrictVersion("5.0.0"):
        style = gr.prefs().get_string('qtgui', 'style', 'raster')
        Qt.QApplication.setGraphicsSystem(style)
    qapp = Qt.QApplication(sys.argv)

    tb = top_block_cls()
    tb.start()
    tb.show()

    def sig_handler(sig=None, frame=None):
        Qt.QApplication.quit()

    signal.signal(signal.SIGINT, sig_handler)
    signal.signal(signal.SIGTERM, sig_handler)

    timer = Qt.QTimer()
    timer.start(500)
    timer.timeout.connect(lambda: None)

    def quitting():
        tb.stop()
        tb.wait()
    qapp.aboutToQuit.connect(quitting)
    qapp.exec_()


if __name__ == '__main__':
    main()
