#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#
# SPDX-License-Identifier: GPL-3.0
#
# GNU Radio Python Flow Graph
# Title: FM Receiver
# Author: Johannes Demel
# GNU Radio version: 3.8tech-preview-381-g27dd99e4

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

import os
import sys
sys.path.append(os.environ.get('GRC_HIER_PATH', os.path.expanduser('~/.grc_gnuradio')))

from PyQt5 import Qt
from gnuradio import qtgui
from gnuradio.filter import firdes
import sip
from fm_stereo_audio_decoder import fm_stereo_audio_decoder  # grc-generated hier_block
from gnuradio import analog
from gnuradio import audio
from gnuradio import blocks
from gnuradio import digital
from gnuradio import filter
from gnuradio import gr
from argparse import ArgumentParser
from gnuradio.eng_arg import eng_float, intx
from gnuradio import eng_notation
from gnuradio.qtgui import Range, RangeWidget
import math
import rds
from gnuradio import qtgui

class fm_rds_alternate(gr.top_block, Qt.QWidget):

    def __init__(self):
        gr.top_block.__init__(self, "FM Receiver")
        Qt.QWidget.__init__(self)
        self.setWindowTitle("FM Receiver")
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

        self.settings = Qt.QSettings("GNU Radio", "fm_rds_alternate")

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
        self.symbols_per_bit = symbols_per_bit = 2
        self.rds_bit_rate = rds_bit_rate = 1187.5
        self.x_decimation = x_decimation = 4
        self.samples_per_symbol = samples_per_symbol = 8
        self.samp_rate = samp_rate = 2.e6
        self.rds_symbol_rate = rds_symbol_rate = symbols_per_bit * rds_bit_rate
        self.x_samp_rate = x_samp_rate = samp_rate / x_decimation
        self.rrc_decim = rrc_decim = 2
        self.rds_sample_rate = rds_sample_rate = samples_per_symbol * rds_symbol_rate
        self.baseband_decim = baseband_decim = 2
        self.variable_constellation_rect_0 = variable_constellation_rect_0 = digital.constellation_rect([-1-1j, -1+1j, 1+1j, 1-1j], [0, 1, 3, 2],
        4, 2, 2, 1, 1).base()
        self.rrc_sample_rate = rrc_sample_rate = rds_sample_rate * rrc_decim
        self.rds_decim = rds_decim = 4
        self.fm_freq = fm_freq = 101.2e6
        self.excess_bw = excess_bw = .48
        self.dgain = dgain = 30
        self.baseband_sample_rate = baseband_sample_rate = x_samp_rate / baseband_decim
        self.audio_rate = audio_rate = 48e3

        ##################################################
        # Blocks
        ##################################################
        self.tabs = Qt.QTabWidget()
        self.tabs_widget_0 = Qt.QWidget()
        self.tabs_layout_0 = Qt.QBoxLayout(Qt.QBoxLayout.TopToBottom, self.tabs_widget_0)
        self.tabs_grid_layout_0 = Qt.QGridLayout()
        self.tabs_layout_0.addLayout(self.tabs_grid_layout_0)
        self.tabs.addTab(self.tabs_widget_0, 'RF Properties')
        self.tabs_widget_1 = Qt.QWidget()
        self.tabs_layout_1 = Qt.QBoxLayout(Qt.QBoxLayout.TopToBottom, self.tabs_widget_1)
        self.tabs_grid_layout_1 = Qt.QGridLayout()
        self.tabs_layout_1.addLayout(self.tabs_grid_layout_1)
        self.tabs.addTab(self.tabs_widget_1, 'FM Band')
        self.tabs_widget_2 = Qt.QWidget()
        self.tabs_layout_2 = Qt.QBoxLayout(Qt.QBoxLayout.TopToBottom, self.tabs_widget_2)
        self.tabs_grid_layout_2 = Qt.QGridLayout()
        self.tabs_layout_2.addLayout(self.tabs_grid_layout_2)
        self.tabs.addTab(self.tabs_widget_2, 'RDS')
        self.tabs_widget_3 = Qt.QWidget()
        self.tabs_layout_3 = Qt.QBoxLayout(Qt.QBoxLayout.TopToBottom, self.tabs_widget_3)
        self.tabs_grid_layout_3 = Qt.QGridLayout()
        self.tabs_layout_3.addLayout(self.tabs_grid_layout_3)
        self.tabs.addTab(self.tabs_widget_3, 'Audio')
        self.top_grid_layout.addWidget(self.tabs, 1, 0, 9, 9)
        for r in range(1, 10):
            self.top_grid_layout.setRowStretch(r, 1)
        for c in range(0, 9):
            self.top_grid_layout.setColumnStretch(c, 1)
        self._fm_freq_range = Range(87.5e6, 108.e6, 1e5, 101.2e6, 200)
        self._fm_freq_win = RangeWidget(self._fm_freq_range, self.set_fm_freq, 'FM Carrier Frequency', "counter_slider", float)
        self.top_grid_layout.addWidget(self._fm_freq_win, 0, 4, 1, 5)
        for r in range(0, 1):
            self.top_grid_layout.setRowStretch(r, 1)
        for c in range(4, 9):
            self.top_grid_layout.setColumnStretch(c, 1)
        self.root_raised_cosine_filter_0 = filter.fir_filter_ccf(
            rrc_decim,
            firdes.root_raised_cosine(
                1,
                rrc_sample_rate,
                rds_symbol_rate,
                1,
                100))
        self.rds_parser_0 = rds.parser(False, False, 0)
        self.rds_panel_0 = rds.rdsPanel(0)
        self._rds_panel_0_win = self.rds_panel_0
        self.top_grid_layout.addWidget(self._rds_panel_0_win)
        self.rds_decoder_0 = rds.decoder(False, False)
        self.rational_resampler_xxx_0 = filter.rational_resampler_ccc(
                interpolation=int(rrc_sample_rate),
                decimation=int(baseband_sample_rate / rds_decim),
                taps=None,
                fractional_bw=None)
        self.qtgui_time_sink_x_0 = qtgui.time_sink_f(
            128, #size
            baseband_sample_rate, #samp_rate
            "2x Pilot Tone", #name
            1 #number of inputs
        )
        self.qtgui_time_sink_x_0.set_update_time(0.10)
        self.qtgui_time_sink_x_0.set_y_axis(-1, 1)

        self.qtgui_time_sink_x_0.set_y_label('Amplitude', "")

        self.qtgui_time_sink_x_0.enable_tags(True)
        self.qtgui_time_sink_x_0.set_trigger_mode(qtgui.TRIG_MODE_FREE, qtgui.TRIG_SLOPE_POS, 0.0, 0, 0, "")
        self.qtgui_time_sink_x_0.enable_autoscale(True)
        self.qtgui_time_sink_x_0.enable_grid(True)
        self.qtgui_time_sink_x_0.enable_axis_labels(True)
        self.qtgui_time_sink_x_0.enable_control_panel(False)
        self.qtgui_time_sink_x_0.enable_stem_plot(False)


        labels = ['', '', '', '', '',
            '', '', '', '', '']
        widths = [1, 1, 1, 1, 1,
            1, 1, 1, 1, 1]
        colors = ["blue", "red", "green", "black", "cyan",
            "magenta", "yellow", "dark red", "dark green", "blue"]
        alphas = [1.0, 1.0, 1.0, 1.0, 1.0,
            1.0, 1.0, 1.0, 1.0, 1.0]
        styles = [1, 1, 1, 1, 1,
            1, 1, 1, 1, 1]
        markers = [-1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1]


        for i in range(1):
            if len(labels[i]) == 0:
                self.qtgui_time_sink_x_0.set_line_label(i, "Data {0}".format(i))
            else:
                self.qtgui_time_sink_x_0.set_line_label(i, labels[i])
            self.qtgui_time_sink_x_0.set_line_width(i, widths[i])
            self.qtgui_time_sink_x_0.set_line_color(i, colors[i])
            self.qtgui_time_sink_x_0.set_line_style(i, styles[i])
            self.qtgui_time_sink_x_0.set_line_marker(i, markers[i])
            self.qtgui_time_sink_x_0.set_line_alpha(i, alphas[i])

        self._qtgui_time_sink_x_0_win = sip.wrapinstance(self.qtgui_time_sink_x_0.pyqwidget(), Qt.QWidget)
        self.tabs_grid_layout_3.addWidget(self._qtgui_time_sink_x_0_win, 4, 4, 4, 4)
        for r in range(4, 8):
            self.tabs_grid_layout_3.setRowStretch(r, 1)
        for c in range(4, 8):
            self.tabs_grid_layout_3.setColumnStretch(c, 1)
        self.qtgui_freq_sink_x_1 = qtgui.freq_sink_c(
            1024, #size
            firdes.WIN_BLACKMAN_hARRIS, #wintype
            0, #fc
            rrc_sample_rate, #bw
            "RDS Spectrum", #name
            2
        )
        self.qtgui_freq_sink_x_1.set_update_time(0.10)
        self.qtgui_freq_sink_x_1.set_y_axis(-140, 10)
        self.qtgui_freq_sink_x_1.set_y_label('Relative Gain', 'dB')
        self.qtgui_freq_sink_x_1.set_trigger_mode(qtgui.TRIG_MODE_FREE, 0.0, 0, "")
        self.qtgui_freq_sink_x_1.enable_autoscale(True)
        self.qtgui_freq_sink_x_1.enable_grid(False)
        self.qtgui_freq_sink_x_1.set_fft_average(1.0)
        self.qtgui_freq_sink_x_1.enable_axis_labels(True)
        self.qtgui_freq_sink_x_1.enable_control_panel(False)



        labels = ['', '', '', '', '',
            '', '', '', '', '']
        widths = [1, 1, 1, 1, 1,
            1, 1, 1, 1, 1]
        colors = ["blue", "red", "green", "black", "cyan",
            "magenta", "yellow", "dark red", "dark green", "dark blue"]
        alphas = [1.0, 1.0, 1.0, 1.0, 1.0,
            1.0, 1.0, 1.0, 1.0, 1.0]

        for i in range(2):
            if len(labels[i]) == 0:
                self.qtgui_freq_sink_x_1.set_line_label(i, "Data {0}".format(i))
            else:
                self.qtgui_freq_sink_x_1.set_line_label(i, labels[i])
            self.qtgui_freq_sink_x_1.set_line_width(i, widths[i])
            self.qtgui_freq_sink_x_1.set_line_color(i, colors[i])
            self.qtgui_freq_sink_x_1.set_line_alpha(i, alphas[i])

        self._qtgui_freq_sink_x_1_win = sip.wrapinstance(self.qtgui_freq_sink_x_1.pyqwidget(), Qt.QWidget)
        self.tabs_grid_layout_2.addWidget(self._qtgui_freq_sink_x_1_win, 0, 0, 5, 5)
        for r in range(0, 5):
            self.tabs_grid_layout_2.setRowStretch(r, 1)
        for c in range(0, 5):
            self.tabs_grid_layout_2.setColumnStretch(c, 1)
        self.qtgui_freq_sink_x_0_0_0_1_0_1 = qtgui.freq_sink_f(
            1024, #size
            firdes.WIN_RECTANGULAR, #wintype
            0.0, #fc
            baseband_sample_rate, #bw
            "DSB-SC Spectrum", #name
            1
        )
        self.qtgui_freq_sink_x_0_0_0_1_0_1.set_update_time(0.10)
        self.qtgui_freq_sink_x_0_0_0_1_0_1.set_y_axis(-140, 10)
        self.qtgui_freq_sink_x_0_0_0_1_0_1.set_y_label('Relative Gain', 'dB')
        self.qtgui_freq_sink_x_0_0_0_1_0_1.set_trigger_mode(qtgui.TRIG_MODE_FREE, 0.0, 0, "")
        self.qtgui_freq_sink_x_0_0_0_1_0_1.enable_autoscale(True)
        self.qtgui_freq_sink_x_0_0_0_1_0_1.enable_grid(False)
        self.qtgui_freq_sink_x_0_0_0_1_0_1.set_fft_average(0.05)
        self.qtgui_freq_sink_x_0_0_0_1_0_1.enable_axis_labels(True)
        self.qtgui_freq_sink_x_0_0_0_1_0_1.enable_control_panel(False)

        self.qtgui_freq_sink_x_0_0_0_1_0_1.disable_legend()

        self.qtgui_freq_sink_x_0_0_0_1_0_1.set_plot_pos_half(not False)

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
                self.qtgui_freq_sink_x_0_0_0_1_0_1.set_line_label(i, "Data {0}".format(i))
            else:
                self.qtgui_freq_sink_x_0_0_0_1_0_1.set_line_label(i, labels[i])
            self.qtgui_freq_sink_x_0_0_0_1_0_1.set_line_width(i, widths[i])
            self.qtgui_freq_sink_x_0_0_0_1_0_1.set_line_color(i, colors[i])
            self.qtgui_freq_sink_x_0_0_0_1_0_1.set_line_alpha(i, alphas[i])

        self._qtgui_freq_sink_x_0_0_0_1_0_1_win = sip.wrapinstance(self.qtgui_freq_sink_x_0_0_0_1_0_1.pyqwidget(), Qt.QWidget)
        self.tabs_grid_layout_3.addWidget(self._qtgui_freq_sink_x_0_0_0_1_0_1_win, 4, 0, 4, 4)
        for r in range(4, 8):
            self.tabs_grid_layout_3.setRowStretch(r, 1)
        for c in range(0, 4):
            self.tabs_grid_layout_3.setColumnStretch(c, 1)
        self.qtgui_freq_sink_x_0_0_0_1_0_0 = qtgui.freq_sink_f(
            1024, #size
            firdes.WIN_RECTANGULAR, #wintype
            0.0, #fc
            baseband_sample_rate / 5, #bw
            "L-R Spectrum", #name
            1
        )
        self.qtgui_freq_sink_x_0_0_0_1_0_0.set_update_time(0.10)
        self.qtgui_freq_sink_x_0_0_0_1_0_0.set_y_axis(-140, 10)
        self.qtgui_freq_sink_x_0_0_0_1_0_0.set_y_label('Relative Gain', 'dB')
        self.qtgui_freq_sink_x_0_0_0_1_0_0.set_trigger_mode(qtgui.TRIG_MODE_FREE, 0.0, 0, "")
        self.qtgui_freq_sink_x_0_0_0_1_0_0.enable_autoscale(True)
        self.qtgui_freq_sink_x_0_0_0_1_0_0.enable_grid(False)
        self.qtgui_freq_sink_x_0_0_0_1_0_0.set_fft_average(0.05)
        self.qtgui_freq_sink_x_0_0_0_1_0_0.enable_axis_labels(True)
        self.qtgui_freq_sink_x_0_0_0_1_0_0.enable_control_panel(False)

        self.qtgui_freq_sink_x_0_0_0_1_0_0.disable_legend()

        self.qtgui_freq_sink_x_0_0_0_1_0_0.set_plot_pos_half(not False)

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
                self.qtgui_freq_sink_x_0_0_0_1_0_0.set_line_label(i, "Data {0}".format(i))
            else:
                self.qtgui_freq_sink_x_0_0_0_1_0_0.set_line_label(i, labels[i])
            self.qtgui_freq_sink_x_0_0_0_1_0_0.set_line_width(i, widths[i])
            self.qtgui_freq_sink_x_0_0_0_1_0_0.set_line_color(i, colors[i])
            self.qtgui_freq_sink_x_0_0_0_1_0_0.set_line_alpha(i, alphas[i])

        self._qtgui_freq_sink_x_0_0_0_1_0_0_win = sip.wrapinstance(self.qtgui_freq_sink_x_0_0_0_1_0_0.pyqwidget(), Qt.QWidget)
        self.tabs_grid_layout_3.addWidget(self._qtgui_freq_sink_x_0_0_0_1_0_0_win, 0, 4, 4, 4)
        for r in range(0, 4):
            self.tabs_grid_layout_3.setRowStretch(r, 1)
        for c in range(4, 8):
            self.tabs_grid_layout_3.setColumnStretch(c, 1)
        self.qtgui_freq_sink_x_0_0_0_1_0 = qtgui.freq_sink_f(
            1024, #size
            firdes.WIN_RECTANGULAR, #wintype
            0.0, #fc
            baseband_sample_rate / 5, #bw
            "L+R Spectrum", #name
            1
        )
        self.qtgui_freq_sink_x_0_0_0_1_0.set_update_time(0.10)
        self.qtgui_freq_sink_x_0_0_0_1_0.set_y_axis(-140, 10)
        self.qtgui_freq_sink_x_0_0_0_1_0.set_y_label('Relative Gain', 'dB')
        self.qtgui_freq_sink_x_0_0_0_1_0.set_trigger_mode(qtgui.TRIG_MODE_FREE, 0.0, 0, "")
        self.qtgui_freq_sink_x_0_0_0_1_0.enable_autoscale(True)
        self.qtgui_freq_sink_x_0_0_0_1_0.enable_grid(False)
        self.qtgui_freq_sink_x_0_0_0_1_0.set_fft_average(0.05)
        self.qtgui_freq_sink_x_0_0_0_1_0.enable_axis_labels(True)
        self.qtgui_freq_sink_x_0_0_0_1_0.enable_control_panel(False)

        self.qtgui_freq_sink_x_0_0_0_1_0.disable_legend()

        self.qtgui_freq_sink_x_0_0_0_1_0.set_plot_pos_half(not False)

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
                self.qtgui_freq_sink_x_0_0_0_1_0.set_line_label(i, "Data {0}".format(i))
            else:
                self.qtgui_freq_sink_x_0_0_0_1_0.set_line_label(i, labels[i])
            self.qtgui_freq_sink_x_0_0_0_1_0.set_line_width(i, widths[i])
            self.qtgui_freq_sink_x_0_0_0_1_0.set_line_color(i, colors[i])
            self.qtgui_freq_sink_x_0_0_0_1_0.set_line_alpha(i, alphas[i])

        self._qtgui_freq_sink_x_0_0_0_1_0_win = sip.wrapinstance(self.qtgui_freq_sink_x_0_0_0_1_0.pyqwidget(), Qt.QWidget)
        self.tabs_grid_layout_3.addWidget(self._qtgui_freq_sink_x_0_0_0_1_0_win, 0, 0, 4, 4)
        for r in range(0, 4):
            self.tabs_grid_layout_3.setRowStretch(r, 1)
        for c in range(0, 4):
            self.tabs_grid_layout_3.setColumnStretch(c, 1)
        self.qtgui_freq_sink_x_0_0_0_1 = qtgui.freq_sink_f(
            4096, #size
            firdes.WIN_RECTANGULAR, #wintype
            0.0, #fc
            baseband_sample_rate, #bw
            "FM demodulated spectrum", #name
            1
        )
        self.qtgui_freq_sink_x_0_0_0_1.set_update_time(0.10)
        self.qtgui_freq_sink_x_0_0_0_1.set_y_axis(-140, 10)
        self.qtgui_freq_sink_x_0_0_0_1.set_y_label('Relative Gain', 'dB')
        self.qtgui_freq_sink_x_0_0_0_1.set_trigger_mode(qtgui.TRIG_MODE_FREE, 0.0, 0, "")
        self.qtgui_freq_sink_x_0_0_0_1.enable_autoscale(True)
        self.qtgui_freq_sink_x_0_0_0_1.enable_grid(False)
        self.qtgui_freq_sink_x_0_0_0_1.set_fft_average(0.1)
        self.qtgui_freq_sink_x_0_0_0_1.enable_axis_labels(True)
        self.qtgui_freq_sink_x_0_0_0_1.enable_control_panel(True)

        self.qtgui_freq_sink_x_0_0_0_1.disable_legend()

        self.qtgui_freq_sink_x_0_0_0_1.set_plot_pos_half(not False)

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
                self.qtgui_freq_sink_x_0_0_0_1.set_line_label(i, "Data {0}".format(i))
            else:
                self.qtgui_freq_sink_x_0_0_0_1.set_line_label(i, labels[i])
            self.qtgui_freq_sink_x_0_0_0_1.set_line_width(i, widths[i])
            self.qtgui_freq_sink_x_0_0_0_1.set_line_color(i, colors[i])
            self.qtgui_freq_sink_x_0_0_0_1.set_line_alpha(i, alphas[i])

        self._qtgui_freq_sink_x_0_0_0_1_win = sip.wrapinstance(self.qtgui_freq_sink_x_0_0_0_1.pyqwidget(), Qt.QWidget)
        self.tabs_grid_layout_1.addWidget(self._qtgui_freq_sink_x_0_0_0_1_win, 0, 0, 8, 9)
        for r in range(0, 8):
            self.tabs_grid_layout_1.setRowStretch(r, 1)
        for c in range(0, 9):
            self.tabs_grid_layout_1.setColumnStretch(c, 1)
        self.qtgui_freq_sink_x_0 = qtgui.freq_sink_c(
            4096, #size
            firdes.WIN_BLACKMAN_hARRIS, #wintype
            fm_freq, #fc
            samp_rate/x_decimation, #bw
            "Radio Spectrum", #name
            1
        )
        self.qtgui_freq_sink_x_0.set_update_time(0.10)
        self.qtgui_freq_sink_x_0.set_y_axis(-140, 10)
        self.qtgui_freq_sink_x_0.set_y_label('Relative Gain', 'dB')
        self.qtgui_freq_sink_x_0.set_trigger_mode(qtgui.TRIG_MODE_FREE, 0.0, 0, "")
        self.qtgui_freq_sink_x_0.enable_autoscale(True)
        self.qtgui_freq_sink_x_0.enable_grid(False)
        self.qtgui_freq_sink_x_0.set_fft_average(0.2)
        self.qtgui_freq_sink_x_0.enable_axis_labels(True)
        self.qtgui_freq_sink_x_0.enable_control_panel(True)

        self.qtgui_freq_sink_x_0.disable_legend()


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
        self.tabs_grid_layout_0.addWidget(self._qtgui_freq_sink_x_0_win, 0, 0, 8, 9)
        for r in range(0, 8):
            self.tabs_grid_layout_0.setRowStretch(r, 1)
        for c in range(0, 9):
            self.tabs_grid_layout_0.setColumnStretch(c, 1)
        self.qtgui_const_sink_x_0 = qtgui.const_sink_c(
            256, #size
            "RDS Constellation", #name
            2 #number of inputs
        )
        self.qtgui_const_sink_x_0.set_update_time(0.10)
        self.qtgui_const_sink_x_0.set_y_axis(-2, 2)
        self.qtgui_const_sink_x_0.set_x_axis(-2, 2)
        self.qtgui_const_sink_x_0.set_trigger_mode(qtgui.TRIG_MODE_FREE, qtgui.TRIG_SLOPE_POS, 0.0, 0, "")
        self.qtgui_const_sink_x_0.enable_autoscale(True)
        self.qtgui_const_sink_x_0.enable_grid(True)
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

        for i in range(2):
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
        self.tabs_grid_layout_2.addWidget(self._qtgui_const_sink_x_0_win, 0, 5, 4, 4)
        for r in range(0, 4):
            self.tabs_grid_layout_2.setRowStretch(r, 1)
        for c in range(5, 9):
            self.tabs_grid_layout_2.setColumnStretch(c, 1)
        self.freq_xlating_fir_filter_xxx_1 = filter.freq_xlating_fir_filter_fcc(rds_decim, firdes.low_pass(2500.0,baseband_sample_rate,2.2e3,2e3,firdes.WIN_HAMMING), 57e3, baseband_sample_rate)
        self.freq_xlating_fir_filter_xxx_0 = filter.freq_xlating_fir_filter_ccc(x_decimation, firdes.low_pass(1, samp_rate, 100e3, 100e3), 0, samp_rate)
        self.fm_stereo_audio_decoder_0 = fm_stereo_audio_decoder(
            audio_rate=audio_rate,
            baseband_rate=baseband_sample_rate,
            volume=-15.,
        )
        self.digital_pfb_clock_sync_xxx_0 = digital.pfb_clock_sync_ccf(samples_per_symbol, 2 * 6.28/100, firdes.root_raised_cosine(32, 32*7, 1.0, excess_bw, 11*7*32), 32, 16, 1.5, 1)
        self.digital_fll_band_edge_cc_0 = digital.fll_band_edge_cc(samples_per_symbol, excess_bw, 55, .3 * 6.28/100)
        self.digital_diff_decoder_bb_0 = digital.diff_decoder_bb(2)
        self.digital_constellation_receiver_cb_0 = digital.constellation_receiver_cb(digital.constellation_bpsk().base(), 4 * 6.28/100, -.25, .25)
        self._dgain_range = Range(0, 50, 1, 30, 200)
        self._dgain_win = RangeWidget(self._dgain_range, self.set_dgain, 'RF Gain', "counter_slider", float)
        self.top_grid_layout.addWidget(self._dgain_win, 0, 0, 1, 4)
        for r in range(0, 1):
            self.top_grid_layout.setRowStretch(r, 1)
        for c in range(0, 4):
            self.top_grid_layout.setColumnStretch(c, 1)
        self.blocks_null_source_0 = blocks.null_source(gr.sizeof_gr_complex*1)
        self.blocks_null_sink_0_0 = blocks.null_sink(gr.sizeof_float*1)
        self.blocks_keep_one_in_n_0 = blocks.keep_one_in_n(gr.sizeof_char*1, symbols_per_bit)
        self.audio_sink_0_0 = audio.sink(int(audio_rate), '', True)
        self.analog_wfm_rcv_0 = analog.wfm_rcv(
        	quad_rate=x_samp_rate,
        	audio_decimation=baseband_decim,
        )
        self.analog_agc2_xx_0 = analog.agc2_cc(.6e-1, 1e-3, 1.0, 1.0)
        self.analog_agc2_xx_0.set_max_gain(65536)



        ##################################################
        # Connections
        ##################################################
        self.msg_connect((self.rds_decoder_0, 'out'), (self.rds_parser_0, 'in'))
        self.msg_connect((self.rds_parser_0, 'out'), (self.rds_panel_0, 'in'))
        self.connect((self.analog_agc2_xx_0, 0), (self.digital_fll_band_edge_cc_0, 0))
        self.connect((self.analog_wfm_rcv_0, 0), (self.fm_stereo_audio_decoder_0, 0))
        self.connect((self.analog_wfm_rcv_0, 0), (self.freq_xlating_fir_filter_xxx_1, 0))
        self.connect((self.analog_wfm_rcv_0, 0), (self.qtgui_freq_sink_x_0_0_0_1, 0))
        self.connect((self.blocks_keep_one_in_n_0, 0), (self.digital_diff_decoder_bb_0, 0))
        self.connect((self.blocks_null_source_0, 0), (self.freq_xlating_fir_filter_xxx_0, 0))
        self.connect((self.digital_constellation_receiver_cb_0, 0), (self.blocks_keep_one_in_n_0, 0))
        self.connect((self.digital_constellation_receiver_cb_0, 3), (self.blocks_null_sink_0_0, 2))
        self.connect((self.digital_constellation_receiver_cb_0, 2), (self.blocks_null_sink_0_0, 1))
        self.connect((self.digital_constellation_receiver_cb_0, 1), (self.blocks_null_sink_0_0, 0))
        self.connect((self.digital_constellation_receiver_cb_0, 4), (self.qtgui_const_sink_x_0, 1))
        self.connect((self.digital_diff_decoder_bb_0, 0), (self.rds_decoder_0, 0))
        self.connect((self.digital_fll_band_edge_cc_0, 0), (self.digital_pfb_clock_sync_xxx_0, 0))
        self.connect((self.digital_fll_band_edge_cc_0, 0), (self.qtgui_freq_sink_x_1, 1))
        self.connect((self.digital_pfb_clock_sync_xxx_0, 0), (self.digital_constellation_receiver_cb_0, 0))
        self.connect((self.digital_pfb_clock_sync_xxx_0, 0), (self.qtgui_const_sink_x_0, 0))
        self.connect((self.fm_stereo_audio_decoder_0, 1), (self.audio_sink_0_0, 1))
        self.connect((self.fm_stereo_audio_decoder_0, 0), (self.audio_sink_0_0, 0))
        self.connect((self.fm_stereo_audio_decoder_0, 4), (self.qtgui_freq_sink_x_0_0_0_1_0, 0))
        self.connect((self.fm_stereo_audio_decoder_0, 5), (self.qtgui_freq_sink_x_0_0_0_1_0_0, 0))
        self.connect((self.fm_stereo_audio_decoder_0, 2), (self.qtgui_freq_sink_x_0_0_0_1_0_1, 0))
        self.connect((self.fm_stereo_audio_decoder_0, 3), (self.qtgui_time_sink_x_0, 0))
        self.connect((self.freq_xlating_fir_filter_xxx_0, 0), (self.analog_wfm_rcv_0, 0))
        self.connect((self.freq_xlating_fir_filter_xxx_0, 0), (self.qtgui_freq_sink_x_0, 0))
        self.connect((self.freq_xlating_fir_filter_xxx_1, 0), (self.rational_resampler_xxx_0, 0))
        self.connect((self.rational_resampler_xxx_0, 0), (self.root_raised_cosine_filter_0, 0))
        self.connect((self.root_raised_cosine_filter_0, 0), (self.analog_agc2_xx_0, 0))
        self.connect((self.root_raised_cosine_filter_0, 0), (self.qtgui_freq_sink_x_1, 0))

    def closeEvent(self, event):
        self.settings = Qt.QSettings("GNU Radio", "fm_rds_alternate")
        self.settings.setValue("geometry", self.saveGeometry())
        event.accept()

    def get_symbols_per_bit(self):
        return self.symbols_per_bit

    def set_symbols_per_bit(self, symbols_per_bit):
        self.symbols_per_bit = symbols_per_bit
        self.set_rds_symbol_rate(self.symbols_per_bit * self.rds_bit_rate)
        self.blocks_keep_one_in_n_0.set_n(self.symbols_per_bit)

    def get_rds_bit_rate(self):
        return self.rds_bit_rate

    def set_rds_bit_rate(self, rds_bit_rate):
        self.rds_bit_rate = rds_bit_rate
        self.set_rds_symbol_rate(self.symbols_per_bit * self.rds_bit_rate)

    def get_x_decimation(self):
        return self.x_decimation

    def set_x_decimation(self, x_decimation):
        self.x_decimation = x_decimation
        self.set_x_samp_rate(self.samp_rate / self.x_decimation)
        self.qtgui_freq_sink_x_0.set_frequency_range(self.fm_freq, self.samp_rate/self.x_decimation)

    def get_samples_per_symbol(self):
        return self.samples_per_symbol

    def set_samples_per_symbol(self, samples_per_symbol):
        self.samples_per_symbol = samples_per_symbol
        self.set_rds_sample_rate(self.samples_per_symbol * self.rds_symbol_rate)

    def get_samp_rate(self):
        return self.samp_rate

    def set_samp_rate(self, samp_rate):
        self.samp_rate = samp_rate
        self.set_x_samp_rate(self.samp_rate / self.x_decimation)
        self.freq_xlating_fir_filter_xxx_0.set_taps(firdes.low_pass(1, self.samp_rate, 100e3, 100e3))
        self.qtgui_freq_sink_x_0.set_frequency_range(self.fm_freq, self.samp_rate/self.x_decimation)

    def get_rds_symbol_rate(self):
        return self.rds_symbol_rate

    def set_rds_symbol_rate(self, rds_symbol_rate):
        self.rds_symbol_rate = rds_symbol_rate
        self.set_rds_sample_rate(self.samples_per_symbol * self.rds_symbol_rate)
        self.root_raised_cosine_filter_0.set_taps(firdes.root_raised_cosine(1, self.rrc_sample_rate, self.rds_symbol_rate, 1, 100))

    def get_x_samp_rate(self):
        return self.x_samp_rate

    def set_x_samp_rate(self, x_samp_rate):
        self.x_samp_rate = x_samp_rate
        self.set_baseband_sample_rate(self.x_samp_rate / self.baseband_decim)

    def get_rrc_decim(self):
        return self.rrc_decim

    def set_rrc_decim(self, rrc_decim):
        self.rrc_decim = rrc_decim
        self.set_rrc_sample_rate(self.rds_sample_rate * self.rrc_decim)

    def get_rds_sample_rate(self):
        return self.rds_sample_rate

    def set_rds_sample_rate(self, rds_sample_rate):
        self.rds_sample_rate = rds_sample_rate
        self.set_rrc_sample_rate(self.rds_sample_rate * self.rrc_decim)

    def get_baseband_decim(self):
        return self.baseband_decim

    def set_baseband_decim(self, baseband_decim):
        self.baseband_decim = baseband_decim
        self.set_baseband_sample_rate(self.x_samp_rate / self.baseband_decim)

    def get_variable_constellation_rect_0(self):
        return self.variable_constellation_rect_0

    def set_variable_constellation_rect_0(self, variable_constellation_rect_0):
        self.variable_constellation_rect_0 = variable_constellation_rect_0

    def get_rrc_sample_rate(self):
        return self.rrc_sample_rate

    def set_rrc_sample_rate(self, rrc_sample_rate):
        self.rrc_sample_rate = rrc_sample_rate
        self.qtgui_freq_sink_x_1.set_frequency_range(0, self.rrc_sample_rate)
        self.root_raised_cosine_filter_0.set_taps(firdes.root_raised_cosine(1, self.rrc_sample_rate, self.rds_symbol_rate, 1, 100))

    def get_rds_decim(self):
        return self.rds_decim

    def set_rds_decim(self, rds_decim):
        self.rds_decim = rds_decim

    def get_fm_freq(self):
        return self.fm_freq

    def set_fm_freq(self, fm_freq):
        self.fm_freq = fm_freq
        self.qtgui_freq_sink_x_0.set_frequency_range(self.fm_freq, self.samp_rate/self.x_decimation)

    def get_excess_bw(self):
        return self.excess_bw

    def set_excess_bw(self, excess_bw):
        self.excess_bw = excess_bw
        self.digital_pfb_clock_sync_xxx_0.update_taps(firdes.root_raised_cosine(32, 32*7, 1.0, self.excess_bw, 11*7*32))

    def get_dgain(self):
        return self.dgain

    def set_dgain(self, dgain):
        self.dgain = dgain

    def get_baseband_sample_rate(self):
        return self.baseband_sample_rate

    def set_baseband_sample_rate(self, baseband_sample_rate):
        self.baseband_sample_rate = baseband_sample_rate
        self.fm_stereo_audio_decoder_0.set_baseband_rate(self.baseband_sample_rate)
        self.freq_xlating_fir_filter_xxx_1.set_taps(firdes.low_pass(2500.0,self.baseband_sample_rate,2.2e3,2e3,firdes.WIN_HAMMING))
        self.qtgui_freq_sink_x_0_0_0_1.set_frequency_range(0.0, self.baseband_sample_rate)
        self.qtgui_freq_sink_x_0_0_0_1_0.set_frequency_range(0.0, self.baseband_sample_rate / 5)
        self.qtgui_freq_sink_x_0_0_0_1_0_0.set_frequency_range(0.0, self.baseband_sample_rate / 5)
        self.qtgui_freq_sink_x_0_0_0_1_0_1.set_frequency_range(0.0, self.baseband_sample_rate)
        self.qtgui_time_sink_x_0.set_samp_rate(self.baseband_sample_rate)

    def get_audio_rate(self):
        return self.audio_rate

    def set_audio_rate(self, audio_rate):
        self.audio_rate = audio_rate
        self.fm_stereo_audio_decoder_0.set_audio_rate(self.audio_rate)



def main(top_block_cls=fm_rds_alternate, options=None):

    if StrictVersion("4.5.0") <= StrictVersion(Qt.qVersion()) < StrictVersion("5.0.0"):
        style = gr.prefs().get_string('qtgui', 'style', 'raster')
        Qt.QApplication.setGraphicsSystem(style)
    qapp = Qt.QApplication(sys.argv)

    tb = top_block_cls()
    tb.start()
    tb.show()

    def quitting():
        tb.stop()
        tb.wait()
    qapp.aboutToQuit.connect(quitting)
    qapp.exec_()


if __name__ == '__main__':
    main()
