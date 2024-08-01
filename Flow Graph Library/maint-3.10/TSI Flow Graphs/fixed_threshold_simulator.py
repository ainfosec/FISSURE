#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#
# SPDX-License-Identifier: GPL-3.0
#
# GNU Radio Python Flow Graph
# Title: Not titled yet
# Author: user
# GNU Radio version: 3.10.7.0

from packaging.version import Version as StrictVersion
from PyQt5 import Qt
from gnuradio import qtgui
from PyQt5.QtCore import QObject, pyqtSlot
from gnuradio import ainfosec
from gnuradio import analog
from gnuradio import blocks
from gnuradio import gr
from gnuradio.filter import firdes
from gnuradio.fft import window
import sys
import signal
from PyQt5 import Qt
from argparse import ArgumentParser
from gnuradio.eng_arg import eng_float, intx
from gnuradio import eng_notation
from gnuradio.fft import logpwrfft
from gnuradio.qtgui import Range, RangeWidget
from PyQt5 import QtCore
import fixed_threshold_simulator_epy_block_0 as epy_block_0  # embedded python block
import numpy as np
import random
import sip
import time



class fixed_threshold_simulator(gr.top_block, Qt.QWidget):

    def __init__(self, antenna_default="N/A", channel_default="N/A", gain_default='2', ip_address='', rx_freq_default='2412', sample_rate_default='20e6', serial='False', threshold_default='0'):
        gr.top_block.__init__(self, "Not titled yet", catch_exceptions=True)
        Qt.QWidget.__init__(self)
        self.setWindowTitle("Not titled yet")
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

        self.settings = Qt.QSettings("GNU Radio", "fixed_threshold_simulator")

        try:
            if StrictVersion(Qt.qVersion()) < StrictVersion("5.0.0"):
                self.restoreGeometry(self.settings.value("geometry").toByteArray())
            else:
                self.restoreGeometry(self.settings.value("geometry"))
        except BaseException as exc:
            print(f"Qt GUI: Could not restore geometry: {str(exc)}", file=sys.stderr)

        ##################################################
        # Parameters
        ##################################################
        self.antenna_default = antenna_default
        self.channel_default = channel_default
        self.gain_default = gain_default
        self.ip_address = ip_address
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
        self.thresh_adj = thresh_adj = float(threshold_default)
        self.signal_source_freq = signal_source_freq = 0
        self.samp_rate = samp_rate = float(sample_rate_default)
        self.rx_gain = rx_gain = float(gain_default)
        self.rx_freq = rx_freq = float(rx_freq_default)
        self.rx_antenna = rx_antenna = antenna_default
        self.low_bound_vec_top_half = low_bound_vec_top_half = (fft_size-low_line_adj-1)*(below_zero,)
        self.low_bound_vec_bottom_half = low_bound_vec_bottom_half = (low_line_adj)*(below_zero,)
        self.in_box_spec_len = in_box_spec_len = int(np.abs(up_line_adj-low_line_adj))
        self.full_band_size = full_band_size = 8192

        ##################################################
        # Blocks
        ##################################################

        self._up_line_adj_range = Range(1, 8191, 1, 8191, 200)
        self._up_line_adj_win = RangeWidget(self._up_line_adj_range, self.set_up_line_adj, "'up_line_adj'", "counter_slider", int, QtCore.Qt.Horizontal)
        self.top_grid_layout.addWidget(self._up_line_adj_win, 5, 0, 1, 4)
        for r in range(5, 6):
            self.top_grid_layout.setRowStretch(r, 1)
        for c in range(0, 4):
            self.top_grid_layout.setColumnStretch(c, 1)
        self._thresh_adj_range = Range(-120, 20, 1, float(threshold_default), 200)
        self._thresh_adj_win = RangeWidget(self._thresh_adj_range, self.set_thresh_adj, "Thresh", "counter_slider", float, QtCore.Qt.Horizontal)
        self.top_grid_layout.addWidget(self._thresh_adj_win, 6, 0, 1, 4)
        for r in range(6, 7):
            self.top_grid_layout.setRowStretch(r, 1)
        for c in range(0, 4):
            self.top_grid_layout.setColumnStretch(c, 1)
        self._signal_source_freq_range = Range(-1, 1, .01, 0, 200)
        self._signal_source_freq_win = RangeWidget(self._signal_source_freq_range, self.set_signal_source_freq, "Signal Source Freq.:", "counter_slider", float, QtCore.Qt.Horizontal)
        self.top_grid_layout.addWidget(self._signal_source_freq_win, 7, 0, 1, 4)
        for r in range(7, 8):
            self.top_grid_layout.setRowStretch(r, 1)
        for c in range(0, 4):
            self.top_grid_layout.setColumnStretch(c, 1)
        # Create the options list
        self._samp_rate_options = [1000000.0, 2000000.0, 5000000.0, 10000000.0, 20000000.0]
        # Create the labels list
        self._samp_rate_labels = ['1 MS/s', '2 MS/s', '5 MS/s', '10 MS/s', '20 MS/s']
        # Create the combo box
        self._samp_rate_tool_bar = Qt.QToolBar(self)
        self._samp_rate_tool_bar.addWidget(Qt.QLabel("Sample Rate" + ": "))
        self._samp_rate_combo_box = Qt.QComboBox()
        self._samp_rate_tool_bar.addWidget(self._samp_rate_combo_box)
        for _label in self._samp_rate_labels: self._samp_rate_combo_box.addItem(_label)
        self._samp_rate_callback = lambda i: Qt.QMetaObject.invokeMethod(self._samp_rate_combo_box, "setCurrentIndex", Qt.Q_ARG("int", self._samp_rate_options.index(i)))
        self._samp_rate_callback(self.samp_rate)
        self._samp_rate_combo_box.currentIndexChanged.connect(
            lambda i: self.set_samp_rate(self._samp_rate_options[i]))
        # Create the radio buttons
        self.top_grid_layout.addWidget(self._samp_rate_tool_bar, 0, 0, 1, 1)
        for r in range(0, 1):
            self.top_grid_layout.setRowStretch(r, 1)
        for c in range(0, 1):
            self.top_grid_layout.setColumnStretch(c, 1)
        self._rx_gain_range = Range(0, 10, 0.001, float(gain_default), 200)
        self._rx_gain_win = RangeWidget(self._rx_gain_range, self.set_rx_gain, "              Gain:", "counter_slider", float, QtCore.Qt.Horizontal)
        self.top_grid_layout.addWidget(self._rx_gain_win, 2, 0, 1, 4)
        for r in range(2, 3):
            self.top_grid_layout.setRowStretch(r, 1)
        for c in range(0, 4):
            self.top_grid_layout.setColumnStretch(c, 1)
        self._rx_freq_range = Range(50, 6000, .1, float(rx_freq_default), 200)
        self._rx_freq_win = RangeWidget(self._rx_freq_range, self.set_rx_freq, " Freq. (MHz):", "counter_slider", float, QtCore.Qt.Horizontal)
        self.top_grid_layout.addWidget(self._rx_freq_win, 1, 0, 1, 4)
        for r in range(1, 2):
            self.top_grid_layout.setRowStretch(r, 1)
        for c in range(0, 4):
            self.top_grid_layout.setColumnStretch(c, 1)
        self._low_line_adj_range = Range(1, 8191, 1, 1, 200)
        self._low_line_adj_win = RangeWidget(self._low_line_adj_range, self.set_low_line_adj, "'low_line_adj'", "counter_slider", int, QtCore.Qt.Horizontal)
        self.top_grid_layout.addWidget(self._low_line_adj_win, 4, 0, 1, 4)
        for r in range(4, 5):
            self.top_grid_layout.setRowStretch(r, 1)
        for c in range(0, 4):
            self.top_grid_layout.setColumnStretch(c, 1)
        # Create the options list
        self._rx_antenna_options = ['N/A']
        # Create the labels list
        self._rx_antenna_labels = ['N/A']
        # Create the combo box
        self._rx_antenna_tool_bar = Qt.QToolBar(self)
        self._rx_antenna_tool_bar.addWidget(Qt.QLabel("        Antenna" + ": "))
        self._rx_antenna_combo_box = Qt.QComboBox()
        self._rx_antenna_tool_bar.addWidget(self._rx_antenna_combo_box)
        for _label in self._rx_antenna_labels: self._rx_antenna_combo_box.addItem(_label)
        self._rx_antenna_callback = lambda i: Qt.QMetaObject.invokeMethod(self._rx_antenna_combo_box, "setCurrentIndex", Qt.Q_ARG("int", self._rx_antenna_options.index(i)))
        self._rx_antenna_callback(self.rx_antenna)
        self._rx_antenna_combo_box.currentIndexChanged.connect(
            lambda i: self.set_rx_antenna(self._rx_antenna_options[i]))
        # Create the radio buttons
        self.top_grid_layout.addWidget(self._rx_antenna_tool_bar, 0, 1, 1, 1)
        for r in range(0, 1):
            self.top_grid_layout.setRowStretch(r, 1)
        for c in range(1, 2):
            self.top_grid_layout.setColumnStretch(c, 1)
        self.qtgui_vector_sink_f_0 = qtgui.vector_sink_f(
            fft_size,
            0,
            1.0,
            "x-Axis",
            "y-Axis",
            "",
            4, # Number of inputs
            None # parent
        )
        self.qtgui_vector_sink_f_0.set_update_time(0.10)
        self.qtgui_vector_sink_f_0.set_y_axis((-140), 10)
        self.qtgui_vector_sink_f_0.enable_autoscale(False)
        self.qtgui_vector_sink_f_0.enable_grid(False)
        self.qtgui_vector_sink_f_0.set_x_axis_units("")
        self.qtgui_vector_sink_f_0.set_y_axis_units("")
        self.qtgui_vector_sink_f_0.set_ref_level(0)


        labels = ['', '', '', '', '',
            '', '', '', '', '']
        widths = [1, 1, 1, 1, 1,
            1, 1, 1, 1, 1]
        colors = ["blue", "red", "green", "black", "cyan",
            "magenta", "yellow", "dark red", "dark green", "dark blue"]
        alphas = [1.0, 1.0, 1.0, 1.0, 1.0,
            1.0, 1.0, 1.0, 1.0, 1.0]

        for i in range(4):
            if len(labels[i]) == 0:
                self.qtgui_vector_sink_f_0.set_line_label(i, "Data {0}".format(i))
            else:
                self.qtgui_vector_sink_f_0.set_line_label(i, labels[i])
            self.qtgui_vector_sink_f_0.set_line_width(i, widths[i])
            self.qtgui_vector_sink_f_0.set_line_color(i, colors[i])
            self.qtgui_vector_sink_f_0.set_line_alpha(i, alphas[i])

        self._qtgui_vector_sink_f_0_win = sip.wrapinstance(self.qtgui_vector_sink_f_0.qwidget(), Qt.QWidget)
        self.top_layout.addWidget(self._qtgui_vector_sink_f_0_win)
        self.logpwrfft_x_0 = logpwrfft.logpwrfft_c(
            sample_rate=samp_rate,
            fft_size=fft_size,
            ref_scale=2,
            frame_rate=30,
            avg_alpha=1.0,
            average=False,
            shift=True)
        self.epy_block_0 = epy_block_0.blk(vec_len=fft_size, sample_rate=samp_rate, rx_freq_mhz=rx_freq)
        self.blocks_vector_source_x_0_1 = blocks.vector_source_f(low_bound_vec_bottom_half+(vec_height,)+low_bound_vec_top_half, True, fft_size, [])
        self.blocks_vector_source_x_0_0 = blocks.vector_source_f(up_bound_vec_bottom_half+(vec_height,)+up_bound_vec_top_half, True, fft_size, [])
        self.blocks_vector_source_x_0 = blocks.vector_source_f((thresh_adj,)*full_band_size, True, fft_size, [])
        self.blocks_throttle2_0 = blocks.throttle( gr.sizeof_gr_complex*1, samp_rate, True, 0 if "auto" == "auto" else max( int(float(0.1) * samp_rate) if "auto" == "time" else int(0.1), 1) )
        self.blocks_max_xx_0 = blocks.max_ff(fft_size, fft_size)
        self.blocks_add_xx_0 = blocks.add_vcc(1)
        self.blocks_add_const_vxx_0 = blocks.add_const_vff(((below_zero*10),)*(low_line_adj)+(0,)*in_box_spec_len+((below_zero*10),)*(fft_size-up_line_adj))
        self.analog_sig_source_x_0 = analog.sig_source_c(samp_rate, analog.GR_COS_WAVE, ((samp_rate/2)*signal_source_freq), (10**rx_gain/100000), 0, 0)
        self.analog_noise_source_x_0 = analog.noise_source_c(analog.GR_GAUSSIAN, .001, 0)
        self.ainfosec_msg_str_to_PUB_0 = ainfosec.msg_str_to_PUB("tcp://127.0.0.1:5060")


        ##################################################
        # Connections
        ##################################################
        self.msg_connect((self.epy_block_0, 'detected_signals'), (self.ainfosec_msg_str_to_PUB_0, 'Message'))
        self.connect((self.analog_noise_source_x_0, 0), (self.blocks_add_xx_0, 0))
        self.connect((self.analog_sig_source_x_0, 0), (self.blocks_add_xx_0, 1))
        self.connect((self.blocks_add_const_vxx_0, 0), (self.blocks_max_xx_0, 1))
        self.connect((self.blocks_add_xx_0, 0), (self.blocks_throttle2_0, 0))
        self.connect((self.blocks_max_xx_0, 0), (self.epy_block_0, 0))
        self.connect((self.blocks_throttle2_0, 0), (self.logpwrfft_x_0, 0))
        self.connect((self.blocks_vector_source_x_0, 0), (self.blocks_max_xx_0, 0))
        self.connect((self.blocks_vector_source_x_0, 0), (self.epy_block_0, 1))
        self.connect((self.blocks_vector_source_x_0, 0), (self.qtgui_vector_sink_f_0, 3))
        self.connect((self.blocks_vector_source_x_0_0, 0), (self.qtgui_vector_sink_f_0, 1))
        self.connect((self.blocks_vector_source_x_0_1, 0), (self.qtgui_vector_sink_f_0, 2))
        self.connect((self.logpwrfft_x_0, 0), (self.blocks_add_const_vxx_0, 0))
        self.connect((self.logpwrfft_x_0, 0), (self.qtgui_vector_sink_f_0, 0))


    def closeEvent(self, event):
        self.settings = Qt.QSettings("GNU Radio", "fixed_threshold_simulator")
        self.settings.setValue("geometry", self.saveGeometry())
        self.stop()
        self.wait()

        event.accept()

    def get_antenna_default(self):
        return self.antenna_default

    def set_antenna_default(self, antenna_default):
        self.antenna_default = antenna_default
        self.set_rx_antenna(self.antenna_default)

    def get_channel_default(self):
        return self.channel_default

    def set_channel_default(self, channel_default):
        self.channel_default = channel_default

    def get_gain_default(self):
        return self.gain_default

    def set_gain_default(self, gain_default):
        self.gain_default = gain_default
        self.set_rx_gain(float(self.gain_default))

    def get_ip_address(self):
        return self.ip_address

    def set_ip_address(self, ip_address):
        self.ip_address = ip_address

    def get_rx_freq_default(self):
        return self.rx_freq_default

    def set_rx_freq_default(self, rx_freq_default):
        self.rx_freq_default = rx_freq_default
        self.set_rx_freq(float(self.rx_freq_default))

    def get_sample_rate_default(self):
        return self.sample_rate_default

    def set_sample_rate_default(self, sample_rate_default):
        self.sample_rate_default = sample_rate_default
        self.set_samp_rate(float(self.sample_rate_default))

    def get_serial(self):
        return self.serial

    def set_serial(self, serial):
        self.serial = serial

    def get_threshold_default(self):
        return self.threshold_default

    def set_threshold_default(self, threshold_default):
        self.threshold_default = threshold_default
        self.set_thresh_adj(float(self.threshold_default))

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
        self.blocks_vector_source_x_0_0.set_data(self.up_bound_vec_bottom_half+(self.vec_height,)+self.up_bound_vec_top_half, [])
        self.blocks_vector_source_x_0_1.set_data(self.low_bound_vec_bottom_half+(self.vec_height,)+self.low_bound_vec_top_half, [])

    def get_up_bound_vec_top_half(self):
        return self.up_bound_vec_top_half

    def set_up_bound_vec_top_half(self, up_bound_vec_top_half):
        self.up_bound_vec_top_half = up_bound_vec_top_half
        self.blocks_vector_source_x_0_0.set_data(self.up_bound_vec_bottom_half+(self.vec_height,)+self.up_bound_vec_top_half, [])

    def get_up_bound_vec_bottom_half(self):
        return self.up_bound_vec_bottom_half

    def set_up_bound_vec_bottom_half(self, up_bound_vec_bottom_half):
        self.up_bound_vec_bottom_half = up_bound_vec_bottom_half
        self.blocks_vector_source_x_0_0.set_data(self.up_bound_vec_bottom_half+(self.vec_height,)+self.up_bound_vec_top_half, [])

    def get_thresh_adj(self):
        return self.thresh_adj

    def set_thresh_adj(self, thresh_adj):
        self.thresh_adj = thresh_adj
        self.blocks_vector_source_x_0.set_data((self.thresh_adj,)*self.full_band_size, [])

    def get_signal_source_freq(self):
        return self.signal_source_freq

    def set_signal_source_freq(self, signal_source_freq):
        self.signal_source_freq = signal_source_freq
        self.analog_sig_source_x_0.set_frequency(((self.samp_rate/2)*self.signal_source_freq))

    def get_samp_rate(self):
        return self.samp_rate

    def set_samp_rate(self, samp_rate):
        self.samp_rate = samp_rate
        self._samp_rate_callback(self.samp_rate)
        self.analog_sig_source_x_0.set_sampling_freq(self.samp_rate)
        self.analog_sig_source_x_0.set_frequency(((self.samp_rate/2)*self.signal_source_freq))
        self.blocks_throttle2_0.set_sample_rate(self.samp_rate)
        self.epy_block_0.sample_rate = self.samp_rate
        self.logpwrfft_x_0.set_sample_rate(self.samp_rate)

    def get_rx_gain(self):
        return self.rx_gain

    def set_rx_gain(self, rx_gain):
        self.rx_gain = rx_gain
        self.analog_sig_source_x_0.set_amplitude((10**self.rx_gain/100000))

    def get_rx_freq(self):
        return self.rx_freq

    def set_rx_freq(self, rx_freq):
        self.rx_freq = rx_freq
        self.epy_block_0.rx_freq_mhz = self.rx_freq

    def get_rx_antenna(self):
        return self.rx_antenna

    def set_rx_antenna(self, rx_antenna):
        self.rx_antenna = rx_antenna
        self._rx_antenna_callback(self.rx_antenna)

    def get_low_bound_vec_top_half(self):
        return self.low_bound_vec_top_half

    def set_low_bound_vec_top_half(self, low_bound_vec_top_half):
        self.low_bound_vec_top_half = low_bound_vec_top_half
        self.blocks_vector_source_x_0_1.set_data(self.low_bound_vec_bottom_half+(self.vec_height,)+self.low_bound_vec_top_half, [])

    def get_low_bound_vec_bottom_half(self):
        return self.low_bound_vec_bottom_half

    def set_low_bound_vec_bottom_half(self, low_bound_vec_bottom_half):
        self.low_bound_vec_bottom_half = low_bound_vec_bottom_half
        self.blocks_vector_source_x_0_1.set_data(self.low_bound_vec_bottom_half+(self.vec_height,)+self.low_bound_vec_top_half, [])

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
        "--antenna-default", dest="antenna_default", type=str, default="N/A",
        help="Set N/A [default=%(default)r]")
    parser.add_argument(
        "--channel-default", dest="channel_default", type=str, default="N/A",
        help="Set N/A [default=%(default)r]")
    parser.add_argument(
        "--gain-default", dest="gain_default", type=str, default='2',
        help="Set 2 [default=%(default)r]")
    parser.add_argument(
        "--ip-address", dest="ip_address", type=str, default='',
        help="Set ip_address [default=%(default)r]")
    parser.add_argument(
        "--rx-freq-default", dest="rx_freq_default", type=str, default='2412',
        help="Set 2412 [default=%(default)r]")
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


def main(top_block_cls=fixed_threshold_simulator, options=None):
    if options is None:
        options = argument_parser().parse_args()

    if StrictVersion("4.5.0") <= StrictVersion(Qt.qVersion()) < StrictVersion("5.0.0"):
        style = gr.prefs().get_string('qtgui', 'style', 'raster')
        Qt.QApplication.setGraphicsSystem(style)
    qapp = Qt.QApplication(sys.argv)

    tb = top_block_cls(antenna_default=options.antenna_default, channel_default=options.channel_default, gain_default=options.gain_default, ip_address=options.ip_address, rx_freq_default=options.rx_freq_default, sample_rate_default=options.sample_rate_default, serial=options.serial, threshold_default=options.threshold_default)

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
