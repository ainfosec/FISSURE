#!/usr/bin/env python2
# -*- coding: utf-8 -*-
##################################################
# GNU Radio Python Flow Graph
# Title: Fixed Threshold Usrp N2Xx
# GNU Radio version: 3.7.13.5
##################################################

from distutils.version import StrictVersion

if __name__ == '__main__':
    import ctypes
    import sys
    if sys.platform.startswith('linux'):
        try:
            x11 = ctypes.cdll.LoadLibrary('libX11.so')
            x11.XInitThreads()
        except:
            print "Warning: failed to XInitThreads()"

from PyQt5 import Qt
from PyQt5 import Qt, QtCore
from PyQt5.QtCore import QObject, pyqtSlot
from gnuradio import blocks
from gnuradio import eng_notation
from gnuradio import fft
from gnuradio import gr
from gnuradio import qtgui
from gnuradio import uhd
from gnuradio.eng_option import eng_option
from gnuradio.fft import window
from gnuradio.filter import firdes
from gnuradio.qtgui import Range, RangeWidget
from optparse import OptionParser
import ainfosec
import epy_block_0
import numpy as np
import random
import sip
import sys
import time
from gnuradio import qtgui


class fixed_threshold_usrp_n2xx(gr.top_block, Qt.QWidget):

    def __init__(self, antenna_default='J1', channel_default='A:0', gain_default='30', ip_address='192.168.10.2', rx_freq_default='2412', sample_rate_default='20e6', serial='False', threshold_default='0'):
        gr.top_block.__init__(self, "Fixed Threshold Usrp N2Xx")
        Qt.QWidget.__init__(self)
        self.setWindowTitle("Fixed Threshold Usrp N2Xx")
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

        self.settings = Qt.QSettings("GNU Radio", "fixed_threshold_usrp_n2xx")
        self.restoreGeometry(self.settings.value("geometry", type=QtCore.QByteArray))


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
        self._up_line_adj_win = RangeWidget(self._up_line_adj_range, self.set_up_line_adj, "up_line_adj", "counter_slider", int)
        self.top_grid_layout.addWidget(self._up_line_adj_win, 5, 0, 1, 4)
        for r in range(5, 6):
            self.top_grid_layout.setRowStretch(r, 1)
        for c in range(0, 4):
            self.top_grid_layout.setColumnStretch(c, 1)
        self._thresh_adj_range = Range(-120, 20, 1, float(threshold_default), 200)
        self._thresh_adj_win = RangeWidget(self._thresh_adj_range, self.set_thresh_adj, 'Thresh', "counter_slider", float)
        self.top_grid_layout.addWidget(self._thresh_adj_win, 6, 0, 1, 4)
        for r in range(6, 7):
            self.top_grid_layout.setRowStretch(r, 1)
        for c in range(0, 4):
            self.top_grid_layout.setColumnStretch(c, 1)
        self._samp_rate_options = (1e6, 2e6, 5e6, 10e6, 20e6, )
        self._samp_rate_labels = ('1 MS/s', '2 MS/s', '5 MS/s', '10 MS/s', '20 MS/s', )
        self._samp_rate_tool_bar = Qt.QToolBar(self)
        self._samp_rate_tool_bar.addWidget(Qt.QLabel('Sample Rate'+": "))
        self._samp_rate_combo_box = Qt.QComboBox()
        self._samp_rate_tool_bar.addWidget(self._samp_rate_combo_box)
        for label in self._samp_rate_labels: self._samp_rate_combo_box.addItem(label)
        self._samp_rate_callback = lambda i: Qt.QMetaObject.invokeMethod(self._samp_rate_combo_box, "setCurrentIndex", Qt.Q_ARG("int", self._samp_rate_options.index(i)))
        self._samp_rate_callback(self.samp_rate)
        self._samp_rate_combo_box.currentIndexChanged.connect(
        	lambda i: self.set_samp_rate(self._samp_rate_options[i]))
        self.top_grid_layout.addWidget(self._samp_rate_tool_bar, 0, 0, 1, 1)
        for r in range(0, 1):
            self.top_grid_layout.setRowStretch(r, 1)
        for c in range(0, 1):
            self.top_grid_layout.setColumnStretch(c, 1)
        self._rx_gain_range = Range(0, 35, 1, float(gain_default), 200)
        self._rx_gain_win = RangeWidget(self._rx_gain_range, self.set_rx_gain, '              Gain:', "counter_slider", float)
        self.top_grid_layout.addWidget(self._rx_gain_win, 2, 0, 1, 4)
        for r in range(2, 3):
            self.top_grid_layout.setRowStretch(r, 1)
        for c in range(0, 4):
            self.top_grid_layout.setColumnStretch(c, 1)
        self._rx_freq_range = Range(50, 6000, 0.1, float(rx_freq_default), 200)
        self._rx_freq_win = RangeWidget(self._rx_freq_range, self.set_rx_freq, 'Freq. (MHz):', "counter_slider", float)
        self.top_grid_layout.addWidget(self._rx_freq_win, 1, 0, 1, 4)
        for r in range(1, 2):
            self.top_grid_layout.setRowStretch(r, 1)
        for c in range(0, 4):
            self.top_grid_layout.setColumnStretch(c, 1)
        self._rx_antenna_options = ('J1', 'J2', )
        self._rx_antenna_labels = ('J1', 'J2', )
        self._rx_antenna_tool_bar = Qt.QToolBar(self)
        self._rx_antenna_tool_bar.addWidget(Qt.QLabel('        Antenna'+": "))
        self._rx_antenna_combo_box = Qt.QComboBox()
        self._rx_antenna_tool_bar.addWidget(self._rx_antenna_combo_box)
        for label in self._rx_antenna_labels: self._rx_antenna_combo_box.addItem(label)
        self._rx_antenna_callback = lambda i: Qt.QMetaObject.invokeMethod(self._rx_antenna_combo_box, "setCurrentIndex", Qt.Q_ARG("int", self._rx_antenna_options.index(i)))
        self._rx_antenna_callback(self.rx_antenna)
        self._rx_antenna_combo_box.currentIndexChanged.connect(
        	lambda i: self.set_rx_antenna(self._rx_antenna_options[i]))
        self.top_grid_layout.addWidget(self._rx_antenna_tool_bar, 0, 1, 1, 1)
        for r in range(0, 1):
            self.top_grid_layout.setRowStretch(r, 1)
        for c in range(1, 2):
            self.top_grid_layout.setColumnStretch(c, 1)
        self._low_line_adj_range = Range(1, 8191, 1, 1, 200)
        self._low_line_adj_win = RangeWidget(self._low_line_adj_range, self.set_low_line_adj, "low_line_adj", "counter_slider", int)
        self.top_grid_layout.addWidget(self._low_line_adj_win, 4, 0, 1, 4)
        for r in range(4, 5):
            self.top_grid_layout.setRowStretch(r, 1)
        for c in range(0, 4):
            self.top_grid_layout.setColumnStretch(c, 1)
        self.uhd_usrp_source_0 = uhd.usrp_source(
        	",".join(("addr=" + ip_address, "")),
        	uhd.stream_args(
        		cpu_format="fc32",
        		channels=range(1),
        	),
        )
        self.uhd_usrp_source_0.set_subdev_spec(channel_default, 0)
        self.uhd_usrp_source_0.set_samp_rate(samp_rate)
        self.uhd_usrp_source_0.set_center_freq(rx_freq*1e6, 0)
        self.uhd_usrp_source_0.set_gain(rx_gain, 0)
        self.uhd_usrp_source_0.set_antenna(rx_antenna, 0)
        self.uhd_usrp_source_0.set_auto_dc_offset(True, 0)
        self.uhd_usrp_source_0.set_auto_iq_balance(True, 0)
        self.qtgui_vector_sink_f_0 = qtgui.vector_sink_f(
            fft_size,
            0,
            1.0,
            "x-Axis",
            "y-Axis",
            "",
            4 # Number of inputs
        )
        self.qtgui_vector_sink_f_0.set_update_time(0.10)
        self.qtgui_vector_sink_f_0.set_y_axis(-140, 10)
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
        for i in xrange(4):
            if len(labels[i]) == 0:
                self.qtgui_vector_sink_f_0.set_line_label(i, "Data {0}".format(i))
            else:
                self.qtgui_vector_sink_f_0.set_line_label(i, labels[i])
            self.qtgui_vector_sink_f_0.set_line_width(i, widths[i])
            self.qtgui_vector_sink_f_0.set_line_color(i, colors[i])
            self.qtgui_vector_sink_f_0.set_line_alpha(i, alphas[i])

        self._qtgui_vector_sink_f_0_win = sip.wrapinstance(self.qtgui_vector_sink_f_0.pyqwidget(), Qt.QWidget)
        self.top_grid_layout.addWidget(self._qtgui_vector_sink_f_0_win, 7, 0, 8, 4)
        for r in range(7, 15):
            self.top_grid_layout.setRowStretch(r, 1)
        for c in range(0, 4):
            self.top_grid_layout.setColumnStretch(c, 1)
        self.fft_vxx_0 = fft.fft_vcc(fft_size, True, (window.blackmanharris(fft_size)), True, 1)
        self.epy_block_0 = epy_block_0.blk(vec_len=fft_size, sample_rate=samp_rate, rx_freq_mhz=rx_freq)
        self.blocks_vector_source_x_0_1 = blocks.vector_source_f(low_bound_vec_bottom_half+(vec_height,)+low_bound_vec_top_half, True, fft_size, [])
        self.blocks_vector_source_x_0_0 = blocks.vector_source_f(up_bound_vec_bottom_half+(vec_height,)+up_bound_vec_top_half, True, fft_size, [])
        self.blocks_vector_source_x_0 = blocks.vector_source_f((thresh_adj,)*full_band_size, True, fft_size, [])
        self.blocks_stream_to_vector_decimator_0 = blocks.stream_to_vector_decimator(
        	item_size=gr.sizeof_gr_complex,
        	sample_rate=samp_rate,
        	vec_rate=30,
        	vec_len=fft_size,
        )
        self.blocks_nlog10_ff_0 = blocks.nlog10_ff(20, fft_size, -72)
        self.blocks_max_xx_0 = blocks.max_ff(fft_size,fft_size)
        self.blocks_complex_to_mag_0 = blocks.complex_to_mag(fft_size)
        self.blocks_add_const_vxx_0 = blocks.add_const_vff((((below_zero*10),)*(low_line_adj)+(0,)*in_box_spec_len+((below_zero*10),)*(fft_size-up_line_adj)))
        self.ainfosec_msg_str_to_PUB_0 = ainfosec.msg_str_to_PUB('tcp://127.0.0.1:5060')



        ##################################################
        # Connections
        ##################################################
        self.msg_connect((self.epy_block_0, 'detected_signals'), (self.ainfosec_msg_str_to_PUB_0, 'Message'))
        self.connect((self.blocks_add_const_vxx_0, 0), (self.blocks_max_xx_0, 1))
        self.connect((self.blocks_complex_to_mag_0, 0), (self.blocks_nlog10_ff_0, 0))
        self.connect((self.blocks_max_xx_0, 0), (self.epy_block_0, 0))
        self.connect((self.blocks_nlog10_ff_0, 0), (self.blocks_add_const_vxx_0, 0))
        self.connect((self.blocks_nlog10_ff_0, 0), (self.qtgui_vector_sink_f_0, 0))
        self.connect((self.blocks_stream_to_vector_decimator_0, 0), (self.fft_vxx_0, 0))
        self.connect((self.blocks_vector_source_x_0, 0), (self.blocks_max_xx_0, 0))
        self.connect((self.blocks_vector_source_x_0, 0), (self.epy_block_0, 1))
        self.connect((self.blocks_vector_source_x_0, 0), (self.qtgui_vector_sink_f_0, 3))
        self.connect((self.blocks_vector_source_x_0_0, 0), (self.qtgui_vector_sink_f_0, 1))
        self.connect((self.blocks_vector_source_x_0_1, 0), (self.qtgui_vector_sink_f_0, 2))
        self.connect((self.fft_vxx_0, 0), (self.blocks_complex_to_mag_0, 0))
        self.connect((self.uhd_usrp_source_0, 0), (self.blocks_stream_to_vector_decimator_0, 0))

    def closeEvent(self, event):
        self.settings = Qt.QSettings("GNU Radio", "fixed_threshold_usrp_n2xx")
        self.settings.setValue("geometry", self.saveGeometry())
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
        self.set_up_bound_vec_top_half((self.fft_size-self.up_line_adj-1)*(self.below_zero,))
        self.set_up_bound_vec_bottom_half((self.up_line_adj)*(self.below_zero,))
        self.set_in_box_spec_len(int(np.abs(self.up_line_adj-self.low_line_adj)))
        self.blocks_add_const_vxx_0.set_k((((self.below_zero*10),)*(self.low_line_adj)+(0,)*self.in_box_spec_len+((self.below_zero*10),)*(self.fft_size-self.up_line_adj)))

    def get_low_line_adj(self):
        return self.low_line_adj

    def set_low_line_adj(self, low_line_adj):
        self.low_line_adj = low_line_adj
        self.set_low_bound_vec_top_half((self.fft_size-self.low_line_adj-1)*(self.below_zero,))
        self.set_low_bound_vec_bottom_half((self.low_line_adj)*(self.below_zero,))
        self.set_in_box_spec_len(int(np.abs(self.up_line_adj-self.low_line_adj)))
        self.blocks_add_const_vxx_0.set_k((((self.below_zero*10),)*(self.low_line_adj)+(0,)*self.in_box_spec_len+((self.below_zero*10),)*(self.fft_size-self.up_line_adj)))

    def get_fft_size(self):
        return self.fft_size

    def set_fft_size(self, fft_size):
        self.fft_size = fft_size
        self.set_up_bound_vec_top_half((self.fft_size-self.up_line_adj-1)*(self.below_zero,))
        self.set_low_bound_vec_top_half((self.fft_size-self.low_line_adj-1)*(self.below_zero,))
        self.blocks_add_const_vxx_0.set_k((((self.below_zero*10),)*(self.low_line_adj)+(0,)*self.in_box_spec_len+((self.below_zero*10),)*(self.fft_size-self.up_line_adj)))

    def get_below_zero(self):
        return self.below_zero

    def set_below_zero(self, below_zero):
        self.below_zero = below_zero
        self.set_up_bound_vec_top_half((self.fft_size-self.up_line_adj-1)*(self.below_zero,))
        self.set_up_bound_vec_bottom_half((self.up_line_adj)*(self.below_zero,))
        self.set_low_bound_vec_top_half((self.fft_size-self.low_line_adj-1)*(self.below_zero,))
        self.set_low_bound_vec_bottom_half((self.low_line_adj)*(self.below_zero,))
        self.blocks_add_const_vxx_0.set_k((((self.below_zero*10),)*(self.low_line_adj)+(0,)*self.in_box_spec_len+((self.below_zero*10),)*(self.fft_size-self.up_line_adj)))

    def get_vec_height(self):
        return self.vec_height

    def set_vec_height(self, vec_height):
        self.vec_height = vec_height
        self.blocks_vector_source_x_0_1.set_data(self.low_bound_vec_bottom_half+(self.vec_height,)+self.low_bound_vec_top_half, [])
        self.blocks_vector_source_x_0_0.set_data(self.up_bound_vec_bottom_half+(self.vec_height,)+self.up_bound_vec_top_half, [])

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

    def get_samp_rate(self):
        return self.samp_rate

    def set_samp_rate(self, samp_rate):
        self.samp_rate = samp_rate
        self._samp_rate_callback(self.samp_rate)
        self.uhd_usrp_source_0.set_samp_rate(self.samp_rate)
        self.epy_block_0.sample_rate = self.samp_rate
        self.blocks_stream_to_vector_decimator_0.set_sample_rate(self.samp_rate)

    def get_rx_gain(self):
        return self.rx_gain

    def set_rx_gain(self, rx_gain):
        self.rx_gain = rx_gain
        self.uhd_usrp_source_0.set_gain(self.rx_gain, 0)


    def get_rx_freq(self):
        return self.rx_freq

    def set_rx_freq(self, rx_freq):
        self.rx_freq = rx_freq
        self.uhd_usrp_source_0.set_center_freq(self.rx_freq*1e6, 0)
        self.epy_block_0.rx_freq_mhz = self.rx_freq

    def get_rx_antenna(self):
        return self.rx_antenna

    def set_rx_antenna(self, rx_antenna):
        self.rx_antenna = rx_antenna
        self._rx_antenna_callback(self.rx_antenna)
        self.uhd_usrp_source_0.set_antenna(self.rx_antenna, 0)

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
        self.blocks_add_const_vxx_0.set_k((((self.below_zero*10),)*(self.low_line_adj)+(0,)*self.in_box_spec_len+((self.below_zero*10),)*(self.fft_size-self.up_line_adj)))

    def get_full_band_size(self):
        return self.full_band_size

    def set_full_band_size(self, full_band_size):
        self.full_band_size = full_band_size
        self.blocks_vector_source_x_0.set_data((self.thresh_adj,)*self.full_band_size, [])


def argument_parser():
    parser = OptionParser(usage="%prog: [options]", option_class=eng_option)
    parser.add_option(
        "", "--antenna-default", dest="antenna_default", type="string", default='J1',
        help="Set J1 [default=%default]")
    parser.add_option(
        "", "--channel-default", dest="channel_default", type="string", default='A:0',
        help="Set A:0 [default=%default]")
    parser.add_option(
        "", "--gain-default", dest="gain_default", type="string", default='30',
        help="Set 30 [default=%default]")
    parser.add_option(
        "", "--ip-address", dest="ip_address", type="string", default='192.168.10.2',
        help="Set 192.168.10.2 [default=%default]")
    parser.add_option(
        "", "--rx-freq-default", dest="rx_freq_default", type="string", default='2412',
        help="Set 2412 [default=%default]")
    parser.add_option(
        "", "--sample-rate-default", dest="sample_rate_default", type="string", default='20e6',
        help="Set 20e6 [default=%default]")
    parser.add_option(
        "", "--serial", dest="serial", type="string", default='False',
        help="Set False [default=%default]")
    parser.add_option(
        "", "--threshold-default", dest="threshold_default", type="string", default='0',
        help="Set 0 [default=%default]")
    return parser


def main(top_block_cls=fixed_threshold_usrp_n2xx, options=None):
    if options is None:
        options, _ = argument_parser().parse_args()

    qapp = Qt.QApplication(sys.argv)

    tb = top_block_cls(antenna_default=options.antenna_default, channel_default=options.channel_default, gain_default=options.gain_default, ip_address=options.ip_address, rx_freq_default=options.rx_freq_default, sample_rate_default=options.sample_rate_default, serial=options.serial, threshold_default=options.threshold_default)
    tb.start()
    tb.show()

    def quitting():
        tb.stop()
        tb.wait()
    qapp.aboutToQuit.connect(quitting)
    qapp.exec_()


if __name__ == '__main__':
    main()
