#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#
# SPDX-License-Identifier: GPL-3.0
#
# GNU Radio Python Flow Graph
# Title: Time Sink Rtl2832U
# GNU Radio version: 3.10.4.0

from packaging.version import Version as StrictVersion

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
from PyQt5.QtCore import QObject, pyqtSlot
from gnuradio import qtgui
from gnuradio.filter import firdes
import sip
from gnuradio import blocks
from gnuradio import gr
from gnuradio.fft import window
import sys
import signal
from argparse import ArgumentParser
from gnuradio.eng_arg import eng_float, intx
from gnuradio import eng_notation
from gnuradio import soapy
from gnuradio.qtgui import Range, GrRangeWidget
from PyQt5 import QtCore



from gnuradio import qtgui

class time_sink_rtl2832u(gr.top_block, Qt.QWidget):

    def __init__(self):
        gr.top_block.__init__(self, "Time Sink Rtl2832U", catch_exceptions=True)
        Qt.QWidget.__init__(self)
        self.setWindowTitle("Time Sink Rtl2832U")
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

        self.settings = Qt.QSettings("GNU Radio", "time_sink_rtl2832u")

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
        self.sample_rate = sample_rate = 2.048e6
        self.rx_rtl_gain = rx_rtl_gain = 40
        self.rx_frequency = rx_frequency = 102.5
        self.decimation = decimation = 1

        ##################################################
        # Blocks
        ##################################################
        # Create the options list
        self._sample_rate_options = [250000.0, 1024000.0, 1536000.0, 1792000.0, 1920000.0, 2048000.0, 2160000.0, 2560000.0, 2880000.0, 3200000.0]
        # Create the labels list
        self._sample_rate_labels = ['0.25 MS/s', '1.024 MS/s', '1.536 MS/s', '1.792 MS/s', '1.92 MS/s', '2.048 MS/s', '2.16 MS/s', '2.56 MS/s', '2.88 MS/s', '3.2 MS/s']
        # Create the combo box
        self._sample_rate_tool_bar = Qt.QToolBar(self)
        self._sample_rate_tool_bar.addWidget(Qt.QLabel("Sample Rate" + ": "))
        self._sample_rate_combo_box = Qt.QComboBox()
        self._sample_rate_tool_bar.addWidget(self._sample_rate_combo_box)
        for _label in self._sample_rate_labels: self._sample_rate_combo_box.addItem(_label)
        self._sample_rate_callback = lambda i: Qt.QMetaObject.invokeMethod(self._sample_rate_combo_box, "setCurrentIndex", Qt.Q_ARG("int", self._sample_rate_options.index(i)))
        self._sample_rate_callback(self.sample_rate)
        self._sample_rate_combo_box.currentIndexChanged.connect(
            lambda i: self.set_sample_rate(self._sample_rate_options[i]))
        # Create the radio buttons
        self.top_grid_layout.addWidget(self._sample_rate_tool_bar, 0, 0, 1, 1)
        for r in range(0, 1):
            self.top_grid_layout.setRowStretch(r, 1)
        for c in range(0, 1):
            self.top_grid_layout.setColumnStretch(c, 1)
        self._rx_rtl_gain_range = Range(0, 47, 1, 40, 200)
        self._rx_rtl_gain_win = GrRangeWidget(self._rx_rtl_gain_range, self.set_rx_rtl_gain, "              Gain:", "counter_slider", float, QtCore.Qt.Horizontal, "value")

        self.top_grid_layout.addWidget(self._rx_rtl_gain_win, 1, 0, 1, 4)
        for r in range(1, 2):
            self.top_grid_layout.setRowStretch(r, 1)
        for c in range(0, 4):
            self.top_grid_layout.setColumnStretch(c, 1)
        self._rx_frequency_range = Range(64, 1700, .1, 102.5, 200)
        self._rx_frequency_win = GrRangeWidget(self._rx_frequency_range, self.set_rx_frequency, " Freq. (MHz):", "counter_slider", float, QtCore.Qt.Horizontal, "value")

        self.top_grid_layout.addWidget(self._rx_frequency_win, 2, 0, 1, 4)
        for r in range(2, 3):
            self.top_grid_layout.setRowStretch(r, 1)
        for c in range(0, 4):
            self.top_grid_layout.setColumnStretch(c, 1)
        # Create the options list
        self._decimation_options = [1, 10, 100, 1000]
        # Create the labels list
        self._decimation_labels = ['1', '10', '100', '1000']
        # Create the combo box
        self._decimation_tool_bar = Qt.QToolBar(self)
        self._decimation_tool_bar.addWidget(Qt.QLabel("  Keep 1 in N" + ": "))
        self._decimation_combo_box = Qt.QComboBox()
        self._decimation_tool_bar.addWidget(self._decimation_combo_box)
        for _label in self._decimation_labels: self._decimation_combo_box.addItem(_label)
        self._decimation_callback = lambda i: Qt.QMetaObject.invokeMethod(self._decimation_combo_box, "setCurrentIndex", Qt.Q_ARG("int", self._decimation_options.index(i)))
        self._decimation_callback(self.decimation)
        self._decimation_combo_box.currentIndexChanged.connect(
            lambda i: self.set_decimation(self._decimation_options[i]))
        # Create the radio buttons
        self.top_grid_layout.addWidget(self._decimation_tool_bar, 0, 1, 1, 1)
        for r in range(0, 1):
            self.top_grid_layout.setRowStretch(r, 1)
        for c in range(1, 2):
            self.top_grid_layout.setColumnStretch(c, 1)
        self.soapy_rtlsdr_source_0 = None
        dev = 'driver=rtlsdr'
        stream_args = ''
        tune_args = ['']
        settings = ['']

        self.soapy_rtlsdr_source_0 = soapy.source(dev, "fc32", 1, '',
                                  stream_args, tune_args, settings)
        self.soapy_rtlsdr_source_0.set_sample_rate(0, sample_rate)
        self.soapy_rtlsdr_source_0.set_gain_mode(0, False)
        self.soapy_rtlsdr_source_0.set_frequency(0, (rx_frequency*1e6))
        self.soapy_rtlsdr_source_0.set_frequency_correction(0, 0)
        self.soapy_rtlsdr_source_0.set_gain(0, 'TUNER', rx_rtl_gain)
        self.qtgui_time_sink_x_0 = qtgui.time_sink_c(
            100000, #size
            sample_rate/decimation, #samp_rate
            "", #name
            1, #number of inputs
            None # parent
        )
        self.qtgui_time_sink_x_0.set_update_time(0.1)
        self.qtgui_time_sink_x_0.set_y_axis(-1, 1)

        self.qtgui_time_sink_x_0.set_y_label('Amplitude', "")

        self.qtgui_time_sink_x_0.enable_tags(True)
        self.qtgui_time_sink_x_0.set_trigger_mode(qtgui.TRIG_MODE_FREE, qtgui.TRIG_SLOPE_POS, 0.005, 0, 0, "")
        self.qtgui_time_sink_x_0.enable_autoscale(False)
        self.qtgui_time_sink_x_0.enable_grid(True)
        self.qtgui_time_sink_x_0.enable_axis_labels(True)
        self.qtgui_time_sink_x_0.enable_control_panel(False)
        self.qtgui_time_sink_x_0.enable_stem_plot(False)


        labels = ['', '', '', '', '',
            '', '', '', '', '']
        widths = [1, 1, 1, 1, 1,
            1, 1, 1, 1, 1]
        colors = ['blue', 'red', 'green', 'black', 'cyan',
            'magenta', 'yellow', 'dark red', 'dark green', 'dark blue']
        alphas = [1.0, 1.0, 1.0, 1.0, 1.0,
            1.0, 1.0, 1.0, 1.0, 1.0]
        styles = [1, 1, 1, 1, 1,
            1, 1, 1, 1, 1]
        markers = [-1, -1, -1, -1, -1,
            -1, -1, -1, -1, -1]


        for i in range(2):
            if len(labels[i]) == 0:
                if (i % 2 == 0):
                    self.qtgui_time_sink_x_0.set_line_label(i, "Re{{Data {0}}}".format(i/2))
                else:
                    self.qtgui_time_sink_x_0.set_line_label(i, "Im{{Data {0}}}".format(i/2))
            else:
                self.qtgui_time_sink_x_0.set_line_label(i, labels[i])
            self.qtgui_time_sink_x_0.set_line_width(i, widths[i])
            self.qtgui_time_sink_x_0.set_line_color(i, colors[i])
            self.qtgui_time_sink_x_0.set_line_style(i, styles[i])
            self.qtgui_time_sink_x_0.set_line_marker(i, markers[i])
            self.qtgui_time_sink_x_0.set_line_alpha(i, alphas[i])

        self._qtgui_time_sink_x_0_win = sip.wrapinstance(self.qtgui_time_sink_x_0.qwidget(), Qt.QWidget)
        self.top_grid_layout.addWidget(self._qtgui_time_sink_x_0_win, 3, 0, 10, 4)
        for r in range(3, 13):
            self.top_grid_layout.setRowStretch(r, 1)
        for c in range(0, 4):
            self.top_grid_layout.setColumnStretch(c, 1)
        self.qtgui_freq_sink_x_0 = qtgui.freq_sink_c(
            2048, #size
            window.WIN_BLACKMAN_hARRIS, #wintype
            0, #fc
            sample_rate, #bw
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
        self.top_grid_layout.addWidget(self._qtgui_freq_sink_x_0_win, 14, 0, 10, 4)
        for r in range(14, 24):
            self.top_grid_layout.setRowStretch(r, 1)
        for c in range(0, 4):
            self.top_grid_layout.setColumnStretch(c, 1)
        self.blocks_keep_one_in_n_0 = blocks.keep_one_in_n(gr.sizeof_gr_complex*1, decimation)


        ##################################################
        # Connections
        ##################################################
        self.connect((self.blocks_keep_one_in_n_0, 0), (self.qtgui_freq_sink_x_0, 0))
        self.connect((self.blocks_keep_one_in_n_0, 0), (self.qtgui_time_sink_x_0, 0))
        self.connect((self.soapy_rtlsdr_source_0, 0), (self.blocks_keep_one_in_n_0, 0))


    def closeEvent(self, event):
        self.settings = Qt.QSettings("GNU Radio", "time_sink_rtl2832u")
        self.settings.setValue("geometry", self.saveGeometry())
        self.stop()
        self.wait()

        event.accept()

    def get_sample_rate(self):
        return self.sample_rate

    def set_sample_rate(self, sample_rate):
        self.sample_rate = sample_rate
        self.qtgui_freq_sink_x_0.set_frequency_range(0, self.sample_rate)
        self.qtgui_time_sink_x_0.set_samp_rate(self.sample_rate/self.decimation)
        self.soapy_rtlsdr_source_0.set_sample_rate(0, self.sample_rate)
        self._sample_rate_callback(self.sample_rate)

    def get_rx_rtl_gain(self):
        return self.rx_rtl_gain

    def set_rx_rtl_gain(self, rx_rtl_gain):
        self.rx_rtl_gain = rx_rtl_gain
        self.soapy_rtlsdr_source_0.set_gain(0, 'TUNER', self.rx_rtl_gain)

    def get_rx_frequency(self):
        return self.rx_frequency

    def set_rx_frequency(self, rx_frequency):
        self.rx_frequency = rx_frequency
        self.soapy_rtlsdr_source_0.set_frequency(0, (self.rx_frequency*1e6))

    def get_decimation(self):
        return self.decimation

    def set_decimation(self, decimation):
        self.decimation = decimation
        self._decimation_callback(self.decimation)
        self.blocks_keep_one_in_n_0.set_n(self.decimation)
        self.qtgui_time_sink_x_0.set_samp_rate(self.sample_rate/self.decimation)




def main(top_block_cls=time_sink_rtl2832u, options=None):

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
