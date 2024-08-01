#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#
# SPDX-License-Identifier: GPL-3.0
#
# GNU Radio Python Flow Graph
# Title: Instantaneous Frequency B20Xmini
# GNU Radio version: 3.8.5.0

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
from PyQt5.QtCore import QObject, pyqtSlot
from gnuradio import qtgui
from gnuradio.filter import firdes
import sip
from gnuradio import blocks
from gnuradio import gr
import sys
import signal
from argparse import ArgumentParser
from gnuradio.eng_arg import eng_float, intx
from gnuradio import eng_notation
from gnuradio import uhd
import time
from gnuradio.qtgui import Range, RangeWidget
import dect2

from gnuradio import qtgui

class instantaneous_frequency_b20xmini(gr.top_block, Qt.QWidget):

    def __init__(self, rx_usrp_channel="A:A", serial="False"):
        gr.top_block.__init__(self, "Instantaneous Frequency B20Xmini")
        Qt.QWidget.__init__(self)
        self.setWindowTitle("Instantaneous Frequency B20Xmini")
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

        self.settings = Qt.QSettings("GNU Radio", "instantaneous_frequency_b20xmini")

        try:
            if StrictVersion(Qt.qVersion()) < StrictVersion("5.0.0"):
                self.restoreGeometry(self.settings.value("geometry").toByteArray())
            else:
                self.restoreGeometry(self.settings.value("geometry"))
        except:
            pass

        ##################################################
        # Parameters
        ##################################################
        self.rx_usrp_channel = rx_usrp_channel
        self.serial = serial

        ##################################################
        # Variables
        ##################################################
        self.sample_rate = sample_rate = 1e6
        self.rx_usrp_gain = rx_usrp_gain = 60
        self.rx_usrp_antenna = rx_usrp_antenna = "TX/RX"
        self.rx_frequency = rx_frequency = 2412
        self.decimation = decimation = 1

        ##################################################
        # Blocks
        ##################################################
        # Create the options list
        self._sample_rate_options = [1000000.0, 5000000.0, 10000000.0, 20000000.0]
        # Create the labels list
        self._sample_rate_labels = ['1 MS/s', '5 MS/s', '10 MS/s', '20 MS/s']
        # Create the combo box
        self._sample_rate_tool_bar = Qt.QToolBar(self)
        self._sample_rate_tool_bar.addWidget(Qt.QLabel('Sample Rate' + ": "))
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
        self._rx_usrp_gain_range = Range(0, 90, 1, 60, 200)
        self._rx_usrp_gain_win = RangeWidget(self._rx_usrp_gain_range, self.set_rx_usrp_gain, '              Gain:', "counter_slider", float)
        self.top_grid_layout.addWidget(self._rx_usrp_gain_win, 1, 0, 1, 4)
        for r in range(1, 2):
            self.top_grid_layout.setRowStretch(r, 1)
        for c in range(0, 4):
            self.top_grid_layout.setColumnStretch(c, 1)
        # Create the options list
        self._rx_usrp_antenna_options = ['TX/RX', 'RX2']
        # Create the labels list
        self._rx_usrp_antenna_labels = ['TX/RX', 'RX2']
        # Create the combo box
        self._rx_usrp_antenna_tool_bar = Qt.QToolBar(self)
        self._rx_usrp_antenna_tool_bar.addWidget(Qt.QLabel('        Antenna' + ": "))
        self._rx_usrp_antenna_combo_box = Qt.QComboBox()
        self._rx_usrp_antenna_tool_bar.addWidget(self._rx_usrp_antenna_combo_box)
        for _label in self._rx_usrp_antenna_labels: self._rx_usrp_antenna_combo_box.addItem(_label)
        self._rx_usrp_antenna_callback = lambda i: Qt.QMetaObject.invokeMethod(self._rx_usrp_antenna_combo_box, "setCurrentIndex", Qt.Q_ARG("int", self._rx_usrp_antenna_options.index(i)))
        self._rx_usrp_antenna_callback(self.rx_usrp_antenna)
        self._rx_usrp_antenna_combo_box.currentIndexChanged.connect(
            lambda i: self.set_rx_usrp_antenna(self._rx_usrp_antenna_options[i]))
        # Create the radio buttons
        self.top_grid_layout.addWidget(self._rx_usrp_antenna_tool_bar, 0, 1, 1, 1)
        for r in range(0, 1):
            self.top_grid_layout.setRowStretch(r, 1)
        for c in range(1, 2):
            self.top_grid_layout.setColumnStretch(c, 1)
        self._rx_frequency_range = Range(50, 6000, .1, 2412, 200)
        self._rx_frequency_win = RangeWidget(self._rx_frequency_range, self.set_rx_frequency, ' Freq. (MHz):', "counter_slider", float)
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
        self._decimation_tool_bar.addWidget(Qt.QLabel('  Keep 1 in N' + ": "))
        self._decimation_combo_box = Qt.QComboBox()
        self._decimation_tool_bar.addWidget(self._decimation_combo_box)
        for _label in self._decimation_labels: self._decimation_combo_box.addItem(_label)
        self._decimation_callback = lambda i: Qt.QMetaObject.invokeMethod(self._decimation_combo_box, "setCurrentIndex", Qt.Q_ARG("int", self._decimation_options.index(i)))
        self._decimation_callback(self.decimation)
        self._decimation_combo_box.currentIndexChanged.connect(
            lambda i: self.set_decimation(self._decimation_options[i]))
        # Create the radio buttons
        self.top_grid_layout.addWidget(self._decimation_tool_bar, 0, 2, 1, 1)
        for r in range(0, 1):
            self.top_grid_layout.setRowStretch(r, 1)
        for c in range(2, 3):
            self.top_grid_layout.setColumnStretch(c, 1)
        self.uhd_usrp_source_0 = uhd.usrp_source(
            ",".join((serial, "")),
            uhd.stream_args(
                cpu_format="fc32",
                args='',
                channels=list(range(0,1)),
            ),
        )
        self.uhd_usrp_source_0.set_subdev_spec(rx_usrp_channel, 0)
        self.uhd_usrp_source_0.set_center_freq(rx_frequency*1e6, 0)
        self.uhd_usrp_source_0.set_gain(rx_usrp_gain, 0)
        self.uhd_usrp_source_0.set_antenna(rx_usrp_antenna, 0)
        self.uhd_usrp_source_0.set_samp_rate(sample_rate)
        self.uhd_usrp_source_0.set_time_unknown_pps(uhd.time_spec())
        self.qtgui_time_sink_x_0 = qtgui.time_sink_f(
            100000, #size
            sample_rate/decimation, #samp_rate
            "", #name
            1 #number of inputs
        )
        self.qtgui_time_sink_x_0.set_update_time(0.1)
        self.qtgui_time_sink_x_0.set_y_axis(-5, 5)

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
        self.top_grid_layout.addWidget(self._qtgui_time_sink_x_0_win, 3, 0, 20, 4)
        for r in range(3, 23):
            self.top_grid_layout.setRowStretch(r, 1)
        for c in range(0, 4):
            self.top_grid_layout.setColumnStretch(c, 1)
        self.dect2_phase_diff_1 = dect2.phase_diff()
        self.blocks_keep_one_in_n_0 = blocks.keep_one_in_n(gr.sizeof_gr_complex*1, decimation)


        ##################################################
        # Connections
        ##################################################
        self.connect((self.blocks_keep_one_in_n_0, 0), (self.dect2_phase_diff_1, 0))
        self.connect((self.dect2_phase_diff_1, 0), (self.qtgui_time_sink_x_0, 0))
        self.connect((self.uhd_usrp_source_0, 0), (self.blocks_keep_one_in_n_0, 0))


    def closeEvent(self, event):
        self.settings = Qt.QSettings("GNU Radio", "instantaneous_frequency_b20xmini")
        self.settings.setValue("geometry", self.saveGeometry())
        event.accept()

    def get_rx_usrp_channel(self):
        return self.rx_usrp_channel

    def set_rx_usrp_channel(self, rx_usrp_channel):
        self.rx_usrp_channel = rx_usrp_channel

    def get_serial(self):
        return self.serial

    def set_serial(self, serial):
        self.serial = serial

    def get_sample_rate(self):
        return self.sample_rate

    def set_sample_rate(self, sample_rate):
        self.sample_rate = sample_rate
        self._sample_rate_callback(self.sample_rate)
        self.qtgui_time_sink_x_0.set_samp_rate(self.sample_rate/self.decimation)
        self.uhd_usrp_source_0.set_samp_rate(self.sample_rate)

    def get_rx_usrp_gain(self):
        return self.rx_usrp_gain

    def set_rx_usrp_gain(self, rx_usrp_gain):
        self.rx_usrp_gain = rx_usrp_gain
        self.uhd_usrp_source_0.set_gain(self.rx_usrp_gain, 0)

    def get_rx_usrp_antenna(self):
        return self.rx_usrp_antenna

    def set_rx_usrp_antenna(self, rx_usrp_antenna):
        self.rx_usrp_antenna = rx_usrp_antenna
        self._rx_usrp_antenna_callback(self.rx_usrp_antenna)
        self.uhd_usrp_source_0.set_antenna(self.rx_usrp_antenna, 0)

    def get_rx_frequency(self):
        return self.rx_frequency

    def set_rx_frequency(self, rx_frequency):
        self.rx_frequency = rx_frequency
        self.uhd_usrp_source_0.set_center_freq(self.rx_frequency*1e6, 0)

    def get_decimation(self):
        return self.decimation

    def set_decimation(self, decimation):
        self.decimation = decimation
        self._decimation_callback(self.decimation)
        self.blocks_keep_one_in_n_0.set_n(self.decimation)
        self.qtgui_time_sink_x_0.set_samp_rate(self.sample_rate/self.decimation)




def argument_parser():
    parser = ArgumentParser()
    parser.add_argument(
        "--rx-usrp-channel", dest="rx_usrp_channel", type=str, default="A:A",
        help="Set A:A [default=%(default)r]")
    parser.add_argument(
        "--serial", dest="serial", type=str, default="False",
        help="Set False [default=%(default)r]")
    return parser


def main(top_block_cls=instantaneous_frequency_b20xmini, options=None):
    if options is None:
        options = argument_parser().parse_args()

    if StrictVersion("4.5.0") <= StrictVersion(Qt.qVersion()) < StrictVersion("5.0.0"):
        style = gr.prefs().get_string('qtgui', 'style', 'raster')
        Qt.QApplication.setGraphicsSystem(style)
    qapp = Qt.QApplication(sys.argv)

    tb = top_block_cls(rx_usrp_channel=options.rx_usrp_channel, serial=options.serial)

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
