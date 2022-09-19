#!/usr/bin/env python2
# -*- coding: utf-8 -*-
##################################################
# GNU Radio Python Flow Graph
# Title: Waterfall Usrp2
# Generated: Sun Sep 18 22:16:19 2022
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
from gnuradio import eng_notation
from gnuradio import gr
from gnuradio import qtgui
from gnuradio import uhd
from gnuradio.eng_option import eng_option
from gnuradio.filter import firdes
from gnuradio.qtgui import Range, RangeWidget
from optparse import OptionParser
import sip
import sys
import time
from gnuradio import qtgui


class waterfall_usrp2(gr.top_block, Qt.QWidget):

    def __init__(self):
        gr.top_block.__init__(self, "Waterfall Usrp2")
        Qt.QWidget.__init__(self)
        self.setWindowTitle("Waterfall Usrp2")
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

        self.settings = Qt.QSettings("GNU Radio", "waterfall_usrp2")

        if StrictVersion(Qt.qVersion()) < StrictVersion("5.0.0"):
            self.restoreGeometry(self.settings.value("geometry").toByteArray())
        else:
            self.restoreGeometry(self.settings.value("geometry", type=QtCore.QByteArray))

        ##################################################
        # Variables
        ##################################################
        self.sample_rate = sample_rate = 1e6
        self.rx_usrp_gain = rx_usrp_gain = 30
        self.rx_usrp_channel = rx_usrp_channel = "A:0"
        self.rx_usrp_antenna = rx_usrp_antenna = "TX/RX"
        self.rx_frequency = rx_frequency = 2412

        ##################################################
        # Blocks
        ##################################################
        self._sample_rate_options = [1e6, 5e6, 10e6, 20e6]
        self._sample_rate_labels = ["1 MS/s", "5 MS/s", "10 MS/s", "20 MS/s"]
        self._sample_rate_tool_bar = Qt.QToolBar(self)
        self._sample_rate_tool_bar.addWidget(Qt.QLabel('Sample Rate'+": "))
        self._sample_rate_combo_box = Qt.QComboBox()
        self._sample_rate_tool_bar.addWidget(self._sample_rate_combo_box)
        for label in self._sample_rate_labels: self._sample_rate_combo_box.addItem(label)
        self._sample_rate_callback = lambda i: Qt.QMetaObject.invokeMethod(self._sample_rate_combo_box, "setCurrentIndex", Qt.Q_ARG("int", self._sample_rate_options.index(i)))
        self._sample_rate_callback(self.sample_rate)
        self._sample_rate_combo_box.currentIndexChanged.connect(
        	lambda i: self.set_sample_rate(self._sample_rate_options[i]))
        self.top_grid_layout.addWidget(self._sample_rate_tool_bar, 0, 0, 1, 1)
        [self.top_grid_layout.setRowStretch(r,1) for r in range(0,1)]
        [self.top_grid_layout.setColumnStretch(c,1) for c in range(0,1)]
        self._rx_usrp_gain_range = Range(0, 34, 1, 30, 200)
        self._rx_usrp_gain_win = RangeWidget(self._rx_usrp_gain_range, self.set_rx_usrp_gain, '              Gain:', "counter_slider", float)
        self.top_grid_layout.addWidget(self._rx_usrp_gain_win, 1, 0, 1, 4)
        [self.top_grid_layout.setRowStretch(r,1) for r in range(1,2)]
        [self.top_grid_layout.setColumnStretch(c,1) for c in range(0,4)]
        self._rx_usrp_antenna_options = ["TX/RX", "RX2"]
        self._rx_usrp_antenna_labels = ["TX/RX", "RX2"]
        self._rx_usrp_antenna_tool_bar = Qt.QToolBar(self)
        self._rx_usrp_antenna_tool_bar.addWidget(Qt.QLabel('        Antenna'+": "))
        self._rx_usrp_antenna_combo_box = Qt.QComboBox()
        self._rx_usrp_antenna_tool_bar.addWidget(self._rx_usrp_antenna_combo_box)
        for label in self._rx_usrp_antenna_labels: self._rx_usrp_antenna_combo_box.addItem(label)
        self._rx_usrp_antenna_callback = lambda i: Qt.QMetaObject.invokeMethod(self._rx_usrp_antenna_combo_box, "setCurrentIndex", Qt.Q_ARG("int", self._rx_usrp_antenna_options.index(i)))
        self._rx_usrp_antenna_callback(self.rx_usrp_antenna)
        self._rx_usrp_antenna_combo_box.currentIndexChanged.connect(
        	lambda i: self.set_rx_usrp_antenna(self._rx_usrp_antenna_options[i]))
        self.top_grid_layout.addWidget(self._rx_usrp_antenna_tool_bar, 0, 1, 1, 1)
        [self.top_grid_layout.setRowStretch(r,1) for r in range(0,1)]
        [self.top_grid_layout.setColumnStretch(c,1) for c in range(1,2)]
        self._rx_frequency_range = Range(50, 6000, .1, 2412, 200)
        self._rx_frequency_win = RangeWidget(self._rx_frequency_range, self.set_rx_frequency, ' Freq. (MHz):', "counter_slider", float)
        self.top_grid_layout.addWidget(self._rx_frequency_win, 2, 0, 1, 4)
        [self.top_grid_layout.setRowStretch(r,1) for r in range(2,3)]
        [self.top_grid_layout.setColumnStretch(c,1) for c in range(0,4)]
        self.uhd_usrp_source_0_0 = uhd.usrp_source(
        	",".join(('', "")),
        	uhd.stream_args(
        		cpu_format="fc32",
        		channels=range(1),
        	),
        )
        self.uhd_usrp_source_0_0.set_subdev_spec(rx_usrp_channel, 0)
        self.uhd_usrp_source_0_0.set_samp_rate(sample_rate)
        self.uhd_usrp_source_0_0.set_center_freq(rx_frequency*1e6, 0)
        self.uhd_usrp_source_0_0.set_gain(rx_usrp_gain, 0)
        self.uhd_usrp_source_0_0.set_antenna(rx_usrp_antenna, 0)
        self.qtgui_waterfall_sink_x_0 = qtgui.waterfall_sink_c(
        	1024, #size
        	firdes.WIN_BLACKMAN_hARRIS, #wintype
        	0, #fc
        	sample_rate, #bw
        	"", #name
                1 #number of inputs
        )
        self.qtgui_waterfall_sink_x_0.set_update_time(0.10)
        self.qtgui_waterfall_sink_x_0.enable_grid(False)
        self.qtgui_waterfall_sink_x_0.enable_axis_labels(True)

        if not True:
          self.qtgui_waterfall_sink_x_0.disable_legend()

        if "complex" == "float" or "complex" == "msg_float":
          self.qtgui_waterfall_sink_x_0.set_plot_pos_half(not True)

        labels = ['', '', '', '', '',
                  '', '', '', '', '']
        colors = [0, 0, 0, 0, 0,
                  0, 0, 0, 0, 0]
        alphas = [1.0, 1.0, 1.0, 1.0, 1.0,
                  1.0, 1.0, 1.0, 1.0, 1.0]
        for i in xrange(1):
            if len(labels[i]) == 0:
                self.qtgui_waterfall_sink_x_0.set_line_label(i, "Data {0}".format(i))
            else:
                self.qtgui_waterfall_sink_x_0.set_line_label(i, labels[i])
            self.qtgui_waterfall_sink_x_0.set_color_map(i, colors[i])
            self.qtgui_waterfall_sink_x_0.set_line_alpha(i, alphas[i])

        self.qtgui_waterfall_sink_x_0.set_intensity_range(-140, 10)

        self._qtgui_waterfall_sink_x_0_win = sip.wrapinstance(self.qtgui_waterfall_sink_x_0.pyqwidget(), Qt.QWidget)
        self.top_grid_layout.addWidget(self._qtgui_waterfall_sink_x_0_win, 3, 0, 6, 4)
        [self.top_grid_layout.setRowStretch(r,1) for r in range(3,9)]
        [self.top_grid_layout.setColumnStretch(c,1) for c in range(0,4)]

        ##################################################
        # Connections
        ##################################################
        self.connect((self.uhd_usrp_source_0_0, 0), (self.qtgui_waterfall_sink_x_0, 0))

    def closeEvent(self, event):
        self.settings = Qt.QSettings("GNU Radio", "waterfall_usrp2")
        self.settings.setValue("geometry", self.saveGeometry())
        event.accept()

    def get_sample_rate(self):
        return self.sample_rate

    def set_sample_rate(self, sample_rate):
        self.sample_rate = sample_rate
        self._sample_rate_callback(self.sample_rate)
        self.uhd_usrp_source_0_0.set_samp_rate(self.sample_rate)
        self.qtgui_waterfall_sink_x_0.set_frequency_range(0, self.sample_rate)

    def get_rx_usrp_gain(self):
        return self.rx_usrp_gain

    def set_rx_usrp_gain(self, rx_usrp_gain):
        self.rx_usrp_gain = rx_usrp_gain
        self.uhd_usrp_source_0_0.set_gain(self.rx_usrp_gain, 0)


    def get_rx_usrp_channel(self):
        return self.rx_usrp_channel

    def set_rx_usrp_channel(self, rx_usrp_channel):
        self.rx_usrp_channel = rx_usrp_channel

    def get_rx_usrp_antenna(self):
        return self.rx_usrp_antenna

    def set_rx_usrp_antenna(self, rx_usrp_antenna):
        self.rx_usrp_antenna = rx_usrp_antenna
        self._rx_usrp_antenna_callback(self.rx_usrp_antenna)
        self.uhd_usrp_source_0_0.set_antenna(self.rx_usrp_antenna, 0)

    def get_rx_frequency(self):
        return self.rx_frequency

    def set_rx_frequency(self, rx_frequency):
        self.rx_frequency = rx_frequency
        self.uhd_usrp_source_0_0.set_center_freq(self.rx_frequency*1e6, 0)


def main(top_block_cls=waterfall_usrp2, options=None):

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
