#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#
# SPDX-License-Identifier: GPL-3.0
#
# GNU Radio Python Flow Graph
# Title: Antenna Test Tx
# GNU Radio version: 3.10.7.0

from packaging.version import Version as StrictVersion
from PyQt5 import Qt
from gnuradio import qtgui
from PyQt5.QtCore import QObject, pyqtSlot
from gnuradio import analog
from gnuradio import gr
from gnuradio.filter import firdes
from gnuradio.fft import window
import sys
import signal
from PyQt5 import Qt
from argparse import ArgumentParser
from gnuradio.eng_arg import eng_float, intx
from gnuradio import eng_notation
from gnuradio import uhd
import time
from gnuradio.qtgui import Range, RangeWidget
from PyQt5 import QtCore



class antenna_test_tx(gr.top_block, Qt.QWidget):

    def __init__(self):
        gr.top_block.__init__(self, "Antenna Test Tx", catch_exceptions=True)
        Qt.QWidget.__init__(self)
        self.setWindowTitle("Antenna Test Tx")
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

        self.settings = Qt.QSettings("GNU Radio", "antenna_test_tx")

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
        self.tx_freq = tx_freq = 900000000
        self.samp_rate = samp_rate = 1e6
        self.gain = gain = 70

        ##################################################
        # Blocks
        ##################################################

        # Create the options list
        self._tx_freq_options = [900000000, 2400000000, 5800000000]
        # Create the labels list
        self._tx_freq_labels = ['900', '2400', '5800']
        # Create the combo box
        self._tx_freq_tool_bar = Qt.QToolBar(self)
        self._tx_freq_tool_bar.addWidget(Qt.QLabel("'tx_freq'" + ": "))
        self._tx_freq_combo_box = Qt.QComboBox()
        self._tx_freq_tool_bar.addWidget(self._tx_freq_combo_box)
        for _label in self._tx_freq_labels: self._tx_freq_combo_box.addItem(_label)
        self._tx_freq_callback = lambda i: Qt.QMetaObject.invokeMethod(self._tx_freq_combo_box, "setCurrentIndex", Qt.Q_ARG("int", self._tx_freq_options.index(i)))
        self._tx_freq_callback(self.tx_freq)
        self._tx_freq_combo_box.currentIndexChanged.connect(
            lambda i: self.set_tx_freq(self._tx_freq_options[i]))
        # Create the radio buttons
        self.top_layout.addWidget(self._tx_freq_tool_bar)
        self.uhd_usrp_sink_1_0 = uhd.usrp_sink(
            ",".join(("", "")),
            uhd.stream_args(
                cpu_format="fc32",
                args='',
                channels=list(range(0,1)),
            ),
            '',
        )
        self.uhd_usrp_sink_1_0.set_samp_rate(1e6)
        self.uhd_usrp_sink_1_0.set_time_unknown_pps(uhd.time_spec(0))

        self.uhd_usrp_sink_1_0.set_center_freq(tx_freq, 0)
        self.uhd_usrp_sink_1_0.set_antenna('TX/RX', 0)
        self.uhd_usrp_sink_1_0.set_gain(40, 0)
        self._gain_range = Range(0, 70, 1, 70, 200)
        self._gain_win = RangeWidget(self._gain_range, self.set_gain, "'gain'", "counter_slider", float, QtCore.Qt.Horizontal)
        self.top_layout.addWidget(self._gain_win)
        self.analog_sig_source_x_0 = analog.sig_source_c(samp_rate, analog.GR_COS_WAVE, 10000, 1, 0, 0)


        ##################################################
        # Connections
        ##################################################
        self.connect((self.analog_sig_source_x_0, 0), (self.uhd_usrp_sink_1_0, 0))


    def closeEvent(self, event):
        self.settings = Qt.QSettings("GNU Radio", "antenna_test_tx")
        self.settings.setValue("geometry", self.saveGeometry())
        self.stop()
        self.wait()

        event.accept()

    def get_tx_freq(self):
        return self.tx_freq

    def set_tx_freq(self, tx_freq):
        self.tx_freq = tx_freq
        self._tx_freq_callback(self.tx_freq)
        self.uhd_usrp_sink_1_0.set_center_freq(self.tx_freq, 0)

    def get_samp_rate(self):
        return self.samp_rate

    def set_samp_rate(self, samp_rate):
        self.samp_rate = samp_rate
        self.analog_sig_source_x_0.set_sampling_freq(self.samp_rate)

    def get_gain(self):
        return self.gain

    def set_gain(self, gain):
        self.gain = gain




def main(top_block_cls=antenna_test_tx, options=None):

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
