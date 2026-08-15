#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#
# SPDX-License-Identifier: GPL-3.0
#
# GNU Radio Python Flow Graph
# Title: Transmit
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
import numpy as np

from gnuradio import qtgui

class transmit(gr.top_block, Qt.QWidget):

    def __init__(self):
        gr.top_block.__init__(self, "Transmit")
        Qt.QWidget.__init__(self)
        self.setWindowTitle("Transmit")
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

        self.settings = Qt.QSettings("GNU Radio", "transmit")

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
        self.tperiod = tperiod = 100e-3
        self.ton = ton = 10e-3
        self.samp_rate = samp_rate = 1e6
        self.f_offset = f_offset = 150e3
        self.bw = bw = 200e3
        self.Nperiod = Nperiod = int(samp_rate*tperiod)
        self.Nchirp = Nchirp = int(samp_rate*ton)
        self.tx_vec = tx_vec = (np.concatenate((np.exp(1j*2*np.pi*np.cumsum(((-bw/2)+(bw/ton)*(np.arange(Nchirp)/samp_rate)))/samp_rate),np.zeros(Nperiod-Nchirp)))*np.exp(1j*2*np.pi*f_offset*np.arange(Nperiod)/samp_rate)).astype(np.complex64)
        self.tx_gain = tx_gain = 80
        self.tx_freq = tx_freq = 433e6
        self.serial = serial = "False"
        self.notes = notes = "Transmits an on message for a Monoprice Z-Wave Plus RGB Smart Bulb."
        self.amp = amp = 0.2

        ##################################################
        # Blocks
        ##################################################
        self.uhd_usrp_sink_1_0 = uhd.usrp_sink(
            ",".join((serial, "")),
            uhd.stream_args(
                cpu_format="fc32",
                args='',
                channels=list(range(0,1)),
            ),
            '',
        )
        self.uhd_usrp_sink_1_0.set_center_freq(tx_freq, 0)
        self.uhd_usrp_sink_1_0.set_gain(tx_gain, 0)
        self.uhd_usrp_sink_1_0.set_antenna('TX/RX', 0)
        self.uhd_usrp_sink_1_0.set_samp_rate(1e6)
        self.uhd_usrp_sink_1_0.set_time_unknown_pps(uhd.time_spec())
        self.qtgui_waterfall_sink_x_0 = qtgui.waterfall_sink_c(
            1024, #size
            firdes.WIN_BLACKMAN_hARRIS, #wintype
            0, #fc
            samp_rate, #bw
            "", #name
            1 #number of inputs
        )
        self.qtgui_waterfall_sink_x_0.set_update_time(0.10)
        self.qtgui_waterfall_sink_x_0.enable_grid(False)
        self.qtgui_waterfall_sink_x_0.enable_axis_labels(True)



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
        self.top_layout.addWidget(self._qtgui_waterfall_sink_x_0_win)
        self.qtgui_time_sink_x_0_0_0_1 = qtgui.time_sink_c(
            100000, #size
            1, #samp_rate
            "", #name
            1 #number of inputs
        )
        self.qtgui_time_sink_x_0_0_0_1.set_update_time(0.10)
        self.qtgui_time_sink_x_0_0_0_1.set_y_axis(-100, 100)

        self.qtgui_time_sink_x_0_0_0_1.set_y_label('Amplitude', "")

        self.qtgui_time_sink_x_0_0_0_1.enable_tags(True)
        self.qtgui_time_sink_x_0_0_0_1.set_trigger_mode(qtgui.TRIG_MODE_FREE, qtgui.TRIG_SLOPE_POS, 0.0, 0, 0, "")
        self.qtgui_time_sink_x_0_0_0_1.enable_autoscale(True)
        self.qtgui_time_sink_x_0_0_0_1.enable_grid(True)
        self.qtgui_time_sink_x_0_0_0_1.enable_axis_labels(True)
        self.qtgui_time_sink_x_0_0_0_1.enable_control_panel(False)
        self.qtgui_time_sink_x_0_0_0_1.enable_stem_plot(False)


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
                    self.qtgui_time_sink_x_0_0_0_1.set_line_label(i, "Re{{Data {0}}}".format(i/2))
                else:
                    self.qtgui_time_sink_x_0_0_0_1.set_line_label(i, "Im{{Data {0}}}".format(i/2))
            else:
                self.qtgui_time_sink_x_0_0_0_1.set_line_label(i, labels[i])
            self.qtgui_time_sink_x_0_0_0_1.set_line_width(i, widths[i])
            self.qtgui_time_sink_x_0_0_0_1.set_line_color(i, colors[i])
            self.qtgui_time_sink_x_0_0_0_1.set_line_style(i, styles[i])
            self.qtgui_time_sink_x_0_0_0_1.set_line_marker(i, markers[i])
            self.qtgui_time_sink_x_0_0_0_1.set_line_alpha(i, alphas[i])

        self._qtgui_time_sink_x_0_0_0_1_win = sip.wrapinstance(self.qtgui_time_sink_x_0_0_0_1.pyqwidget(), Qt.QWidget)
        self.top_layout.addWidget(self._qtgui_time_sink_x_0_0_0_1_win)
        self.blocks_vector_source_x_0 = blocks.vector_source_c(tx_vec, True, 1, [])
        self.blocks_throttle_0 = blocks.throttle(gr.sizeof_gr_complex*1, samp_rate,True)
        self.blocks_multiply_const_vxx_2 = blocks.multiply_const_cc(amp)


        ##################################################
        # Connections
        ##################################################
        self.connect((self.blocks_multiply_const_vxx_2, 0), (self.blocks_throttle_0, 0))
        self.connect((self.blocks_multiply_const_vxx_2, 0), (self.uhd_usrp_sink_1_0, 0))
        self.connect((self.blocks_throttle_0, 0), (self.qtgui_time_sink_x_0_0_0_1, 0))
        self.connect((self.blocks_throttle_0, 0), (self.qtgui_waterfall_sink_x_0, 0))
        self.connect((self.blocks_vector_source_x_0, 0), (self.blocks_multiply_const_vxx_2, 0))


    def closeEvent(self, event):
        self.settings = Qt.QSettings("GNU Radio", "transmit")
        self.settings.setValue("geometry", self.saveGeometry())
        event.accept()

    def get_tperiod(self):
        return self.tperiod

    def set_tperiod(self, tperiod):
        self.tperiod = tperiod
        self.set_Nperiod(int(self.samp_rate*self.tperiod))

    def get_ton(self):
        return self.ton

    def set_ton(self, ton):
        self.ton = ton
        self.set_Nchirp(int(self.samp_rate*self.ton))
        self.set_tx_vec((np.concatenate((np.exp(1j*2*np.pi*np.cumsum(((-self.bw/2)+(self.bw/self.ton)*(np.arange(self.Nchirp)/self.samp_rate)))/self.samp_rate),np.zeros(self.Nperiod-self.Nchirp)))*np.exp(1j*2*np.pi*self.f_offset*np.arange(self.Nperiod)/self.samp_rate)).astype(np.complex64))

    def get_samp_rate(self):
        return self.samp_rate

    def set_samp_rate(self, samp_rate):
        self.samp_rate = samp_rate
        self.set_Nchirp(int(self.samp_rate*self.ton))
        self.set_Nperiod(int(self.samp_rate*self.tperiod))
        self.set_tx_vec((np.concatenate((np.exp(1j*2*np.pi*np.cumsum(((-self.bw/2)+(self.bw/self.ton)*(np.arange(self.Nchirp)/self.samp_rate)))/self.samp_rate),np.zeros(self.Nperiod-self.Nchirp)))*np.exp(1j*2*np.pi*self.f_offset*np.arange(self.Nperiod)/self.samp_rate)).astype(np.complex64))
        self.blocks_throttle_0.set_sample_rate(self.samp_rate)
        self.qtgui_waterfall_sink_x_0.set_frequency_range(0, self.samp_rate)

    def get_f_offset(self):
        return self.f_offset

    def set_f_offset(self, f_offset):
        self.f_offset = f_offset
        self.set_tx_vec((np.concatenate((np.exp(1j*2*np.pi*np.cumsum(((-self.bw/2)+(self.bw/self.ton)*(np.arange(self.Nchirp)/self.samp_rate)))/self.samp_rate),np.zeros(self.Nperiod-self.Nchirp)))*np.exp(1j*2*np.pi*self.f_offset*np.arange(self.Nperiod)/self.samp_rate)).astype(np.complex64))

    def get_bw(self):
        return self.bw

    def set_bw(self, bw):
        self.bw = bw
        self.set_tx_vec((np.concatenate((np.exp(1j*2*np.pi*np.cumsum(((-self.bw/2)+(self.bw/self.ton)*(np.arange(self.Nchirp)/self.samp_rate)))/self.samp_rate),np.zeros(self.Nperiod-self.Nchirp)))*np.exp(1j*2*np.pi*self.f_offset*np.arange(self.Nperiod)/self.samp_rate)).astype(np.complex64))

    def get_Nperiod(self):
        return self.Nperiod

    def set_Nperiod(self, Nperiod):
        self.Nperiod = Nperiod
        self.set_tx_vec((np.concatenate((np.exp(1j*2*np.pi*np.cumsum(((-self.bw/2)+(self.bw/self.ton)*(np.arange(self.Nchirp)/self.samp_rate)))/self.samp_rate),np.zeros(self.Nperiod-self.Nchirp)))*np.exp(1j*2*np.pi*self.f_offset*np.arange(self.Nperiod)/self.samp_rate)).astype(np.complex64))

    def get_Nchirp(self):
        return self.Nchirp

    def set_Nchirp(self, Nchirp):
        self.Nchirp = Nchirp
        self.set_tx_vec((np.concatenate((np.exp(1j*2*np.pi*np.cumsum(((-self.bw/2)+(self.bw/self.ton)*(np.arange(self.Nchirp)/self.samp_rate)))/self.samp_rate),np.zeros(self.Nperiod-self.Nchirp)))*np.exp(1j*2*np.pi*self.f_offset*np.arange(self.Nperiod)/self.samp_rate)).astype(np.complex64))

    def get_tx_vec(self):
        return self.tx_vec

    def set_tx_vec(self, tx_vec):
        self.tx_vec = tx_vec
        self.blocks_vector_source_x_0.set_data(self.tx_vec, [])

    def get_tx_gain(self):
        return self.tx_gain

    def set_tx_gain(self, tx_gain):
        self.tx_gain = tx_gain
        self.uhd_usrp_sink_1_0.set_gain(self.tx_gain, 0)

    def get_tx_freq(self):
        return self.tx_freq

    def set_tx_freq(self, tx_freq):
        self.tx_freq = tx_freq
        self.uhd_usrp_sink_1_0.set_center_freq(self.tx_freq, 0)

    def get_serial(self):
        return self.serial

    def set_serial(self, serial):
        self.serial = serial

    def get_notes(self):
        return self.notes

    def set_notes(self, notes):
        self.notes = notes

    def get_amp(self):
        return self.amp

    def set_amp(self, amp):
        self.amp = amp
        self.blocks_multiply_const_vxx_2.set_k(self.amp)





def main(top_block_cls=transmit, options=None):

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
