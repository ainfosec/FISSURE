#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#
# SPDX-License-Identifier: GPL-3.0
#
# GNU Radio Python Flow Graph
# Title: Soapy AIS receiver
# Author: Nick Foster
# GNU Radio version: v3.11.0.0git-55-g8526e6f8

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

import os
import sys
sys.path.append(os.environ.get('GRC_HIER_PATH', os.path.expanduser('~/.grc_gnuradio')))

from PyQt5 import Qt
from gnuradio import qtgui
from gnuradio.filter import firdes
import sip
from ais_rx_core import ais_rx_core  # grc-generated hier_block
from gnuradio import analog
import math
from gnuradio import blocks
from gnuradio import gr
from gnuradio.fft import window
import signal
from argparse import ArgumentParser
from gnuradio.eng_arg import eng_float, intx
from gnuradio import eng_notation
from gnuradio import soapy
from gnuradio.ais import pdu_to_nmea
from gnuradio.qtgui import Range, RangeWidget
from PyQt5 import QtCore



from gnuradio import qtgui

class soapy_ais_rx(gr.top_block, Qt.QWidget):

    def __init__(self, ant='TX/RX', args="", samp_rate=300e3):
        gr.top_block.__init__(self, "Soapy AIS receiver", catch_exceptions=True)
        Qt.QWidget.__init__(self)
        self.setWindowTitle("Soapy AIS receiver")
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

        self.settings = Qt.QSettings("GNU Radio", "soapy_ais_rx")

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
        self.ant = ant
        self.args = args
        self.samp_rate = samp_rate

        ##################################################
        # Variables
        ##################################################
        self.threshold = threshold = 0.83
        self.ted_bw = ted_bw = 0.033
        self.gain = gain = 70

        ##################################################
        # Blocks
        ##################################################
        self._threshold_range = Range(0, 1.0, 0.001, 0.83, 200)
        self._threshold_win = RangeWidget(self._threshold_range, self.set_threshold, "Correlator threshold", "counter_slider", float, QtCore.Qt.Horizontal)
        self.top_layout.addWidget(self._threshold_win)
        self._ted_bw_range = Range(0.001, 1.0, 0.001, 0.033, 200)
        self._ted_bw_win = RangeWidget(self._ted_bw_range, self.set_ted_bw, "TED bandwidth", "counter_slider", float, QtCore.Qt.Horizontal)
        self.top_layout.addWidget(self._ted_bw_win)
        self._gain_range = Range(0, 120, 1, 70, 200)
        self._gain_win = RangeWidget(self._gain_range, self.set_gain, "Gain", "counter_slider", float, QtCore.Qt.Horizontal)
        self.top_layout.addWidget(self._gain_win)
        self.soapy_source_0 = None
        # Make sure that the gain mode is valid
        if('Overall' not in ['Overall', 'Specific', 'Settings Field']):
            raise ValueError("Wrong gain mode on channel 0. Allowed gain modes: "
                  "['Overall', 'Specific', 'Settings Field']")

        dev = 'driver=rtlsdr'

        # Stream arguments
        stream_args = ''

        # Tune arguments for every activated stream
        tune_args = ['']
        settings = ['']

        # Setup the device arguments
        dev_args = ''

        self.soapy_source_0 = soapy.source(dev, "fc32", 1, dev_args,
                                  stream_args, tune_args, settings)

        self.soapy_source_0.set_sample_rate(0, samp_rate)



        self.soapy_source_0.set_dc_offset_mode(0,False)

        # Set up DC offset. If set to (0, 0) internally the source block
        # will handle the case if no DC offset correction is supported
        self.soapy_source_0.set_dc_offset(0,0)

        # Setup IQ Balance. If set to (0, 0) internally the source block
        # will handle the case if no IQ balance correction is supported
        self.soapy_source_0.set_iq_balance(0,0)

        self.soapy_source_0.set_gain_mode(0,False)

        # generic frequency setting should be specified first
        self.soapy_source_0.set_frequency(0, 162e6)

        self.soapy_source_0.set_frequency(0,"BB",0)

        # Setup Frequency correction. If set to 0 internally the source block
        # will handle the case if no frequency correction is supported
        self.soapy_source_0.set_frequency_correction(0,0)

        self.soapy_source_0.set_antenna(0,'RX')

        self.soapy_source_0.set_bandwidth(0,0)

        if('Overall' != 'Settings Field'):
            # pass is needed, in case the template does not evaluare anything
            pass
            self.soapy_source_0.set_gain(0,gain)
        self.qtgui_time_sink_x_0 = qtgui.time_sink_f(
            1024, #size
            samp_rate, #samp_rate
            "", #name
            2, #number of inputs
            None # parent
        )
        self.qtgui_time_sink_x_0.set_update_time(0.10)
        self.qtgui_time_sink_x_0.set_y_axis(-1, 1)

        self.qtgui_time_sink_x_0.set_y_label('Amplitude', "")

        self.qtgui_time_sink_x_0.enable_tags(True)
        self.qtgui_time_sink_x_0.set_trigger_mode(qtgui.TRIG_MODE_TAG, qtgui.TRIG_SLOPE_POS, 0.0, 0, 0, "time_est")
        self.qtgui_time_sink_x_0.enable_autoscale(False)
        self.qtgui_time_sink_x_0.enable_grid(False)
        self.qtgui_time_sink_x_0.enable_axis_labels(True)
        self.qtgui_time_sink_x_0.enable_control_panel(False)
        self.qtgui_time_sink_x_0.enable_stem_plot(False)


        labels = ['Signal 1', 'Signal 2', 'Signal 3', 'Signal 4', 'Signal 5',
            'Signal 6', 'Signal 7', 'Signal 8', 'Signal 9', 'Signal 10']
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
                self.qtgui_time_sink_x_0.set_line_label(i, "Data {0}".format(i))
            else:
                self.qtgui_time_sink_x_0.set_line_label(i, labels[i])
            self.qtgui_time_sink_x_0.set_line_width(i, widths[i])
            self.qtgui_time_sink_x_0.set_line_color(i, colors[i])
            self.qtgui_time_sink_x_0.set_line_style(i, styles[i])
            self.qtgui_time_sink_x_0.set_line_marker(i, markers[i])
            self.qtgui_time_sink_x_0.set_line_alpha(i, alphas[i])

        self._qtgui_time_sink_x_0_win = sip.wrapinstance(self.qtgui_time_sink_x_0.qwidget(), Qt.QWidget)
        self.top_layout.addWidget(self._qtgui_time_sink_x_0_win)
        self.pdu_to_nmea_0_0 = pdu_to_nmea('B')
        self.pdu_to_nmea_0 = pdu_to_nmea('A')
        self.blocks_rotator_cc_0_0 = blocks.rotator_cc(2*math.pi*(25e3/samp_rate), False)
        self.blocks_rotator_cc_0 = blocks.rotator_cc(2*math.pi*(-25e3/samp_rate), False)
        self.analog_quadrature_demod_cf_0 = analog.quadrature_demod_cf(1)
        self.ais_rx_core_0_0 = ais_rx_core(
            bb_sps=4,
            bt=0.4,
            loopbw=ted_bw,
            samp_rate=samp_rate,
            threshold=threshold,
        )
        self.ais_rx_core_0 = ais_rx_core(
            bb_sps=4,
            bt=0.4,
            loopbw=ted_bw,
            samp_rate=samp_rate,
            threshold=threshold,
        )


        ##################################################
        # Connections
        ##################################################
        self.msg_connect((self.ais_rx_core_0, 'out'), (self.pdu_to_nmea_0, 'print'))
        self.msg_connect((self.ais_rx_core_0_0, 'out'), (self.pdu_to_nmea_0_0, 'print'))
        self.connect((self.ais_rx_core_0, 1), (self.analog_quadrature_demod_cf_0, 0))
        self.connect((self.ais_rx_core_0, 2), (self.qtgui_time_sink_x_0, 1))
        self.connect((self.analog_quadrature_demod_cf_0, 0), (self.qtgui_time_sink_x_0, 0))
        self.connect((self.blocks_rotator_cc_0, 0), (self.ais_rx_core_0, 0))
        self.connect((self.blocks_rotator_cc_0_0, 0), (self.ais_rx_core_0_0, 0))
        self.connect((self.soapy_source_0, 0), (self.blocks_rotator_cc_0, 0))
        self.connect((self.soapy_source_0, 0), (self.blocks_rotator_cc_0_0, 0))


    def closeEvent(self, event):
        self.settings = Qt.QSettings("GNU Radio", "soapy_ais_rx")
        self.settings.setValue("geometry", self.saveGeometry())
        self.stop()
        self.wait()

        event.accept()

    def get_ant(self):
        return self.ant

    def set_ant(self, ant):
        self.ant = ant

    def get_args(self):
        return self.args

    def set_args(self, args):
        self.args = args

    def get_samp_rate(self):
        return self.samp_rate

    def set_samp_rate(self, samp_rate):
        self.samp_rate = samp_rate
        self.ais_rx_core_0.set_samp_rate(self.samp_rate)
        self.ais_rx_core_0_0.set_samp_rate(self.samp_rate)
        self.blocks_rotator_cc_0.set_phase_inc(2*math.pi*(-25e3/self.samp_rate))
        self.blocks_rotator_cc_0_0.set_phase_inc(2*math.pi*(25e3/self.samp_rate))
        self.qtgui_time_sink_x_0.set_samp_rate(self.samp_rate)

    def get_threshold(self):
        return self.threshold

    def set_threshold(self, threshold):
        self.threshold = threshold
        self.ais_rx_core_0.set_threshold(self.threshold)
        self.ais_rx_core_0_0.set_threshold(self.threshold)

    def get_ted_bw(self):
        return self.ted_bw

    def set_ted_bw(self, ted_bw):
        self.ted_bw = ted_bw
        self.ais_rx_core_0.set_loopbw(self.ted_bw)
        self.ais_rx_core_0_0.set_loopbw(self.ted_bw)

    def get_gain(self):
        return self.gain

    def set_gain(self, gain):
        self.gain = gain
        self.soapy_source_0.set_gain(0, self.gain)



def argument_parser():
    parser = ArgumentParser()
    parser.add_argument(
        "--ant", dest="ant", type=str, default='TX/RX',
        help="Set Antenna [default=%(default)r]")
    parser.add_argument(
        "--args", dest="args", type=str, default="",
        help="Set USRP args [default=%(default)r]")
    parser.add_argument(
        "--samp-rate", dest="samp_rate", type=eng_float, default=eng_notation.num_to_str(float(300e3)),
        help="Set Sample rate [default=%(default)r]")
    return parser


def main(top_block_cls=soapy_ais_rx, options=None):
    if options is None:
        options = argument_parser().parse_args()

    if StrictVersion("4.5.0") <= StrictVersion(Qt.qVersion()) < StrictVersion("5.0.0"):
        style = gr.prefs().get_string('qtgui', 'style', 'raster')
        Qt.QApplication.setGraphicsSystem(style)
    qapp = Qt.QApplication(sys.argv)

    tb = top_block_cls(ant=options.ant, args=options.args, samp_rate=options.samp_rate)

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
