#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#
# SPDX-License-Identifier: GPL-3.0
#
# GNU Radio Python Flow Graph
# Title: Adapted from gr-gsm Livemon
# GNU Radio version: 3.10.7.0

from packaging.version import Version as StrictVersion
from PyQt5 import Qt
from gnuradio import qtgui
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
from gnuradio import gsm
from gnuradio import uhd
import time
from gnuradio.gsm import arfcn
from gnuradio.qtgui import Range, RangeWidget
from PyQt5 import QtCore
from math import pi
import sip



class gsm_uplink_downlink(gr.top_block, Qt.QWidget):

    def __init__(self, args="", collector="localhost", collectorport='4729', fc=1930.2e6, gain=32, osr=4, ppm=0, samp_rate=2000000, serverport='4729', shiftoff=400e3):
        gr.top_block.__init__(self, "Adapted from gr-gsm Livemon", catch_exceptions=True)
        Qt.QWidget.__init__(self)
        self.setWindowTitle("Adapted from gr-gsm Livemon")
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

        self.settings = Qt.QSettings("GNU Radio", "gsm_uplink_downlink")

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
        self.args = args
        self.collector = collector
        self.collectorport = collectorport
        self.fc = fc
        self.gain = gain
        self.osr = osr
        self.ppm = ppm
        self.samp_rate = samp_rate
        self.serverport = serverport
        self.shiftoff = shiftoff

        ##################################################
        # Variables
        ##################################################
        self.ppm_slider = ppm_slider = ppm
        self.gain_slider = gain_slider = gain
        self.fc_slider_uplink = fc_slider_uplink = 1850.2e6
        self.fc_slider = fc_slider = fc

        ##################################################
        # Blocks
        ##################################################

        self._fc_slider_uplink_range = Range(800e6, 1990e6, 2e5, 1850.2e6, 100)
        self._fc_slider_uplink_win = RangeWidget(self._fc_slider_uplink_range, self.set_fc_slider_uplink, "Uplink Frequency", "counter_slider", float, QtCore.Qt.Horizontal)
        self.top_layout.addWidget(self._fc_slider_uplink_win)
        self._fc_slider_range = Range(800e6, 1990e6, 2e5, fc, 100)
        self._fc_slider_win = RangeWidget(self._fc_slider_range, self.set_fc_slider, "Frequency", "counter_slider", float, QtCore.Qt.Horizontal)
        self.top_layout.addWidget(self._fc_slider_win)
        self.uhd_usrp_source_0_0_1 = uhd.usrp_source(
            ",".join(('', "")),
            uhd.stream_args(
                cpu_format="fc32",
                args='',
                channels=list(range(0,1)),
            ),
        )
        self.uhd_usrp_source_0_0_1.set_subdev_spec("A:A", 0)
        self.uhd_usrp_source_0_0_1.set_samp_rate(samp_rate)
        self.uhd_usrp_source_0_0_1.set_time_unknown_pps(uhd.time_spec(0))

        self.uhd_usrp_source_0_0_1.set_center_freq(fc_slider-shiftoff, 0)
        self.uhd_usrp_source_0_0_1.set_antenna('TX/RX', 0)
        self.uhd_usrp_source_0_0_1.set_gain(60, 0)
        self.qtgui_time_sink_x_0_0 = qtgui.time_sink_c(
            2000000, #size
            samp_rate, #samp_rate
            "Downlink", #name
            1, #number of inputs
            None # parent
        )
        self.qtgui_time_sink_x_0_0.set_update_time(0.10)
        self.qtgui_time_sink_x_0_0.set_y_axis(-1, 1)

        self.qtgui_time_sink_x_0_0.set_y_label('Amplitude', "")

        self.qtgui_time_sink_x_0_0.enable_tags(True)
        self.qtgui_time_sink_x_0_0.set_trigger_mode(qtgui.TRIG_MODE_FREE, qtgui.TRIG_SLOPE_POS, 0.0, 0, 0, "")
        self.qtgui_time_sink_x_0_0.enable_autoscale(False)
        self.qtgui_time_sink_x_0_0.enable_grid(False)
        self.qtgui_time_sink_x_0_0.enable_axis_labels(True)
        self.qtgui_time_sink_x_0_0.enable_control_panel(False)
        self.qtgui_time_sink_x_0_0.enable_stem_plot(False)


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
                    self.qtgui_time_sink_x_0_0.set_line_label(i, "Re{{Data {0}}}".format(i/2))
                else:
                    self.qtgui_time_sink_x_0_0.set_line_label(i, "Im{{Data {0}}}".format(i/2))
            else:
                self.qtgui_time_sink_x_0_0.set_line_label(i, labels[i])
            self.qtgui_time_sink_x_0_0.set_line_width(i, widths[i])
            self.qtgui_time_sink_x_0_0.set_line_color(i, colors[i])
            self.qtgui_time_sink_x_0_0.set_line_style(i, styles[i])
            self.qtgui_time_sink_x_0_0.set_line_marker(i, markers[i])
            self.qtgui_time_sink_x_0_0.set_line_alpha(i, alphas[i])

        self._qtgui_time_sink_x_0_0_win = sip.wrapinstance(self.qtgui_time_sink_x_0_0.qwidget(), Qt.QWidget)
        self.top_layout.addWidget(self._qtgui_time_sink_x_0_0_win)
        self.qtgui_time_sink_x_0 = qtgui.time_sink_c(
            2000000, #size
            samp_rate, #samp_rate
            "Uplink", #name
            1, #number of inputs
            None # parent
        )
        self.qtgui_time_sink_x_0.set_update_time(0.10)
        self.qtgui_time_sink_x_0.set_y_axis(-1, 1)

        self.qtgui_time_sink_x_0.set_y_label('Amplitude', "")

        self.qtgui_time_sink_x_0.enable_tags(True)
        self.qtgui_time_sink_x_0.set_trigger_mode(qtgui.TRIG_MODE_FREE, qtgui.TRIG_SLOPE_POS, 0.0, 0, 0, "")
        self.qtgui_time_sink_x_0.enable_autoscale(False)
        self.qtgui_time_sink_x_0.enable_grid(False)
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
        self.top_layout.addWidget(self._qtgui_time_sink_x_0_win)
        self._ppm_slider_range = Range(-150, 150, 0.1, ppm, 100)
        self._ppm_slider_win = RangeWidget(self._ppm_slider_range, self.set_ppm_slider, "PPM Offset", "counter", float, QtCore.Qt.Horizontal)
        self.top_layout.addWidget(self._ppm_slider_win)
        self.gsm_uplink_downlink_splitter_0 = gsm.uplink_downlink_splitter()
        self.gsm_sdcch8_demapper_0_0_3 = gsm.gsm_sdcch8_demapper(
            timeslot_nr=5,
        )
        self.gsm_sdcch8_demapper_0_0_2 = gsm.gsm_sdcch8_demapper(
            timeslot_nr=4,
        )
        self.gsm_sdcch8_demapper_0_0_1_0 = gsm.gsm_sdcch8_demapper(
            timeslot_nr=7,
        )
        self.gsm_sdcch8_demapper_0_0_1 = gsm.gsm_sdcch8_demapper(
            timeslot_nr=3,
        )
        self.gsm_sdcch8_demapper_0_0_0_0 = gsm.gsm_sdcch8_demapper(
            timeslot_nr=6,
        )
        self.gsm_sdcch8_demapper_0_0_0 = gsm.gsm_sdcch8_demapper(
            timeslot_nr=2,
        )
        self.gsm_sdcch8_demapper_0_0 = gsm.gsm_sdcch8_demapper(
            timeslot_nr=1,
        )
        self.gsm_sdcch8_demapper_0 = gsm.gsm_sdcch8_demapper(
            timeslot_nr=0,
        )
        self.gsm_receiver_with_uplink_0 = gsm.receiver(4, [0], [2], True)
        self.gsm_input_0_0 = gsm.gsm_input(
            ppm=ppm-int(ppm),
            osr=osr,
            fc=fc_slider-shiftoff,
            samp_rate_in=samp_rate,
        )
        self.gsm_input_0 = gsm.gsm_input(
            ppm=ppm-int(ppm),
            osr=osr,
            fc=fc_slider-shiftoff,
            samp_rate_in=samp_rate,
        )
        self.gsm_control_channels_decoder_0_0_1_3 = gsm.control_channels_decoder()
        self.gsm_control_channels_decoder_0_0_1_2 = gsm.control_channels_decoder()
        self.gsm_control_channels_decoder_0_0_1_1_0 = gsm.control_channels_decoder()
        self.gsm_control_channels_decoder_0_0_1_1 = gsm.control_channels_decoder()
        self.gsm_control_channels_decoder_0_0_1_0_0 = gsm.control_channels_decoder()
        self.gsm_control_channels_decoder_0_0_1_0 = gsm.control_channels_decoder()
        self.gsm_control_channels_decoder_0_0_1 = gsm.control_channels_decoder()
        self.gsm_control_channels_decoder_0_0_0_2 = gsm.control_channels_decoder()
        self.gsm_control_channels_decoder_0_0_0_1_0_0_0 = gsm.control_channels_decoder()
        self.gsm_control_channels_decoder_0_0_0_1_0_0 = gsm.control_channels_decoder()
        self.gsm_control_channels_decoder_0_0_0_1_0 = gsm.control_channels_decoder()
        self.gsm_control_channels_decoder_0_0_0_1 = gsm.control_channels_decoder()
        self.gsm_control_channels_decoder_0_0_0_0_0 = gsm.control_channels_decoder()
        self.gsm_control_channels_decoder_0_0_0_0 = gsm.control_channels_decoder()
        self.gsm_control_channels_decoder_0_0_0 = gsm.control_channels_decoder()
        self.gsm_control_channels_decoder_0_0 = gsm.control_channels_decoder()
        self.gsm_control_channels_decoder_0 = gsm.control_channels_decoder()
        self.gsm_clock_offset_control_0_0 = gsm.clock_offset_control(fc_slider_uplink-shiftoff, samp_rate, osr)
        self.gsm_clock_offset_control_0 = gsm.clock_offset_control(fc_slider-shiftoff, samp_rate, osr)
        self.gsm_bcch_ccch_sdcch4_demapper_0_2 = gsm.gsm_bcch_ccch_sdcch4_demapper(
            timeslot_nr=3,
        )
        self.gsm_bcch_ccch_sdcch4_demapper_0_1_0_0_0 = gsm.gsm_bcch_ccch_sdcch4_demapper(
            timeslot_nr=7,
        )
        self.gsm_bcch_ccch_sdcch4_demapper_0_1_0_0 = gsm.gsm_bcch_ccch_sdcch4_demapper(
            timeslot_nr=6,
        )
        self.gsm_bcch_ccch_sdcch4_demapper_0_1_0 = gsm.gsm_bcch_ccch_sdcch4_demapper(
            timeslot_nr=5,
        )
        self.gsm_bcch_ccch_sdcch4_demapper_0_1 = gsm.gsm_bcch_ccch_sdcch4_demapper(
            timeslot_nr=2,
        )
        self.gsm_bcch_ccch_sdcch4_demapper_0_0_0 = gsm.gsm_bcch_ccch_sdcch4_demapper(
            timeslot_nr=4,
        )
        self.gsm_bcch_ccch_sdcch4_demapper_0_0 = gsm.gsm_bcch_ccch_sdcch4_demapper(
            timeslot_nr=1,
        )
        self.gsm_bcch_ccch_sdcch4_demapper_0 = gsm.gsm_bcch_ccch_sdcch4_demapper(
            timeslot_nr=0,
        )
        self.gsm_bcch_ccch_demapper_0 = gsm.gsm_bcch_ccch_demapper(
            timeslot_nr=0,
        )
        self._gain_slider_range = Range(0, 40, 0.5, gain, 100)
        self._gain_slider_win = RangeWidget(self._gain_slider_range, self.set_gain_slider, "Gain", "counter", float, QtCore.Qt.Horizontal)
        self.top_layout.addWidget(self._gain_slider_win)
        self.blocks_rotator_cc_0_0 = blocks.rotator_cc((-2*pi*shiftoff/samp_rate), False)
        self.blocks_rotator_cc_0 = blocks.rotator_cc((-2*pi*shiftoff/samp_rate), False)
        self.blocks_null_source_0 = blocks.null_source(gr.sizeof_gr_complex*1)
        self.blocks_keep_one_in_n_0_0 = blocks.keep_one_in_n(gr.sizeof_gr_complex*1, 10)
        self.blocks_keep_one_in_n_0 = blocks.keep_one_in_n(gr.sizeof_gr_complex*1, 10)


        ##################################################
        # Connections
        ##################################################
        self.msg_connect((self.gsm_bcch_ccch_demapper_0, 'bursts'), (self.gsm_control_channels_decoder_0, 'bursts'))
        self.msg_connect((self.gsm_bcch_ccch_sdcch4_demapper_0, 'bursts'), (self.gsm_control_channels_decoder_0_0_0, 'bursts'))
        self.msg_connect((self.gsm_bcch_ccch_sdcch4_demapper_0_0, 'bursts'), (self.gsm_control_channels_decoder_0_0_0_0, 'bursts'))
        self.msg_connect((self.gsm_bcch_ccch_sdcch4_demapper_0_0_0, 'bursts'), (self.gsm_control_channels_decoder_0_0_0_0_0, 'bursts'))
        self.msg_connect((self.gsm_bcch_ccch_sdcch4_demapper_0_1, 'bursts'), (self.gsm_control_channels_decoder_0_0_0_1, 'bursts'))
        self.msg_connect((self.gsm_bcch_ccch_sdcch4_demapper_0_1_0, 'bursts'), (self.gsm_control_channels_decoder_0_0_0_1_0, 'bursts'))
        self.msg_connect((self.gsm_bcch_ccch_sdcch4_demapper_0_1_0_0, 'bursts'), (self.gsm_control_channels_decoder_0_0_0_1_0_0, 'bursts'))
        self.msg_connect((self.gsm_bcch_ccch_sdcch4_demapper_0_1_0_0_0, 'bursts'), (self.gsm_control_channels_decoder_0_0_0_1_0_0_0, 'bursts'))
        self.msg_connect((self.gsm_bcch_ccch_sdcch4_demapper_0_2, 'bursts'), (self.gsm_control_channels_decoder_0_0_0_2, 'bursts'))
        self.msg_connect((self.gsm_clock_offset_control_0, 'ctrl'), (self.gsm_input_0, 'ctrl_in'))
        self.msg_connect((self.gsm_clock_offset_control_0_0, 'ctrl'), (self.gsm_input_0_0, 'ctrl_in'))
        self.msg_connect((self.gsm_control_channels_decoder_0, 'msgs'), (self.gsm_uplink_downlink_splitter_0, 'in'))
        self.msg_connect((self.gsm_control_channels_decoder_0_0, 'msgs'), (self.gsm_uplink_downlink_splitter_0, 'in'))
        self.msg_connect((self.gsm_control_channels_decoder_0_0_0, 'msgs'), (self.gsm_uplink_downlink_splitter_0, 'in'))
        self.msg_connect((self.gsm_control_channels_decoder_0_0_0_0, 'msgs'), (self.gsm_uplink_downlink_splitter_0, 'in'))
        self.msg_connect((self.gsm_control_channels_decoder_0_0_0_0_0, 'msgs'), (self.gsm_uplink_downlink_splitter_0, 'in'))
        self.msg_connect((self.gsm_control_channels_decoder_0_0_0_1, 'msgs'), (self.gsm_uplink_downlink_splitter_0, 'in'))
        self.msg_connect((self.gsm_control_channels_decoder_0_0_0_1_0, 'msgs'), (self.gsm_uplink_downlink_splitter_0, 'in'))
        self.msg_connect((self.gsm_control_channels_decoder_0_0_0_1_0_0, 'msgs'), (self.gsm_uplink_downlink_splitter_0, 'in'))
        self.msg_connect((self.gsm_control_channels_decoder_0_0_0_1_0_0_0, 'msgs'), (self.gsm_uplink_downlink_splitter_0, 'in'))
        self.msg_connect((self.gsm_control_channels_decoder_0_0_0_2, 'msgs'), (self.gsm_uplink_downlink_splitter_0, 'in'))
        self.msg_connect((self.gsm_control_channels_decoder_0_0_1, 'msgs'), (self.gsm_uplink_downlink_splitter_0, 'in'))
        self.msg_connect((self.gsm_control_channels_decoder_0_0_1_0, 'msgs'), (self.gsm_uplink_downlink_splitter_0, 'in'))
        self.msg_connect((self.gsm_control_channels_decoder_0_0_1_0_0, 'msgs'), (self.gsm_uplink_downlink_splitter_0, 'in'))
        self.msg_connect((self.gsm_control_channels_decoder_0_0_1_1, 'msgs'), (self.gsm_uplink_downlink_splitter_0, 'in'))
        self.msg_connect((self.gsm_control_channels_decoder_0_0_1_1_0, 'msgs'), (self.gsm_uplink_downlink_splitter_0, 'in'))
        self.msg_connect((self.gsm_control_channels_decoder_0_0_1_2, 'msgs'), (self.gsm_uplink_downlink_splitter_0, 'in'))
        self.msg_connect((self.gsm_control_channels_decoder_0_0_1_3, 'msgs'), (self.gsm_uplink_downlink_splitter_0, 'in'))
        self.msg_connect((self.gsm_receiver_with_uplink_0, 'C0'), (self.gsm_bcch_ccch_demapper_0, 'bursts'))
        self.msg_connect((self.gsm_receiver_with_uplink_0, 'C0'), (self.gsm_bcch_ccch_sdcch4_demapper_0, 'bursts'))
        self.msg_connect((self.gsm_receiver_with_uplink_0, 'C0'), (self.gsm_bcch_ccch_sdcch4_demapper_0_0, 'bursts'))
        self.msg_connect((self.gsm_receiver_with_uplink_0, 'C0'), (self.gsm_bcch_ccch_sdcch4_demapper_0_0_0, 'bursts'))
        self.msg_connect((self.gsm_receiver_with_uplink_0, 'C0'), (self.gsm_bcch_ccch_sdcch4_demapper_0_1, 'bursts'))
        self.msg_connect((self.gsm_receiver_with_uplink_0, 'C0'), (self.gsm_bcch_ccch_sdcch4_demapper_0_1_0, 'bursts'))
        self.msg_connect((self.gsm_receiver_with_uplink_0, 'C0'), (self.gsm_bcch_ccch_sdcch4_demapper_0_1_0_0, 'bursts'))
        self.msg_connect((self.gsm_receiver_with_uplink_0, 'C0'), (self.gsm_bcch_ccch_sdcch4_demapper_0_1_0_0_0, 'bursts'))
        self.msg_connect((self.gsm_receiver_with_uplink_0, 'C0'), (self.gsm_bcch_ccch_sdcch4_demapper_0_2, 'bursts'))
        self.msg_connect((self.gsm_receiver_with_uplink_0, 'measurements'), (self.gsm_clock_offset_control_0, 'measurements'))
        self.msg_connect((self.gsm_receiver_with_uplink_0, 'measurements'), (self.gsm_clock_offset_control_0_0, 'measurements'))
        self.msg_connect((self.gsm_receiver_with_uplink_0, 'C0'), (self.gsm_sdcch8_demapper_0, 'bursts'))
        self.msg_connect((self.gsm_receiver_with_uplink_0, 'C0'), (self.gsm_sdcch8_demapper_0_0, 'bursts'))
        self.msg_connect((self.gsm_receiver_with_uplink_0, 'C0'), (self.gsm_sdcch8_demapper_0_0_0, 'bursts'))
        self.msg_connect((self.gsm_receiver_with_uplink_0, 'C0'), (self.gsm_sdcch8_demapper_0_0_0_0, 'bursts'))
        self.msg_connect((self.gsm_receiver_with_uplink_0, 'C0'), (self.gsm_sdcch8_demapper_0_0_1, 'bursts'))
        self.msg_connect((self.gsm_receiver_with_uplink_0, 'C0'), (self.gsm_sdcch8_demapper_0_0_1_0, 'bursts'))
        self.msg_connect((self.gsm_receiver_with_uplink_0, 'C0'), (self.gsm_sdcch8_demapper_0_0_2, 'bursts'))
        self.msg_connect((self.gsm_receiver_with_uplink_0, 'C0'), (self.gsm_sdcch8_demapper_0_0_3, 'bursts'))
        self.msg_connect((self.gsm_sdcch8_demapper_0, 'bursts'), (self.gsm_control_channels_decoder_0_0, 'bursts'))
        self.msg_connect((self.gsm_sdcch8_demapper_0_0, 'bursts'), (self.gsm_control_channels_decoder_0_0_1, 'bursts'))
        self.msg_connect((self.gsm_sdcch8_demapper_0_0_0, 'bursts'), (self.gsm_control_channels_decoder_0_0_1_0, 'bursts'))
        self.msg_connect((self.gsm_sdcch8_demapper_0_0_0_0, 'bursts'), (self.gsm_control_channels_decoder_0_0_1_0_0, 'bursts'))
        self.msg_connect((self.gsm_sdcch8_demapper_0_0_1, 'bursts'), (self.gsm_control_channels_decoder_0_0_1_1, 'bursts'))
        self.msg_connect((self.gsm_sdcch8_demapper_0_0_1_0, 'bursts'), (self.gsm_control_channels_decoder_0_0_1_1_0, 'bursts'))
        self.msg_connect((self.gsm_sdcch8_demapper_0_0_2, 'bursts'), (self.gsm_control_channels_decoder_0_0_1_2, 'bursts'))
        self.msg_connect((self.gsm_sdcch8_demapper_0_0_3, 'bursts'), (self.gsm_control_channels_decoder_0_0_1_3, 'bursts'))
        self.connect((self.blocks_keep_one_in_n_0, 0), (self.qtgui_time_sink_x_0, 0))
        self.connect((self.blocks_keep_one_in_n_0_0, 0), (self.qtgui_time_sink_x_0_0, 0))
        self.connect((self.blocks_null_source_0, 0), (self.blocks_keep_one_in_n_0, 0))
        self.connect((self.blocks_null_source_0, 0), (self.blocks_rotator_cc_0_0, 0))
        self.connect((self.blocks_rotator_cc_0, 0), (self.gsm_input_0, 0))
        self.connect((self.blocks_rotator_cc_0_0, 0), (self.gsm_input_0_0, 0))
        self.connect((self.gsm_input_0, 0), (self.gsm_receiver_with_uplink_0, 0))
        self.connect((self.gsm_input_0_0, 0), (self.gsm_receiver_with_uplink_0, 1))
        self.connect((self.uhd_usrp_source_0_0_1, 0), (self.blocks_keep_one_in_n_0_0, 0))
        self.connect((self.uhd_usrp_source_0_0_1, 0), (self.blocks_rotator_cc_0, 0))


    def closeEvent(self, event):
        self.settings = Qt.QSettings("GNU Radio", "gsm_uplink_downlink")
        self.settings.setValue("geometry", self.saveGeometry())
        self.stop()
        self.wait()

        event.accept()

    def get_args(self):
        return self.args

    def set_args(self, args):
        self.args = args

    def get_collector(self):
        return self.collector

    def set_collector(self, collector):
        self.collector = collector

    def get_collectorport(self):
        return self.collectorport

    def set_collectorport(self, collectorport):
        self.collectorport = collectorport

    def get_fc(self):
        return self.fc

    def set_fc(self, fc):
        self.fc = fc
        self.set_fc_slider(self.fc)

    def get_gain(self):
        return self.gain

    def set_gain(self, gain):
        self.gain = gain
        self.set_gain_slider(self.gain)

    def get_osr(self):
        return self.osr

    def set_osr(self, osr):
        self.osr = osr
        self.gsm_input_0.set_osr(self.osr)
        self.gsm_input_0_0.set_osr(self.osr)

    def get_ppm(self):
        return self.ppm

    def set_ppm(self, ppm):
        self.ppm = ppm
        self.set_ppm_slider(self.ppm)
        self.gsm_input_0.set_ppm(self.ppm-int(self.ppm))
        self.gsm_input_0_0.set_ppm(self.ppm-int(self.ppm))

    def get_samp_rate(self):
        return self.samp_rate

    def set_samp_rate(self, samp_rate):
        self.samp_rate = samp_rate
        self.blocks_rotator_cc_0.set_phase_inc((-2*pi*self.shiftoff/self.samp_rate))
        self.blocks_rotator_cc_0_0.set_phase_inc((-2*pi*self.shiftoff/self.samp_rate))
        self.gsm_input_0.set_samp_rate_in(self.samp_rate)
        self.gsm_input_0_0.set_samp_rate_in(self.samp_rate)
        self.qtgui_time_sink_x_0.set_samp_rate(self.samp_rate)
        self.qtgui_time_sink_x_0_0.set_samp_rate(self.samp_rate)
        self.uhd_usrp_source_0_0_1.set_samp_rate(self.samp_rate)

    def get_serverport(self):
        return self.serverport

    def set_serverport(self, serverport):
        self.serverport = serverport

    def get_shiftoff(self):
        return self.shiftoff

    def set_shiftoff(self, shiftoff):
        self.shiftoff = shiftoff
        self.blocks_rotator_cc_0.set_phase_inc((-2*pi*self.shiftoff/self.samp_rate))
        self.blocks_rotator_cc_0_0.set_phase_inc((-2*pi*self.shiftoff/self.samp_rate))
        self.gsm_clock_offset_control_0.set_fc(self.fc_slider-self.shiftoff)
        self.gsm_clock_offset_control_0_0.set_fc(self.fc_slider_uplink-self.shiftoff)
        self.gsm_input_0.set_fc(self.fc_slider-self.shiftoff)
        self.gsm_input_0_0.set_fc(self.fc_slider-self.shiftoff)
        self.uhd_usrp_source_0_0_1.set_center_freq(self.fc_slider-self.shiftoff, 0)

    def get_ppm_slider(self):
        return self.ppm_slider

    def set_ppm_slider(self, ppm_slider):
        self.ppm_slider = ppm_slider

    def get_gain_slider(self):
        return self.gain_slider

    def set_gain_slider(self, gain_slider):
        self.gain_slider = gain_slider

    def get_fc_slider_uplink(self):
        return self.fc_slider_uplink

    def set_fc_slider_uplink(self, fc_slider_uplink):
        self.fc_slider_uplink = fc_slider_uplink
        self.gsm_clock_offset_control_0_0.set_fc(self.fc_slider_uplink-self.shiftoff)

    def get_fc_slider(self):
        return self.fc_slider

    def set_fc_slider(self, fc_slider):
        self.fc_slider = fc_slider
        self.gsm_clock_offset_control_0.set_fc(self.fc_slider-self.shiftoff)
        self.gsm_input_0.set_fc(self.fc_slider-self.shiftoff)
        self.gsm_input_0_0.set_fc(self.fc_slider-self.shiftoff)
        self.uhd_usrp_source_0_0_1.set_center_freq(self.fc_slider-self.shiftoff, 0)



def argument_parser():
    parser = ArgumentParser()
    parser.add_argument(
        "--collector", dest="collector", type=str, default="localhost",
        help="Set IP or DNS name of collector point [default=%(default)r]")
    parser.add_argument(
        "--collectorport", dest="collectorport", type=str, default='4729',
        help="Set UDP port number of collector [default=%(default)r]")
    parser.add_argument(
        "-f", "--fc", dest="fc", type=eng_float, default=eng_notation.num_to_str(float(1930.2e6)),
        help="Set GSM channel's central frequency [default=%(default)r]")
    parser.add_argument(
        "-g", "--gain", dest="gain", type=eng_float, default=eng_notation.num_to_str(float(32)),
        help="Set gain [default=%(default)r]")
    parser.add_argument(
        "--osr", dest="osr", type=intx, default=4,
        help="Set OverSampling Ratio [default=%(default)r]")
    parser.add_argument(
        "-p", "--ppm", dest="ppm", type=eng_float, default=eng_notation.num_to_str(float(0)),
        help="Set ppm [default=%(default)r]")
    parser.add_argument(
        "-s", "--samp-rate", dest="samp_rate", type=eng_float, default=eng_notation.num_to_str(float(2000000)),
        help="Set samp_rate [default=%(default)r]")
    parser.add_argument(
        "--serverport", dest="serverport", type=str, default='4729',
        help="Set UDP server listening port [default=%(default)r]")
    parser.add_argument(
        "-o", "--shiftoff", dest="shiftoff", type=eng_float, default=eng_notation.num_to_str(float(400e3)),
        help="Set Frequency Shiftoff [default=%(default)r]")
    return parser


def main(top_block_cls=gsm_uplink_downlink, options=None):
    if options is None:
        options = argument_parser().parse_args()

    if StrictVersion("4.5.0") <= StrictVersion(Qt.qVersion()) < StrictVersion("5.0.0"):
        style = gr.prefs().get_string('qtgui', 'style', 'raster')
        Qt.QApplication.setGraphicsSystem(style)
    qapp = Qt.QApplication(sys.argv)

    tb = top_block_cls(collector=options.collector, collectorport=options.collectorport, fc=options.fc, gain=options.gain, osr=options.osr, ppm=options.ppm, samp_rate=options.samp_rate, serverport=options.serverport, shiftoff=options.shiftoff)

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
