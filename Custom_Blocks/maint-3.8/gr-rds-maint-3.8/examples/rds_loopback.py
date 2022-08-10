#!/usr/bin/env python3
# -*- coding: utf-8 -*-

#
# SPDX-License-Identifier: GPL-3.0
#
# GNU Radio Python Flow Graph
# Title: Rds Loopback
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

from PyQt5 import Qt
from gnuradio import qtgui
from gnuradio.filter import firdes
import sip
from gnuradio import analog
from gnuradio import blocks
from gnuradio import digital
from gnuradio import filter
from gnuradio import gr
import sys
from argparse import ArgumentParser
from gnuradio.eng_arg import eng_float, intx
from gnuradio import eng_notation
from gnuradio.qtgui import Range, RangeWidget
import math
import rds
from gnuradio import qtgui

class rds_loopback(gr.top_block, Qt.QWidget):

    def __init__(self):
        gr.top_block.__init__(self, "Rds Loopback")
        Qt.QWidget.__init__(self)
        self.setWindowTitle("Rds Loopback")
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

        self.settings = Qt.QSettings("GNU Radio", "rds_loopback")

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
        self.samp_rate = samp_rate = 1000000
        self.bb_decim = bb_decim = 4
        self.baseband_rate = baseband_rate = samp_rate/bb_decim
        self.audio_decim = audio_decim = 5
        self.xlate_bandwidth = xlate_bandwidth = 100000
        self.usrp_rate = usrp_rate = 19e3*20
        self.stereo_gain = stereo_gain = 0.3
        self.rds_gain = rds_gain = 0.02
        self.outbuffer = outbuffer = 0
        self.input_gain = input_gain = 1
        self.freq = freq = 97e6
        self.fm_max_dev = fm_max_dev = 80e3
        self.audio_rate = audio_rate = 48000
        self.audio_decim_rate = audio_decim_rate = baseband_rate/audio_decim

        ##################################################
        # Blocks
        ##################################################
        self.tabs = Qt.QTabWidget()
        self.tabs_widget_0 = Qt.QWidget()
        self.tabs_layout_0 = Qt.QBoxLayout(Qt.QBoxLayout.TopToBottom, self.tabs_widget_0)
        self.tabs_grid_layout_0 = Qt.QGridLayout()
        self.tabs_layout_0.addLayout(self.tabs_grid_layout_0)
        self.tabs.addTab(self.tabs_widget_0, 'BB')
        self.tabs_widget_1 = Qt.QWidget()
        self.tabs_layout_1 = Qt.QBoxLayout(Qt.QBoxLayout.TopToBottom, self.tabs_widget_1)
        self.tabs_grid_layout_1 = Qt.QGridLayout()
        self.tabs_layout_1.addLayout(self.tabs_grid_layout_1)
        self.tabs.addTab(self.tabs_widget_1, 'RDS')
        self.tabs_widget_2 = Qt.QWidget()
        self.tabs_layout_2 = Qt.QBoxLayout(Qt.QBoxLayout.TopToBottom, self.tabs_widget_2)
        self.tabs_grid_layout_2 = Qt.QGridLayout()
        self.tabs_layout_2.addLayout(self.tabs_grid_layout_2)
        self.tabs.addTab(self.tabs_widget_2, 'Waterfall')
        self.top_grid_layout.addWidget(self.tabs)
        self._rds_gain_range = Range(0, 3, 0.01, 0.02, 200)
        self._rds_gain_win = RangeWidget(self._rds_gain_range, self.set_rds_gain, 'rds_gain', "counter_slider", float)
        self.top_grid_layout.addWidget(self._rds_gain_win)
        self._stereo_gain_range = Range(0, 3, 0.01, 0.3, 200)
        self._stereo_gain_win = RangeWidget(self._stereo_gain_range, self.set_stereo_gain, 'stereo_gain', "counter_slider", float)
        self.top_grid_layout.addWidget(self._stereo_gain_win)
        self.root_raised_cosine_filter_0_0 = filter.fir_filter_ccf(
            3,
            firdes.root_raised_cosine(
                1,
                samp_rate/bb_decim/audio_decim,
                2375,
                1,
                100))
        self.rds_parser_0 = rds.parser(False, False, 0)
        self.rds_panel_0 = rds.rdsPanel(0)
        self._rds_panel_0_win = self.rds_panel_0
        self.top_grid_layout.addWidget(self._rds_panel_0_win)
        self.rds_encoder_0 = rds.encoder(0, 14, True, 'WDR 3', 89.8e6,
        			True, False, 13, 3,
        			147, 'GNU Radio <3')

        self.rds_decoder_0 = rds.decoder(False, False)
        self.rational_resampler_xxx_1 = filter.rational_resampler_ccc(
                interpolation=100,
                decimation=38,
                taps=None,
                fractional_bw=None)
        self.qtgui_waterfall_sink_x_0 = qtgui.waterfall_sink_f(
            1024, #size
            firdes.WIN_BLACKMAN_hARRIS, #wintype
            0, #fc
            baseband_rate, #bw
            "", #name
            1 #number of inputs
        )
        self.qtgui_waterfall_sink_x_0.set_update_time(0.10)
        self.qtgui_waterfall_sink_x_0.enable_grid(False)
        self.qtgui_waterfall_sink_x_0.enable_axis_labels(True)


        self.qtgui_waterfall_sink_x_0.set_plot_pos_half(not True)

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
        self.tabs_layout_2.addWidget(self._qtgui_waterfall_sink_x_0_win)
        self.qtgui_time_sink_x_0 = qtgui.time_sink_c(
            1024, #size
            samp_rate/5, #samp_rate
            "", #name
            1 #number of inputs
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
        colors = ["blue", "red", "green", "black", "cyan",
            "magenta", "yellow", "dark red", "dark green", "blue"]
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

        self._qtgui_time_sink_x_0_win = sip.wrapinstance(self.qtgui_time_sink_x_0.pyqwidget(), Qt.QWidget)
        self.tabs_layout_0.addWidget(self._qtgui_time_sink_x_0_win)
        self.qtgui_freq_sink_x_0 = qtgui.freq_sink_c(
            1024, #size
            firdes.WIN_BLACKMAN_hARRIS, #wintype
            0, #fc
            audio_rate, #bw
            "", #name
            1
        )
        self.qtgui_freq_sink_x_0.set_update_time(0.10)
        self.qtgui_freq_sink_x_0.set_y_axis(-140, 10)
        self.qtgui_freq_sink_x_0.set_y_label('Relative Gain', 'dB')
        self.qtgui_freq_sink_x_0.set_trigger_mode(qtgui.TRIG_MODE_FREE, 0.0, 0, "")
        self.qtgui_freq_sink_x_0.enable_autoscale(False)
        self.qtgui_freq_sink_x_0.enable_grid(False)
        self.qtgui_freq_sink_x_0.set_fft_average(1.0)
        self.qtgui_freq_sink_x_0.enable_axis_labels(True)
        self.qtgui_freq_sink_x_0.enable_control_panel(False)



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
        self.tabs_layout_1.addWidget(self._qtgui_freq_sink_x_0_win)
        self.low_pass_filter_0 = filter.interp_fir_filter_fff(
            1,
            firdes.low_pass(
                1,
                usrp_rate,
                2.5e3,
                .5e3,
                firdes.WIN_HAMMING,
                6.76))
        self._input_gain_range = Range(0, 10, 0.1, 1, 200)
        self._input_gain_win = RangeWidget(self._input_gain_range, self.set_input_gain, 'input_gain', "counter_slider", float)
        self.top_grid_layout.addWidget(self._input_gain_win)
        self.gr_unpack_k_bits_bb_0 = blocks.unpack_k_bits_bb(2)
        self.gr_sig_source_x_0_0 = analog.sig_source_f(usrp_rate, analog.GR_SIN_WAVE, 57e3, 1, 0)
        self.gr_multiply_xx_0 = blocks.multiply_vff(1)
        self.gr_map_bb_1 = digital.map_bb([1,2])
        self.gr_map_bb_0 = digital.map_bb([-1,1])
        self.gr_frequency_modulator_fc_0 = analog.frequency_modulator_fc(2*math.pi*fm_max_dev/usrp_rate)
        self.gr_diff_encoder_bb_0 = digital.diff_encoder_bb(2)
        self.gr_char_to_float_0 = blocks.char_to_float(1, 1)
        self.freq_xlating_fir_filter_xxx_1 = filter.freq_xlating_fir_filter_fcc(audio_decim, firdes.low_pass(2500.0,baseband_rate,2.4e3,2e3,firdes.WIN_HAMMING), 57e3, baseband_rate)
        self.freq_xlating_fir_filter_xxx_0 = filter.freq_xlating_fir_filter_ccc(1, firdes.low_pass(1, samp_rate, xlate_bandwidth, 100000), 0, samp_rate)
        self._freq_range = Range(88.0e6, 108.0e6, 0.1e6, 97e6, 200)
        self._freq_win = RangeWidget(self._freq_range, self.set_freq, 'freq', "counter_slider", float)
        self.top_grid_layout.addWidget(self._freq_win)
        self.digital_psk_demod_0 = digital.psk.psk_demod(
            constellation_points=2,
            differential=False,
            samples_per_symbol=7,
            excess_bw=0.35,
            phase_bw=6.28/100.0,
            timing_bw=6.28/100.0,
            mod_code="gray",
            verbose=False,
            log=False)
        self.digital_diff_decoder_bb_0_0 = digital.diff_decoder_bb(2)
        self.blocks_throttle_0 = blocks.throttle(gr.sizeof_gr_complex*1, 1e6,True)
        self.blocks_socket_pdu_0 = blocks.socket_pdu('TCP_SERVER', '', '52001', 10000, False)
        self.blocks_repeat_0 = blocks.repeat(gr.sizeof_float*1, 160)
        self.blocks_multiply_const_vxx_0_0 = blocks.multiply_const_ff(rds_gain)
        self.blocks_keep_one_in_n_0_0 = blocks.keep_one_in_n(gr.sizeof_char*1, 2)
        self.analog_wfm_rcv_0 = analog.wfm_rcv(
        	quad_rate=samp_rate,
        	audio_decimation=bb_decim,
        )



        ##################################################
        # Connections
        ##################################################
        self.msg_connect((self.blocks_socket_pdu_0, 'pdus'), (self.rds_encoder_0, 'rds in'))
        self.msg_connect((self.rds_decoder_0, 'out'), (self.rds_parser_0, 'in'))
        self.msg_connect((self.rds_parser_0, 'out'), (self.rds_panel_0, 'in'))
        self.connect((self.analog_wfm_rcv_0, 0), (self.freq_xlating_fir_filter_xxx_1, 0))
        self.connect((self.analog_wfm_rcv_0, 0), (self.qtgui_waterfall_sink_x_0, 0))
        self.connect((self.blocks_keep_one_in_n_0_0, 0), (self.digital_diff_decoder_bb_0_0, 0))
        self.connect((self.blocks_multiply_const_vxx_0_0, 0), (self.gr_frequency_modulator_fc_0, 0))
        self.connect((self.blocks_repeat_0, 0), (self.low_pass_filter_0, 0))
        self.connect((self.blocks_throttle_0, 0), (self.freq_xlating_fir_filter_xxx_0, 0))
        self.connect((self.digital_diff_decoder_bb_0_0, 0), (self.rds_decoder_0, 0))
        self.connect((self.digital_psk_demod_0, 0), (self.blocks_keep_one_in_n_0_0, 0))
        self.connect((self.freq_xlating_fir_filter_xxx_0, 0), (self.analog_wfm_rcv_0, 0))
        self.connect((self.freq_xlating_fir_filter_xxx_1, 0), (self.qtgui_freq_sink_x_0, 0))
        self.connect((self.freq_xlating_fir_filter_xxx_1, 0), (self.qtgui_time_sink_x_0, 0))
        self.connect((self.freq_xlating_fir_filter_xxx_1, 0), (self.root_raised_cosine_filter_0_0, 0))
        self.connect((self.gr_char_to_float_0, 0), (self.blocks_repeat_0, 0))
        self.connect((self.gr_diff_encoder_bb_0, 0), (self.gr_map_bb_1, 0))
        self.connect((self.gr_frequency_modulator_fc_0, 0), (self.rational_resampler_xxx_1, 0))
        self.connect((self.gr_map_bb_0, 0), (self.gr_char_to_float_0, 0))
        self.connect((self.gr_map_bb_1, 0), (self.gr_unpack_k_bits_bb_0, 0))
        self.connect((self.gr_multiply_xx_0, 0), (self.blocks_multiply_const_vxx_0_0, 0))
        self.connect((self.gr_sig_source_x_0_0, 0), (self.gr_multiply_xx_0, 0))
        self.connect((self.gr_unpack_k_bits_bb_0, 0), (self.gr_map_bb_0, 0))
        self.connect((self.low_pass_filter_0, 0), (self.gr_multiply_xx_0, 1))
        self.connect((self.rational_resampler_xxx_1, 0), (self.blocks_throttle_0, 0))
        self.connect((self.rds_encoder_0, 0), (self.gr_diff_encoder_bb_0, 0))
        self.connect((self.root_raised_cosine_filter_0_0, 0), (self.digital_psk_demod_0, 0))

    def closeEvent(self, event):
        self.settings = Qt.QSettings("GNU Radio", "rds_loopback")
        self.settings.setValue("geometry", self.saveGeometry())
        event.accept()

    def get_samp_rate(self):
        return self.samp_rate

    def set_samp_rate(self, samp_rate):
        self.samp_rate = samp_rate
        self.set_baseband_rate(self.samp_rate/self.bb_decim)
        self.freq_xlating_fir_filter_xxx_0.set_taps(firdes.low_pass(1, self.samp_rate, self.xlate_bandwidth, 100000))
        self.qtgui_time_sink_x_0.set_samp_rate(self.samp_rate/5)
        self.root_raised_cosine_filter_0_0.set_taps(firdes.root_raised_cosine(1, self.samp_rate/self.bb_decim/self.audio_decim, 2375, 1, 100))

    def get_bb_decim(self):
        return self.bb_decim

    def set_bb_decim(self, bb_decim):
        self.bb_decim = bb_decim
        self.set_baseband_rate(self.samp_rate/self.bb_decim)
        self.root_raised_cosine_filter_0_0.set_taps(firdes.root_raised_cosine(1, self.samp_rate/self.bb_decim/self.audio_decim, 2375, 1, 100))

    def get_baseband_rate(self):
        return self.baseband_rate

    def set_baseband_rate(self, baseband_rate):
        self.baseband_rate = baseband_rate
        self.set_audio_decim_rate(self.baseband_rate/self.audio_decim)
        self.freq_xlating_fir_filter_xxx_1.set_taps(firdes.low_pass(2500.0,self.baseband_rate,2.4e3,2e3,firdes.WIN_HAMMING))
        self.qtgui_waterfall_sink_x_0.set_frequency_range(0, self.baseband_rate)

    def get_audio_decim(self):
        return self.audio_decim

    def set_audio_decim(self, audio_decim):
        self.audio_decim = audio_decim
        self.set_audio_decim_rate(self.baseband_rate/self.audio_decim)
        self.root_raised_cosine_filter_0_0.set_taps(firdes.root_raised_cosine(1, self.samp_rate/self.bb_decim/self.audio_decim, 2375, 1, 100))

    def get_xlate_bandwidth(self):
        return self.xlate_bandwidth

    def set_xlate_bandwidth(self, xlate_bandwidth):
        self.xlate_bandwidth = xlate_bandwidth
        self.freq_xlating_fir_filter_xxx_0.set_taps(firdes.low_pass(1, self.samp_rate, self.xlate_bandwidth, 100000))

    def get_usrp_rate(self):
        return self.usrp_rate

    def set_usrp_rate(self, usrp_rate):
        self.usrp_rate = usrp_rate
        self.gr_frequency_modulator_fc_0.set_sensitivity(2*math.pi*self.fm_max_dev/self.usrp_rate)
        self.gr_sig_source_x_0_0.set_sampling_freq(self.usrp_rate)
        self.low_pass_filter_0.set_taps(firdes.low_pass(1, self.usrp_rate, 2.5e3, .5e3, firdes.WIN_HAMMING, 6.76))

    def get_stereo_gain(self):
        return self.stereo_gain

    def set_stereo_gain(self, stereo_gain):
        self.stereo_gain = stereo_gain

    def get_rds_gain(self):
        return self.rds_gain

    def set_rds_gain(self, rds_gain):
        self.rds_gain = rds_gain
        self.blocks_multiply_const_vxx_0_0.set_k(self.rds_gain)

    def get_outbuffer(self):
        return self.outbuffer

    def set_outbuffer(self, outbuffer):
        self.outbuffer = outbuffer

    def get_input_gain(self):
        return self.input_gain

    def set_input_gain(self, input_gain):
        self.input_gain = input_gain

    def get_freq(self):
        return self.freq

    def set_freq(self, freq):
        self.freq = freq

    def get_fm_max_dev(self):
        return self.fm_max_dev

    def set_fm_max_dev(self, fm_max_dev):
        self.fm_max_dev = fm_max_dev
        self.gr_frequency_modulator_fc_0.set_sensitivity(2*math.pi*self.fm_max_dev/self.usrp_rate)

    def get_audio_rate(self):
        return self.audio_rate

    def set_audio_rate(self, audio_rate):
        self.audio_rate = audio_rate
        self.qtgui_freq_sink_x_0.set_frequency_range(0, self.audio_rate)

    def get_audio_decim_rate(self):
        return self.audio_decim_rate

    def set_audio_decim_rate(self, audio_decim_rate):
        self.audio_decim_rate = audio_decim_rate



def main(top_block_cls=rds_loopback, options=None):

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
