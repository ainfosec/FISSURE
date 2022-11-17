#!/usr/bin/env python2
# -*- coding: utf-8 -*-
##################################################
# GNU Radio Python Flow Graph
# Title: J2497 Demod Method1
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
from gnuradio import blocks
from gnuradio import eng_notation
from gnuradio import filter
from gnuradio import gr
from gnuradio import qtgui
from gnuradio import uhd
from gnuradio.eng_option import eng_option
from gnuradio.filter import firdes
from optparse import OptionParser
from scipy.signal import chirp
import J2497
import numpy as np
import sip
import sys
import time
from gnuradio import qtgui


class j2497_demod_method1(gr.top_block, Qt.QWidget):

    def __init__(self):
        gr.top_block.__init__(self, "J2497 Demod Method1")
        Qt.QWidget.__init__(self)
        self.setWindowTitle("J2497 Demod Method1")
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

        self.settings = Qt.QSettings("GNU Radio", "j2497_demod_method1")
        self.restoreGeometry(self.settings.value("geometry", type=QtCore.QByteArray))


        ##################################################
        # Variables
        ##################################################
        self.samp_rate = samp_rate = 1000000
        self.samples = samples = 300000
        self.chirp_section = chirp_section = np.hstack((chirp(np.linspace(0E-6,33E-6,33E-6*samp_rate),f0=203E3,f1=203E3,t1=33E-6,phi=-90,method='linear')*1))[::-1]

        ##################################################
        # Blocks
        ##################################################
        self.uhd_usrp_source_0 = uhd.usrp_source(
        	",".join(("", "")),
        	uhd.stream_args(
        		cpu_format="fc32",
        		channels=range(1),
        	),
        )
        self.uhd_usrp_source_0.set_subdev_spec("A:A", 0)
        self.uhd_usrp_source_0.set_samp_rate(samp_rate*2)
        self.uhd_usrp_source_0.set_center_freq(126e6, 0)
        self.uhd_usrp_source_0.set_gain(40, 0)
        self.uhd_usrp_source_0.set_antenna('TX/RX', 0)
        self.uhd_usrp_source_0.set_auto_dc_offset(True, 0)
        self.uhd_usrp_source_0.set_auto_iq_balance(True, 0)
        self.qtgui_time_sink_x_0_0_0_3_0 = qtgui.time_sink_f(
        	samples, #size
        	1, #samp_rate
        	"Correlation Result", #name
        	1 #number of inputs
        )
        self.qtgui_time_sink_x_0_0_0_3_0.set_update_time(0.10)
        self.qtgui_time_sink_x_0_0_0_3_0.set_y_axis(-10, 400)

        self.qtgui_time_sink_x_0_0_0_3_0.set_y_label('Amplitude', "")

        self.qtgui_time_sink_x_0_0_0_3_0.enable_tags(-1, True)
        self.qtgui_time_sink_x_0_0_0_3_0.set_trigger_mode(qtgui.TRIG_MODE_FREE, qtgui.TRIG_SLOPE_POS, 0, 15, 0, '')
        self.qtgui_time_sink_x_0_0_0_3_0.enable_autoscale(True)
        self.qtgui_time_sink_x_0_0_0_3_0.enable_grid(True)
        self.qtgui_time_sink_x_0_0_0_3_0.enable_axis_labels(True)
        self.qtgui_time_sink_x_0_0_0_3_0.enable_control_panel(False)
        self.qtgui_time_sink_x_0_0_0_3_0.enable_stem_plot(False)

        if not False:
          self.qtgui_time_sink_x_0_0_0_3_0.disable_legend()

        labels = ['', '', '', '', '',
                  '', '', '', '', '']
        widths = [1, 1, 1, 1, 1,
                  1, 1, 1, 1, 1]
        colors = ["blue", "red", "green", "black", "cyan",
                  "magenta", "yellow", "dark red", "dark green", "blue"]
        styles = [1, 1, 1, 1, 1,
                  1, 1, 1, 1, 1]
        markers = [-1, -1, -1, -1, -1,
                   -1, -1, -1, -1, -1]
        alphas = [1.0, 1.0, 1.0, 1.0, 1.0,
                  1.0, 1.0, 1.0, 1.0, 1.0]

        for i in xrange(1):
            if len(labels[i]) == 0:
                self.qtgui_time_sink_x_0_0_0_3_0.set_line_label(i, "Data {0}".format(i))
            else:
                self.qtgui_time_sink_x_0_0_0_3_0.set_line_label(i, labels[i])
            self.qtgui_time_sink_x_0_0_0_3_0.set_line_width(i, widths[i])
            self.qtgui_time_sink_x_0_0_0_3_0.set_line_color(i, colors[i])
            self.qtgui_time_sink_x_0_0_0_3_0.set_line_style(i, styles[i])
            self.qtgui_time_sink_x_0_0_0_3_0.set_line_marker(i, markers[i])
            self.qtgui_time_sink_x_0_0_0_3_0.set_line_alpha(i, alphas[i])

        self._qtgui_time_sink_x_0_0_0_3_0_win = sip.wrapinstance(self.qtgui_time_sink_x_0_0_0_3_0.pyqwidget(), Qt.QWidget)
        self.top_grid_layout.addWidget(self._qtgui_time_sink_x_0_0_0_3_0_win)
        self.freq_xlating_fir_filter_xxx_0 = filter.freq_xlating_fir_filter_ccc(2, (firdes.complex_band_pass(1, 2e6, 50e3, 450e3, 1e3)), -1e6, samp_rate*2)
        self.fir_filter_xxx_1_0 = filter.fir_filter_fff(1, (20*[0.05]))
        self.fir_filter_xxx_1_0.declare_sample_delay(0)
        self.fft_filter_xxx_0 = filter.fft_filter_ccc(1, (chirp_section), 1)
        self.fft_filter_xxx_0.declare_sample_delay(0)
        self.blocks_throttle_0 = blocks.throttle(gr.sizeof_gr_complex*1, samp_rate,True)
        self.blocks_threshold_ff_0_0 = blocks.threshold_ff(.1, 10, 0)
        self.blocks_message_debug_0 = blocks.message_debug()
        self.blocks_float_to_short_1 = blocks.float_to_short(1, 1)
        self.blocks_delay_1 = blocks.delay(gr.sizeof_float*1, 20)
        self.blocks_complex_to_mag_squared_0_0 = blocks.complex_to_mag_squared(1)
        self.blocks_burst_tagger_1 = blocks.burst_tagger(gr.sizeof_float)
        self.blocks_burst_tagger_1.set_true_tag('burst',True)
        self.blocks_burst_tagger_1.set_false_tag('burst',False)

        self.J2497_J2497_decoder_corr_0 = J2497.J2497_decoder_corr(True,6972)



        ##################################################
        # Connections
        ##################################################
        self.msg_connect((self.J2497_J2497_decoder_corr_0, 'out'), (self.blocks_message_debug_0, 'print'))
        self.connect((self.blocks_burst_tagger_1, 0), (self.J2497_J2497_decoder_corr_0, 0))
        self.connect((self.blocks_burst_tagger_1, 0), (self.qtgui_time_sink_x_0_0_0_3_0, 0))
        self.connect((self.blocks_complex_to_mag_squared_0_0, 0), (self.blocks_delay_1, 0))
        self.connect((self.blocks_complex_to_mag_squared_0_0, 0), (self.fir_filter_xxx_1_0, 0))
        self.connect((self.blocks_delay_1, 0), (self.blocks_burst_tagger_1, 0))
        self.connect((self.blocks_float_to_short_1, 0), (self.blocks_burst_tagger_1, 1))
        self.connect((self.blocks_threshold_ff_0_0, 0), (self.blocks_float_to_short_1, 0))
        self.connect((self.blocks_throttle_0, 0), (self.fft_filter_xxx_0, 0))
        self.connect((self.fft_filter_xxx_0, 0), (self.blocks_complex_to_mag_squared_0_0, 0))
        self.connect((self.fir_filter_xxx_1_0, 0), (self.blocks_threshold_ff_0_0, 0))
        self.connect((self.freq_xlating_fir_filter_xxx_0, 0), (self.blocks_throttle_0, 0))
        self.connect((self.uhd_usrp_source_0, 0), (self.freq_xlating_fir_filter_xxx_0, 0))

    def closeEvent(self, event):
        self.settings = Qt.QSettings("GNU Radio", "j2497_demod_method1")
        self.settings.setValue("geometry", self.saveGeometry())
        event.accept()

    def get_samp_rate(self):
        return self.samp_rate

    def set_samp_rate(self, samp_rate):
        self.samp_rate = samp_rate
        self.set_chirp_section(np.hstack((chirp(np.linspace(0E-6,33E-6,33E-6*self.samp_rate),f0=203E3,f1=203E3,t1=33E-6,phi=-90,method='linear')*1))[::-1])
        self.uhd_usrp_source_0.set_samp_rate(self.samp_rate*2)
        self.blocks_throttle_0.set_sample_rate(self.samp_rate)

    def get_samples(self):
        return self.samples

    def set_samples(self, samples):
        self.samples = samples

    def get_chirp_section(self):
        return self.chirp_section

    def set_chirp_section(self, chirp_section):
        self.chirp_section = chirp_section
        self.fft_filter_xxx_0.set_taps((self.chirp_section))


def main(top_block_cls=j2497_demod_method1, options=None):

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
