#!/usr/bin/env python2
# -*- coding: utf-8 -*-
##################################################
# GNU Radio Python Flow Graph
# Title: Acars Demo
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
from gnuradio import analog
from gnuradio import audio
from gnuradio import blocks
from gnuradio import eng_notation
from gnuradio import filter
from gnuradio import gr
from gnuradio import qtgui
from gnuradio import uhd
from gnuradio.eng_option import eng_option
from gnuradio.filter import firdes
from gnuradio.qtgui import Range, RangeWidget
from optparse import OptionParser
import acars
import sip
import sys
import time
from gnuradio import qtgui


class acars_demo(gr.top_block, Qt.QWidget):

    def __init__(self):
        gr.top_block.__init__(self, "Acars Demo")
        Qt.QWidget.__init__(self)
        self.setWindowTitle("Acars Demo")
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

        self.settings = Qt.QSettings("GNU Radio", "acars_demo")
        self.restoreGeometry(self.settings.value("geometry", type=QtCore.QByteArray))


        ##################################################
        # Variables
        ##################################################
        self.samp_rate = samp_rate = 48000
        self.rf_freq = rf_freq = 131.550
        self.ch0rfgain = ch0rfgain = 35
        self.audio_gain = audio_gain = 3200

        ##################################################
        # Blocks
        ##################################################
        self._rf_freq_options = (131.725, 131.450, 131.550, )
        self._rf_freq_labels = ('Europe', 'Japan', 'worlwide', )
        self._rf_freq_tool_bar = Qt.QToolBar(self)
        self._rf_freq_tool_bar.addWidget(Qt.QLabel("rf_freq"+": "))
        self._rf_freq_combo_box = Qt.QComboBox()
        self._rf_freq_tool_bar.addWidget(self._rf_freq_combo_box)
        for label in self._rf_freq_labels: self._rf_freq_combo_box.addItem(label)
        self._rf_freq_callback = lambda i: Qt.QMetaObject.invokeMethod(self._rf_freq_combo_box, "setCurrentIndex", Qt.Q_ARG("int", self._rf_freq_options.index(i)))
        self._rf_freq_callback(self.rf_freq)
        self._rf_freq_combo_box.currentIndexChanged.connect(
        	lambda i: self.set_rf_freq(self._rf_freq_options[i]))
        self.top_grid_layout.addWidget(self._rf_freq_tool_bar)
        self._audio_gain_range = Range(0, 20000, 1, 3200, 200)
        self._audio_gain_win = RangeWidget(self._audio_gain_range, self.set_audio_gain, "audio_gain", "counter_slider", float)
        self.top_grid_layout.addWidget(self._audio_gain_win)
        self.uhd_usrp_source_0 = uhd.usrp_source(
        	",".join(("", "")),
        	uhd.stream_args(
        		cpu_format="fc32",
        		channels=range(1),
        	),
        )
        self.uhd_usrp_source_0.set_samp_rate(samp_rate*20*2)
        self.uhd_usrp_source_0.set_center_freq(rf_freq*1e6, 0)
        self.uhd_usrp_source_0.set_gain(75, 0)
        self.uhd_usrp_source_0.set_antenna('TX/RX', 0)
        self.uhd_usrp_source_0.set_auto_dc_offset(True, 0)
        self.uhd_usrp_source_0.set_auto_iq_balance(True, 0)
        self.qtgui_freq_sink_x_0 = qtgui.freq_sink_c(
        	1024, #size
        	firdes.WIN_BLACKMAN_hARRIS, #wintype
        	rf_freq*1e6, #fc
        	samp_rate*20*2, #bw
        	"", #name
        	1 #number of inputs
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

        if not True:
          self.qtgui_freq_sink_x_0.disable_legend()

        if "complex" == "float" or "complex" == "msg_float":
          self.qtgui_freq_sink_x_0.set_plot_pos_half(not True)

        labels = ['', '', '', '', '',
                  '', '', '', '', '']
        widths = [1, 1, 1, 1, 1,
                  1, 1, 1, 1, 1]
        colors = ["blue", "red", "green", "black", "cyan",
                  "magenta", "yellow", "dark red", "dark green", "dark blue"]
        alphas = [1.0, 1.0, 1.0, 1.0, 1.0,
                  1.0, 1.0, 1.0, 1.0, 1.0]
        for i in xrange(1):
            if len(labels[i]) == 0:
                self.qtgui_freq_sink_x_0.set_line_label(i, "Data {0}".format(i))
            else:
                self.qtgui_freq_sink_x_0.set_line_label(i, labels[i])
            self.qtgui_freq_sink_x_0.set_line_width(i, widths[i])
            self.qtgui_freq_sink_x_0.set_line_color(i, colors[i])
            self.qtgui_freq_sink_x_0.set_line_alpha(i, alphas[i])

        self._qtgui_freq_sink_x_0_win = sip.wrapinstance(self.qtgui_freq_sink_x_0.pyqwidget(), Qt.QWidget)
        self.top_grid_layout.addWidget(self._qtgui_freq_sink_x_0_win)
        self.low_pass_filter_0_0 = filter.fir_filter_ccf(10, firdes.low_pass(
        	2, samp_rate*20*2, 150000, 150000, firdes.WIN_HAMMING, 6.76))
        self._ch0rfgain_range = Range(0, 39, 1, 35, 200)
        self._ch0rfgain_win = RangeWidget(self._ch0rfgain_range, self.set_ch0rfgain, "ch0rfgain", "counter_slider", float)
        self.top_grid_layout.addWidget(self._ch0rfgain_win)
        self.blocks_multiply_const_vxx_0 = blocks.multiply_const_vff((audio_gain, ))
        self.audio_sink_0 = audio.sink(samp_rate, '', True)
        self.analog_am_demod_cf_0 = analog.am_demod_cf(
        	channel_rate=samp_rate*2*2,
        	audio_decim=4,
        	audio_pass=5000,
        	audio_stop=8500,
        )
        self.acars_decodeur_0 = acars.acars(150,'/tmp/acars.log')



        ##################################################
        # Connections
        ##################################################
        self.connect((self.analog_am_demod_cf_0, 0), (self.audio_sink_0, 0))
        self.connect((self.analog_am_demod_cf_0, 0), (self.blocks_multiply_const_vxx_0, 0))
        self.connect((self.blocks_multiply_const_vxx_0, 0), (self.acars_decodeur_0, 0))
        self.connect((self.low_pass_filter_0_0, 0), (self.analog_am_demod_cf_0, 0))
        self.connect((self.uhd_usrp_source_0, 0), (self.low_pass_filter_0_0, 0))
        self.connect((self.uhd_usrp_source_0, 0), (self.qtgui_freq_sink_x_0, 0))

    def closeEvent(self, event):
        self.settings = Qt.QSettings("GNU Radio", "acars_demo")
        self.settings.setValue("geometry", self.saveGeometry())
        event.accept()

    def get_samp_rate(self):
        return self.samp_rate

    def set_samp_rate(self, samp_rate):
        self.samp_rate = samp_rate
        self.uhd_usrp_source_0.set_samp_rate(self.samp_rate*20*2)
        self.qtgui_freq_sink_x_0.set_frequency_range(self.rf_freq*1e6, self.samp_rate*20*2)
        self.low_pass_filter_0_0.set_taps(firdes.low_pass(2, self.samp_rate*20*2, 150000, 150000, firdes.WIN_HAMMING, 6.76))

    def get_rf_freq(self):
        return self.rf_freq

    def set_rf_freq(self, rf_freq):
        self.rf_freq = rf_freq
        self._rf_freq_callback(self.rf_freq)
        self.uhd_usrp_source_0.set_center_freq(self.rf_freq*1e6, 0)
        self.qtgui_freq_sink_x_0.set_frequency_range(self.rf_freq*1e6, self.samp_rate*20*2)

    def get_ch0rfgain(self):
        return self.ch0rfgain

    def set_ch0rfgain(self, ch0rfgain):
        self.ch0rfgain = ch0rfgain

    def get_audio_gain(self):
        return self.audio_gain

    def set_audio_gain(self, audio_gain):
        self.audio_gain = audio_gain
        self.blocks_multiply_const_vxx_0.set_k((self.audio_gain, ))


def main(top_block_cls=acars_demo, options=None):

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
