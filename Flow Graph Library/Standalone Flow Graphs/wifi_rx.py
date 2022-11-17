#!/usr/bin/env python2
# -*- coding: utf-8 -*-
##################################################
# GNU Radio Python Flow Graph
# Title: Wifi Rx
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
from gnuradio import blocks
from gnuradio import eng_notation
from gnuradio import fft
from gnuradio import gr
from gnuradio import qtgui
from gnuradio import uhd
from gnuradio.eng_option import eng_option
from gnuradio.fft import window
from gnuradio.filter import firdes
from gnuradio.qtgui import Range, RangeWidget
from optparse import OptionParser
import foo
import ieee802_11
import sip
import sys
import time
from gnuradio import qtgui


class wifi_rx(gr.top_block, Qt.QWidget):

    def __init__(self):
        gr.top_block.__init__(self, "Wifi Rx")
        Qt.QWidget.__init__(self)
        self.setWindowTitle("Wifi Rx")
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

        self.settings = Qt.QSettings("GNU Radio", "wifi_rx")
        self.restoreGeometry(self.settings.value("geometry", type=QtCore.QByteArray))


        ##################################################
        # Variables
        ##################################################
        self.window_size = window_size = 48
        self.sync_length = sync_length = 320
        self.samp_rate = samp_rate = 20e6
        self.lo_offset = lo_offset = 0
        self.gain = gain = 0.75
        self.freq = freq = 5175000000.0
        self.chan_est = chan_est = 0

        ##################################################
        # Blocks
        ##################################################
        self._samp_rate_options = [5e6, 10e6, 20e6]
        self._samp_rate_labels = ["5 MHz", "10 MHz", "20 MHz"]
        self._samp_rate_tool_bar = Qt.QToolBar(self)
        self._samp_rate_tool_bar.addWidget(Qt.QLabel("samp_rate"+": "))
        self._samp_rate_combo_box = Qt.QComboBox()
        self._samp_rate_tool_bar.addWidget(self._samp_rate_combo_box)
        for label in self._samp_rate_labels: self._samp_rate_combo_box.addItem(label)
        self._samp_rate_callback = lambda i: Qt.QMetaObject.invokeMethod(self._samp_rate_combo_box, "setCurrentIndex", Qt.Q_ARG("int", self._samp_rate_options.index(i)))
        self._samp_rate_callback(self.samp_rate)
        self._samp_rate_combo_box.currentIndexChanged.connect(
        	lambda i: self.set_samp_rate(self._samp_rate_options[i]))
        self.top_grid_layout.addWidget(self._samp_rate_tool_bar)
        self._lo_offset_options = (0, 6e6, 11e6, )
        self._lo_offset_labels = (str(self._lo_offset_options[0]), str(self._lo_offset_options[1]), str(self._lo_offset_options[2]), )
        self._lo_offset_tool_bar = Qt.QToolBar(self)
        self._lo_offset_tool_bar.addWidget(Qt.QLabel("lo_offset"+": "))
        self._lo_offset_combo_box = Qt.QComboBox()
        self._lo_offset_tool_bar.addWidget(self._lo_offset_combo_box)
        for label in self._lo_offset_labels: self._lo_offset_combo_box.addItem(label)
        self._lo_offset_callback = lambda i: Qt.QMetaObject.invokeMethod(self._lo_offset_combo_box, "setCurrentIndex", Qt.Q_ARG("int", self._lo_offset_options.index(i)))
        self._lo_offset_callback(self.lo_offset)
        self._lo_offset_combo_box.currentIndexChanged.connect(
        	lambda i: self.set_lo_offset(self._lo_offset_options[i]))
        self.top_grid_layout.addWidget(self._lo_offset_tool_bar)
        self._gain_range = Range(0, 1, 0.01, 0.75, 200)
        self._gain_win = RangeWidget(self._gain_range, self.set_gain, "gain", "counter_slider", float)
        self.top_grid_layout.addWidget(self._gain_win)
        self._freq_options = [5175000000.0, 2412000000.0, 2417000000.0, 2422000000.0, 2427000000.0, 2432000000.0, 2437000000.0, 2442000000.0, 2447000000.0, 2452000000.0, 2457000000.0, 2462000000.0, 2467000000.0, 2472000000.0, 2484000000.0, 5170000000.0, 5180000000.0, 5190000000.0, 5200000000.0, 5210000000.0, 5220000000.0, 5230000000.0, 5240000000.0, 5250000000.0, 5260000000.0, 5270000000.0, 5280000000.0, 5290000000.0, 5300000000.0, 5310000000.0, 5320000000.0, 5500000000.0, 5510000000.0, 5520000000.0, 5530000000.0, 5540000000.0, 5550000000.0, 5560000000.0, 5570000000.0, 5580000000.0, 5590000000.0, 5600000000.0, 5610000000.0, 5620000000.0, 5630000000.0, 5640000000.0, 5660000000.0, 5670000000.0, 5680000000.0, 5690000000.0, 5700000000.0, 5710000000.0, 5720000000.0, 5745000000.0, 5755000000.0, 5765000000.0, 5775000000.0, 5785000000.0, 5795000000.0, 5805000000.0, 5825000000.0, 5860000000.0, 5870000000.0, 5880000000.0, 5890000000.0, 5900000000.0, 5910000000.0, 5920000000.0]
        self._freq_labels = ['  Custom1 | 5175', '  1 | 2412.0 | 11g', '  2 | 2417.0 | 11g', '  3 | 2422.0 | 11g', '  4 | 2427.0 | 11g', '  5 | 2432.0 | 11g', '  6 | 2437.0 | 11g', '  7 | 2442.0 | 11g', '  8 | 2447.0 | 11g', '  9 | 2452.0 | 11g', ' 10 | 2457.0 | 11g', ' 11 | 2462.0 | 11g', ' 12 | 2467.0 | 11g', ' 13 | 2472.0 | 11g', ' 14 | 2484.0 | 11g', ' 34 | 5170.0 | 11a', ' 36 | 5180.0 | 11a', ' 38 | 5190.0 | 11a', ' 40 | 5200.0 | 11a', ' 42 | 5210.0 | 11a', ' 44 | 5220.0 | 11a', ' 46 | 5230.0 | 11a', ' 48 | 5240.0 | 11a', ' 50 | 5250.0 | 11a', ' 52 | 5260.0 | 11a', ' 54 | 5270.0 | 11a', ' 56 | 5280.0 | 11a', ' 58 | 5290.0 | 11a', ' 60 | 5300.0 | 11a', ' 62 | 5310.0 | 11a', ' 64 | 5320.0 | 11a', '100 | 5500.0 | 11a', '102 | 5510.0 | 11a', '104 | 5520.0 | 11a', '106 | 5530.0 | 11a', '108 | 5540.0 | 11a', '110 | 5550.0 | 11a', '112 | 5560.0 | 11a', '114 | 5570.0 | 11a', '116 | 5580.0 | 11a', '118 | 5590.0 | 11a', '120 | 5600.0 | 11a', '122 | 5610.0 | 11a', '124 | 5620.0 | 11a', '126 | 5630.0 | 11a', '128 | 5640.0 | 11a', '132 | 5660.0 | 11a', '134 | 5670.0 | 11a', '136 | 5680.0 | 11a', '138 | 5690.0 | 11a', '140 | 5700.0 | 11a', '142 | 5710.0 | 11a', '144 | 5720.0 | 11a', '149 | 5745.0 | 11a (SRD)', '151 | 5755.0 | 11a (SRD)', '153 | 5765.0 | 11a (SRD)', '155 | 5775.0 | 11a (SRD)', '157 | 5785.0 | 11a (SRD)', '159 | 5795.0 | 11a (SRD)', '161 | 5805.0 | 11a (SRD)', '165 | 5825.0 | 11a (SRD)', '172 | 5860.0 | 11p', '174 | 5870.0 | 11p', '176 | 5880.0 | 11p', '178 | 5890.0 | 11p', '180 | 5900.0 | 11p', '182 | 5910.0 | 11p', '184 | 5920.0 | 11p']
        self._freq_tool_bar = Qt.QToolBar(self)
        self._freq_tool_bar.addWidget(Qt.QLabel("freq"+": "))
        self._freq_combo_box = Qt.QComboBox()
        self._freq_tool_bar.addWidget(self._freq_combo_box)
        for label in self._freq_labels: self._freq_combo_box.addItem(label)
        self._freq_callback = lambda i: Qt.QMetaObject.invokeMethod(self._freq_combo_box, "setCurrentIndex", Qt.Q_ARG("int", self._freq_options.index(i)))
        self._freq_callback(self.freq)
        self._freq_combo_box.currentIndexChanged.connect(
        	lambda i: self.set_freq(self._freq_options[i]))
        self.top_grid_layout.addWidget(self._freq_tool_bar)
        self._chan_est_options = [ieee802_11.LS, ieee802_11.LMS, ieee802_11.STA, ieee802_11.COMB]
        self._chan_est_labels = ["LS", "LMS", "STA", "Linear Comb"]
        self._chan_est_group_box = Qt.QGroupBox("chan_est")
        self._chan_est_box = Qt.QHBoxLayout()
        class variable_chooser_button_group(Qt.QButtonGroup):
            def __init__(self, parent=None):
                Qt.QButtonGroup.__init__(self, parent)
            @pyqtSlot(int)
            def updateButtonChecked(self, button_id):
                self.button(button_id).setChecked(True)
        self._chan_est_button_group = variable_chooser_button_group()
        self._chan_est_group_box.setLayout(self._chan_est_box)
        for i, label in enumerate(self._chan_est_labels):
        	radio_button = Qt.QRadioButton(label)
        	self._chan_est_box.addWidget(radio_button)
        	self._chan_est_button_group.addButton(radio_button, i)
        self._chan_est_callback = lambda i: Qt.QMetaObject.invokeMethod(self._chan_est_button_group, "updateButtonChecked", Qt.Q_ARG("int", self._chan_est_options.index(i)))
        self._chan_est_callback(self.chan_est)
        self._chan_est_button_group.buttonClicked[int].connect(
        	lambda i: self.set_chan_est(self._chan_est_options[i]))
        self.top_grid_layout.addWidget(self._chan_est_group_box)
        self.uhd_usrp_source_0 = uhd.usrp_source(
        	",".join(('', "")),
        	uhd.stream_args(
        		cpu_format="fc32",
        		channels=range(1),
        	),
        )
        self.uhd_usrp_source_0.set_samp_rate(samp_rate)
        self.uhd_usrp_source_0.set_center_freq(uhd.tune_request(freq, rf_freq = freq - lo_offset, rf_freq_policy=uhd.tune_request.POLICY_MANUAL), 0)
        self.uhd_usrp_source_0.set_normalized_gain(gain, 0)
        self.uhd_usrp_source_0.set_antenna('TX/RX', 0)
        self.uhd_usrp_source_0.set_auto_dc_offset(True, 0)
        self.uhd_usrp_source_0.set_auto_iq_balance(True, 0)
        self.qtgui_const_sink_x_0 = qtgui.const_sink_c(
        	48*10, #size
        	"", #name
        	1 #number of inputs
        )
        self.qtgui_const_sink_x_0.set_update_time(0.10)
        self.qtgui_const_sink_x_0.set_y_axis(-2, 2)
        self.qtgui_const_sink_x_0.set_x_axis(-2, 2)
        self.qtgui_const_sink_x_0.set_trigger_mode(qtgui.TRIG_MODE_FREE, qtgui.TRIG_SLOPE_POS, 0.0, 0, "")
        self.qtgui_const_sink_x_0.enable_autoscale(False)
        self.qtgui_const_sink_x_0.enable_grid(False)
        self.qtgui_const_sink_x_0.enable_axis_labels(True)

        if not True:
          self.qtgui_const_sink_x_0.disable_legend()

        labels = ['', '', '', '', '',
                  '', '', '', '', '']
        widths = [1, 1, 1, 1, 1,
                  1, 1, 1, 1, 1]
        colors = ["blue", "red", "red", "red", "red",
                  "red", "red", "red", "red", "red"]
        styles = [0, 0, 0, 0, 0,
                  0, 0, 0, 0, 0]
        markers = [0, 0, 0, 0, 0,
                   0, 0, 0, 0, 0]
        alphas = [1.0, 1.0, 1.0, 1.0, 1.0,
                  1.0, 1.0, 1.0, 1.0, 1.0]
        for i in xrange(1):
            if len(labels[i]) == 0:
                self.qtgui_const_sink_x_0.set_line_label(i, "Data {0}".format(i))
            else:
                self.qtgui_const_sink_x_0.set_line_label(i, labels[i])
            self.qtgui_const_sink_x_0.set_line_width(i, widths[i])
            self.qtgui_const_sink_x_0.set_line_color(i, colors[i])
            self.qtgui_const_sink_x_0.set_line_style(i, styles[i])
            self.qtgui_const_sink_x_0.set_line_marker(i, markers[i])
            self.qtgui_const_sink_x_0.set_line_alpha(i, alphas[i])

        self._qtgui_const_sink_x_0_win = sip.wrapinstance(self.qtgui_const_sink_x_0.pyqwidget(), Qt.QWidget)
        self.top_grid_layout.addWidget(self._qtgui_const_sink_x_0_win)
        self.ieee802_11_sync_short_0 = ieee802_11.sync_short(0.56, 2, False, False)
        self.ieee802_11_sync_long_0 = ieee802_11.sync_long(sync_length, True, False)
        self.ieee802_11_parse_mac_0 = ieee802_11.parse_mac(True, True)
        self.ieee802_11_moving_average_xx_1 = ieee802_11.moving_average_ff(window_size + 16)
        self.ieee802_11_moving_average_xx_0 = ieee802_11.moving_average_cc(window_size)
        self.ieee802_11_frame_equalizer_0 = ieee802_11.frame_equalizer(chan_est, freq, samp_rate, False, False)
        self.ieee802_11_decode_mac_0 = ieee802_11.decode_mac(True, False)
        self.foo_wireshark_connector_0 = foo.wireshark_connector(127, False)
        self.fft_vxx_0 = fft.fft_vcc(64, True, (window.rectangular(64)), True, 1)
        self.blocks_stream_to_vector_0 = blocks.stream_to_vector(gr.sizeof_gr_complex*1, 64)
        self.blocks_pdu_to_tagged_stream_1 = blocks.pdu_to_tagged_stream(blocks.complex_t, 'packet_len')
        self.blocks_multiply_xx_0 = blocks.multiply_vcc(1)
        self.blocks_file_sink_0 = blocks.file_sink(gr.sizeof_char*1, '/tmp/wifi.pcap', True)
        self.blocks_file_sink_0.set_unbuffered(True)
        self.blocks_divide_xx_0 = blocks.divide_ff(1)
        self.blocks_delay_0_0 = blocks.delay(gr.sizeof_gr_complex*1, 16)
        self.blocks_delay_0 = blocks.delay(gr.sizeof_gr_complex*1, sync_length)
        self.blocks_conjugate_cc_0 = blocks.conjugate_cc()
        self.blocks_complex_to_mag_squared_0 = blocks.complex_to_mag_squared(1)
        self.blocks_complex_to_mag_0 = blocks.complex_to_mag(1)



        ##################################################
        # Connections
        ##################################################
        self.msg_connect((self.ieee802_11_decode_mac_0, 'out'), (self.foo_wireshark_connector_0, 'in'))
        self.msg_connect((self.ieee802_11_decode_mac_0, 'out'), (self.ieee802_11_parse_mac_0, 'in'))
        self.msg_connect((self.ieee802_11_frame_equalizer_0, 'symbols'), (self.blocks_pdu_to_tagged_stream_1, 'pdus'))
        self.connect((self.blocks_complex_to_mag_0, 0), (self.blocks_divide_xx_0, 0))
        self.connect((self.blocks_complex_to_mag_squared_0, 0), (self.ieee802_11_moving_average_xx_1, 0))
        self.connect((self.blocks_conjugate_cc_0, 0), (self.blocks_multiply_xx_0, 1))
        self.connect((self.blocks_delay_0, 0), (self.ieee802_11_sync_long_0, 1))
        self.connect((self.blocks_delay_0_0, 0), (self.blocks_conjugate_cc_0, 0))
        self.connect((self.blocks_delay_0_0, 0), (self.ieee802_11_sync_short_0, 0))
        self.connect((self.blocks_divide_xx_0, 0), (self.ieee802_11_sync_short_0, 2))
        self.connect((self.blocks_multiply_xx_0, 0), (self.ieee802_11_moving_average_xx_0, 0))
        self.connect((self.blocks_pdu_to_tagged_stream_1, 0), (self.qtgui_const_sink_x_0, 0))
        self.connect((self.blocks_stream_to_vector_0, 0), (self.fft_vxx_0, 0))
        self.connect((self.fft_vxx_0, 0), (self.ieee802_11_frame_equalizer_0, 0))
        self.connect((self.foo_wireshark_connector_0, 0), (self.blocks_file_sink_0, 0))
        self.connect((self.ieee802_11_frame_equalizer_0, 0), (self.ieee802_11_decode_mac_0, 0))
        self.connect((self.ieee802_11_moving_average_xx_0, 0), (self.blocks_complex_to_mag_0, 0))
        self.connect((self.ieee802_11_moving_average_xx_0, 0), (self.ieee802_11_sync_short_0, 1))
        self.connect((self.ieee802_11_moving_average_xx_1, 0), (self.blocks_divide_xx_0, 1))
        self.connect((self.ieee802_11_sync_long_0, 0), (self.blocks_stream_to_vector_0, 0))
        self.connect((self.ieee802_11_sync_short_0, 0), (self.blocks_delay_0, 0))
        self.connect((self.ieee802_11_sync_short_0, 0), (self.ieee802_11_sync_long_0, 0))
        self.connect((self.uhd_usrp_source_0, 0), (self.blocks_complex_to_mag_squared_0, 0))
        self.connect((self.uhd_usrp_source_0, 0), (self.blocks_delay_0_0, 0))
        self.connect((self.uhd_usrp_source_0, 0), (self.blocks_multiply_xx_0, 0))

    def closeEvent(self, event):
        self.settings = Qt.QSettings("GNU Radio", "wifi_rx")
        self.settings.setValue("geometry", self.saveGeometry())
        event.accept()

    def get_window_size(self):
        return self.window_size

    def set_window_size(self, window_size):
        self.window_size = window_size
        self.ieee802_11_moving_average_xx_1.set_length(self.window_size + 16)
        self.ieee802_11_moving_average_xx_0.set_length(self.window_size)

    def get_sync_length(self):
        return self.sync_length

    def set_sync_length(self, sync_length):
        self.sync_length = sync_length
        self.blocks_delay_0.set_dly(self.sync_length)

    def get_samp_rate(self):
        return self.samp_rate

    def set_samp_rate(self, samp_rate):
        self.samp_rate = samp_rate
        self._samp_rate_callback(self.samp_rate)
        self.uhd_usrp_source_0.set_samp_rate(self.samp_rate)
        self.ieee802_11_frame_equalizer_0.set_bandwidth(self.samp_rate)

    def get_lo_offset(self):
        return self.lo_offset

    def set_lo_offset(self, lo_offset):
        self.lo_offset = lo_offset
        self._lo_offset_callback(self.lo_offset)
        self.uhd_usrp_source_0.set_center_freq(uhd.tune_request(self.freq, rf_freq = self.freq - self.lo_offset, rf_freq_policy=uhd.tune_request.POLICY_MANUAL), 0)

    def get_gain(self):
        return self.gain

    def set_gain(self, gain):
        self.gain = gain
        self.uhd_usrp_source_0.set_normalized_gain(self.gain, 0)


    def get_freq(self):
        return self.freq

    def set_freq(self, freq):
        self.freq = freq
        self._freq_callback(self.freq)
        self.uhd_usrp_source_0.set_center_freq(uhd.tune_request(self.freq, rf_freq = self.freq - self.lo_offset, rf_freq_policy=uhd.tune_request.POLICY_MANUAL), 0)
        self.ieee802_11_frame_equalizer_0.set_frequency(self.freq)

    def get_chan_est(self):
        return self.chan_est

    def set_chan_est(self, chan_est):
        self.chan_est = chan_est
        self._chan_est_callback(self.chan_est)
        self.ieee802_11_frame_equalizer_0.set_algorithm(self.chan_est)


def main(top_block_cls=wifi_rx, options=None):

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
