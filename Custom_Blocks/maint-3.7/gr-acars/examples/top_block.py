#!/usr/bin/env python
##################################################
# Gnuradio Python Flow Graph
# Title: Top Block
# Generated: Wed May  6 08:01:52 2015
##################################################

from gnuradio import analog
from gnuradio import audio
from gnuradio import blocks
from gnuradio import eng_notation
from gnuradio import filter
from gnuradio import gr
from gnuradio import wxgui
from gnuradio.eng_option import eng_option
from gnuradio.fft import window
from gnuradio.filter import firdes
from gnuradio.wxgui import fftsink2
from gnuradio.wxgui import forms
from grc_gnuradio import wxgui as grc_wxgui
from optparse import OptionParser
import acars
import osmosdr
import wx

class top_block(grc_wxgui.top_block_gui):

    def __init__(self):
        grc_wxgui.top_block_gui.__init__(self, title="Top Block")
        _icon_path = "/usr/share/icons/hicolor/32x32/apps/gnuradio-grc.png"
        self.SetIcon(wx.Icon(_icon_path, wx.BITMAP_TYPE_ANY))

        ##################################################
        # Variables
        ##################################################
        self.samp_rate = samp_rate = 48000
        self.rf_freq = rf_freq = 131.725
        self.firdes_tap = firdes_tap = firdes.low_pass(1,samp_rate*4,80000,20000,firdes.WIN_HAMMING,6.76)
        self.ch0rfgain = ch0rfgain = 30
        self.ch0ifgain = ch0ifgain = 20
        self.audio_gain = audio_gain = 2000

        ##################################################
        # Blocks
        ##################################################
        _rf_freq_sizer = wx.BoxSizer(wx.VERTICAL)
        self._rf_freq_text_box = forms.text_box(
        	parent=self.GetWin(),
        	sizer=_rf_freq_sizer,
        	value=self.rf_freq,
        	callback=self.set_rf_freq,
        	label="rf_freq",
        	converter=forms.float_converter(),
        	proportion=0,
        )
        self._rf_freq_slider = forms.slider(
        	parent=self.GetWin(),
        	sizer=_rf_freq_sizer,
        	value=self.rf_freq,
        	callback=self.set_rf_freq,
        	minimum=88,
        	maximum=150,
        	num_steps=100,
        	style=wx.SL_HORIZONTAL,
        	cast=float,
        	proportion=1,
        )
        self.Add(_rf_freq_sizer)
        _ch0rfgain_sizer = wx.BoxSizer(wx.VERTICAL)
        self._ch0rfgain_text_box = forms.text_box(
        	parent=self.GetWin(),
        	sizer=_ch0rfgain_sizer,
        	value=self.ch0rfgain,
        	callback=self.set_ch0rfgain,
        	label="ch0rfgain",
        	converter=forms.float_converter(),
        	proportion=0,
        )
        self._ch0rfgain_slider = forms.slider(
        	parent=self.GetWin(),
        	sizer=_ch0rfgain_sizer,
        	value=self.ch0rfgain,
        	callback=self.set_ch0rfgain,
        	minimum=0,
        	maximum=50,
        	num_steps=100,
        	style=wx.SL_HORIZONTAL,
        	cast=float,
        	proportion=1,
        )
        self.Add(_ch0rfgain_sizer)
        _audio_gain_sizer = wx.BoxSizer(wx.VERTICAL)
        self._audio_gain_text_box = forms.text_box(
        	parent=self.GetWin(),
        	sizer=_audio_gain_sizer,
        	value=self.audio_gain,
        	callback=self.set_audio_gain,
        	label="audio_gain",
        	converter=forms.float_converter(),
        	proportion=0,
        )
        self._audio_gain_slider = forms.slider(
        	parent=self.GetWin(),
        	sizer=_audio_gain_sizer,
        	value=self.audio_gain,
        	callback=self.set_audio_gain,
        	minimum=0,
        	maximum=20000,
        	num_steps=100,
        	style=wx.SL_HORIZONTAL,
        	cast=float,
        	proportion=1,
        )
        self.Add(_audio_gain_sizer)
        self.wxgui_fftsink2_0 = fftsink2.fft_sink_c(
        	self.GetWin(),
        	baseband_freq=0,
        	y_per_div=10,
        	y_divs=10,
        	ref_level=0,
        	ref_scale=2.0,
        	sample_rate=samp_rate*24,
        	fft_size=1024,
        	fft_rate=15,
        	average=False,
        	avg_alpha=None,
        	title="FFT Plot",
        	peak_hold=False,
        )
        self.Add(self.wxgui_fftsink2_0.win)
        self.osmosdr_source_0 = osmosdr.source( args="numchan=" + str(1) + " " + "" )
        self.osmosdr_source_0.set_sample_rate(samp_rate*24)
        self.osmosdr_source_0.set_center_freq(rf_freq*1e6, 0)
        self.osmosdr_source_0.set_freq_corr(0, 0)
        self.osmosdr_source_0.set_dc_offset_mode(0, 0)
        self.osmosdr_source_0.set_iq_balance_mode(0, 0)
        self.osmosdr_source_0.set_gain_mode(False, 0)
        self.osmosdr_source_0.set_gain(ch0rfgain, 0)
        self.osmosdr_source_0.set_if_gain(20, 0)
        self.osmosdr_source_0.set_bb_gain(20, 0)
        self.osmosdr_source_0.set_antenna("", 0)
        self.osmosdr_source_0.set_bandwidth(0, 0)
          
        self.low_pass_filter_0 = filter.fir_filter_ccf(6, firdes.low_pass(
        	2, samp_rate*24, 500000, 150000, firdes.WIN_HAMMING, 6.76))
        _ch0ifgain_sizer = wx.BoxSizer(wx.VERTICAL)
        self._ch0ifgain_text_box = forms.text_box(
        	parent=self.GetWin(),
        	sizer=_ch0ifgain_sizer,
        	value=self.ch0ifgain,
        	callback=self.set_ch0ifgain,
        	label="ch0ifgain",
        	converter=forms.float_converter(),
        	proportion=0,
        )
        self._ch0ifgain_slider = forms.slider(
        	parent=self.GetWin(),
        	sizer=_ch0ifgain_sizer,
        	value=self.ch0ifgain,
        	callback=self.set_ch0ifgain,
        	minimum=0,
        	maximum=50,
        	num_steps=100,
        	style=wx.SL_HORIZONTAL,
        	cast=float,
        	proportion=1,
        )
        self.Add(_ch0ifgain_sizer)
        self.blocks_multiply_const_vxx_0 = blocks.multiply_const_vff((audio_gain, ))
        self.audio_sink_0 = audio.sink(samp_rate, "hw:0", True)
        self.analog_am_demod_cf_0 = analog.am_demod_cf(
        	channel_rate=samp_rate*4,
        	audio_decim=4,
        	audio_pass=5000,
        	audio_stop=8500,
        )
        self.acars_decodeur_0 = acars.acars(150,"/tmp/acars.log")

        ##################################################
        # Connections
        ##################################################
        self.connect((self.osmosdr_source_0, 0), (self.low_pass_filter_0, 0))
        self.connect((self.analog_am_demod_cf_0, 0), (self.audio_sink_0, 0))
        self.connect((self.analog_am_demod_cf_0, 0), (self.blocks_multiply_const_vxx_0, 0))
        self.connect((self.low_pass_filter_0, 0), (self.analog_am_demod_cf_0, 0))
        self.connect((self.osmosdr_source_0, 0), (self.wxgui_fftsink2_0, 0))
        self.connect((self.blocks_multiply_const_vxx_0, 0), (self.acars_decodeur_0, 0))



    def get_samp_rate(self):
        return self.samp_rate

    def set_samp_rate(self, samp_rate):
        self.samp_rate = samp_rate
        self.set_firdes_tap(firdes.low_pass(1,self.samp_rate*4,80000,20000,firdes.WIN_HAMMING,6.76))
        self.osmosdr_source_0.set_sample_rate(self.samp_rate*24)
        self.wxgui_fftsink2_0.set_sample_rate(self.samp_rate*24)
        self.low_pass_filter_0.set_taps(firdes.low_pass(2, self.samp_rate*24, 500000, 150000, firdes.WIN_HAMMING, 6.76))

    def get_rf_freq(self):
        return self.rf_freq

    def set_rf_freq(self, rf_freq):
        self.rf_freq = rf_freq
        self.osmosdr_source_0.set_center_freq(self.rf_freq*1e6, 0)
        self._rf_freq_slider.set_value(self.rf_freq)
        self._rf_freq_text_box.set_value(self.rf_freq)

    def get_firdes_tap(self):
        return self.firdes_tap

    def set_firdes_tap(self, firdes_tap):
        self.firdes_tap = firdes_tap

    def get_ch0rfgain(self):
        return self.ch0rfgain

    def set_ch0rfgain(self, ch0rfgain):
        self.ch0rfgain = ch0rfgain
        self.osmosdr_source_0.set_gain(self.ch0rfgain, 0)
        self._ch0rfgain_slider.set_value(self.ch0rfgain)
        self._ch0rfgain_text_box.set_value(self.ch0rfgain)

    def get_ch0ifgain(self):
        return self.ch0ifgain

    def set_ch0ifgain(self, ch0ifgain):
        self.ch0ifgain = ch0ifgain
        self._ch0ifgain_slider.set_value(self.ch0ifgain)
        self._ch0ifgain_text_box.set_value(self.ch0ifgain)

    def get_audio_gain(self):
        return self.audio_gain

    def set_audio_gain(self, audio_gain):
        self.audio_gain = audio_gain
        self._audio_gain_slider.set_value(self.audio_gain)
        self._audio_gain_text_box.set_value(self.audio_gain)
        self.blocks_multiply_const_vxx_0.set_k((self.audio_gain, ))

if __name__ == '__main__':
    import ctypes
    import sys
    if sys.platform.startswith('linux'):
        try:
            x11 = ctypes.cdll.LoadLibrary('libX11.so')
            x11.XInitThreads()
        except:
            print "Warning: failed to XInitThreads()"
    parser = OptionParser(option_class=eng_option, usage="%prog: [options]")
    (options, args) = parser.parse_args()
    tb = top_block()
    tb.Start(True)
    tb.Wait()
