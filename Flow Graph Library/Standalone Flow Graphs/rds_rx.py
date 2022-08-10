#!/usr/bin/env python2
# -*- coding: utf-8 -*-
##################################################
# GNU Radio Python Flow Graph
# Title: Stereo FM receiver and RDS Decoder
# Generated: Fri Nov 20 22:13:47 2020
##################################################

if __name__ == '__main__':
    import ctypes
    import sys
    if sys.platform.startswith('linux'):
        try:
            x11 = ctypes.cdll.LoadLibrary('libX11.so')
            x11.XInitThreads()
        except:
            print "Warning: failed to XInitThreads()"

from gnuradio import analog
from gnuradio import audio
from gnuradio import blocks
from gnuradio import digital
from gnuradio import eng_notation
from gnuradio import filter
from gnuradio import gr
from gnuradio import wxgui
from gnuradio.eng_option import eng_option
from gnuradio.fft import window
from gnuradio.filter import firdes
from gnuradio.filter import pfb
from gnuradio.wxgui import fftsink2
from gnuradio.wxgui import forms
from gnuradio.wxgui import scopesink2
from gnuradio.wxgui import waterfallsink2
from grc_gnuradio import wxgui as grc_wxgui
from optparse import OptionParser
import math
import osmosdr
import rds
import time
import wx


class rds_rx(grc_wxgui.top_block_gui):

    def __init__(self):
        grc_wxgui.top_block_gui.__init__(self, title="Stereo FM receiver and RDS Decoder")
        _icon_path = "/usr/share/icons/hicolor/32x32/apps/gnuradio-grc.png"
        self.SetIcon(wx.Icon(_icon_path, wx.BITMAP_TYPE_ANY))

        ##################################################
        # Variables
        ##################################################
        self.freq_offset = freq_offset = 250000
        self.freq = freq = 106.5e6
        self.volume = volume = -3
        self.samp_rate = samp_rate = 2000000
        self.gain = gain = 40
        self.freq_tune = freq_tune = freq - freq_offset

        ##################################################
        # Blocks
        ##################################################
        _volume_sizer = wx.BoxSizer(wx.VERTICAL)
        self._volume_text_box = forms.text_box(
        	parent=self.GetWin(),
        	sizer=_volume_sizer,
        	value=self.volume,
        	callback=self.set_volume,
        	label="Volume",
        	converter=forms.float_converter(),
        	proportion=0,
        )
        self._volume_slider = forms.slider(
        	parent=self.GetWin(),
        	sizer=_volume_sizer,
        	value=self.volume,
        	callback=self.set_volume,
        	minimum=-20,
        	maximum=10,
        	num_steps=300,
        	style=wx.SL_HORIZONTAL,
        	cast=float,
        	proportion=1,
        )
        self.GridAdd(_volume_sizer, 0, 1, 1, 1)
        self.nb = self.nb = wx.Notebook(self.GetWin(), style=wx.NB_TOP)
        self.nb.AddPage(grc_wxgui.Panel(self.nb), "BB")
        self.nb.AddPage(grc_wxgui.Panel(self.nb), "Demod")
        self.nb.AddPage(grc_wxgui.Panel(self.nb), "Waterfall")
        self.nb.AddPage(grc_wxgui.Panel(self.nb), "L+R")
        self.nb.AddPage(grc_wxgui.Panel(self.nb), "L-R")
        self.nb.AddPage(grc_wxgui.Panel(self.nb), "RDS")
        self.nb.AddPage(grc_wxgui.Panel(self.nb), "Const")
        self.GridAdd(self.nb, 2, 0, 1, 2)
        _gain_sizer = wx.BoxSizer(wx.VERTICAL)
        self._gain_text_box = forms.text_box(
        	parent=self.GetWin(),
        	sizer=_gain_sizer,
        	value=self.gain,
        	callback=self.set_gain,
        	label="RF Gain",
        	converter=forms.float_converter(),
        	proportion=0,
        )
        self._gain_slider = forms.slider(
        	parent=self.GetWin(),
        	sizer=_gain_sizer,
        	value=self.gain,
        	callback=self.set_gain,
        	minimum=0,
        	maximum=49.6,
        	num_steps=124,
        	style=wx.SL_HORIZONTAL,
        	cast=float,
        	proportion=1,
        )
        self.GridAdd(_gain_sizer, 0, 0, 1, 1)
        _freq_sizer = wx.BoxSizer(wx.VERTICAL)
        self._freq_text_box = forms.text_box(
        	parent=self.GetWin(),
        	sizer=_freq_sizer,
        	value=self.freq,
        	callback=self.set_freq,
        	label="Freq",
        	converter=forms.float_converter(),
        	proportion=0,
        )
        self._freq_slider = forms.slider(
        	parent=self.GetWin(),
        	sizer=_freq_sizer,
        	value=self.freq,
        	callback=self.set_freq,
        	minimum=88e6,
        	maximum=108e6,
        	num_steps=200,
        	style=wx.SL_HORIZONTAL,
        	cast=float,
        	proportion=1,
        )
        self.GridAdd(_freq_sizer, 1, 0, 1, 2)
        self.wxgui_waterfallsink2_0 = waterfallsink2.waterfall_sink_f(
        	self.nb.GetPage(2).GetWin(),
        	baseband_freq=0,
        	dynamic_range=100,
        	ref_level=0,
        	ref_scale=2.0,
        	sample_rate=250000,
        	fft_size=512,
        	fft_rate=15,
        	average=False,
        	avg_alpha=None,
        	title="Waterfall Plot",
        )
        self.nb.GetPage(2).Add(self.wxgui_waterfallsink2_0.win)
        self.wxgui_scopesink2_1 = scopesink2.scope_sink_c(
        	self.nb.GetPage(6).GetWin(),
        	title="Scope Plot",
        	sample_rate=2375 * 4,
        	v_scale=0.4,
        	v_offset=0,
        	t_scale=0,
        	ac_couple=False,
        	xy_mode=True,
        	num_inputs=1,
        	trig_mode=wxgui.TRIG_MODE_AUTO,
        	y_axis_label="Counts",
        )
        self.nb.GetPage(6).Add(self.wxgui_scopesink2_1.win)
        self.wxgui_fftsink2_0_0_0_1_0_1 = fftsink2.fft_sink_c(
        	self.nb.GetPage(5).GetWin(),
        	baseband_freq=0,
        	y_per_div=10,
        	y_divs=10,
        	ref_level=0,
        	ref_scale=2.0,
        	sample_rate=19000,
        	fft_size=1024,
        	fft_rate=15,
        	average=False,
        	avg_alpha=None,
        	title="RDS",
        	peak_hold=False,
        )
        self.nb.GetPage(5).Add(self.wxgui_fftsink2_0_0_0_1_0_1.win)
        self.wxgui_fftsink2_0_0_0_1 = fftsink2.fft_sink_f(
        	self.nb.GetPage(4).GetWin(),
        	baseband_freq=0,
        	y_per_div=10,
        	y_divs=10,
        	ref_level=0,
        	ref_scale=2.0,
        	sample_rate=48000,
        	fft_size=1024,
        	fft_rate=15,
        	average=False,
        	avg_alpha=None,
        	title="L-R",
        	peak_hold=False,
        )
        self.nb.GetPage(4).Add(self.wxgui_fftsink2_0_0_0_1.win)
        self.wxgui_fftsink2_0_0_0 = fftsink2.fft_sink_f(
        	self.nb.GetPage(3).GetWin(),
        	baseband_freq=0,
        	y_per_div=10,
        	y_divs=10,
        	ref_level=0,
        	ref_scale=2.0,
        	sample_rate=48000,
        	fft_size=1024,
        	fft_rate=15,
        	average=False,
        	avg_alpha=None,
        	title="L+R",
        	peak_hold=False,
        )
        self.nb.GetPage(3).Add(self.wxgui_fftsink2_0_0_0.win)
        self.wxgui_fftsink2_0_0 = fftsink2.fft_sink_f(
        	self.nb.GetPage(1).GetWin(),
        	baseband_freq=0,
        	y_per_div=10,
        	y_divs=10,
        	ref_level=0,
        	ref_scale=2.0,
        	sample_rate=250000,
        	fft_size=1024,
        	fft_rate=15,
        	average=True,
        	avg_alpha=0.8,
        	title="FM Demod",
        	peak_hold=False,
        )
        self.nb.GetPage(1).Add(self.wxgui_fftsink2_0_0.win)
        self.wxgui_fftsink2_0 = fftsink2.fft_sink_c(
        	self.nb.GetPage(0).GetWin(),
        	baseband_freq=0,
        	y_per_div=10,
        	y_divs=10,
        	ref_level=-30,
        	ref_scale=2.0,
        	sample_rate=samp_rate,
        	fft_size=1024,
        	fft_rate=15,
        	average=True,
        	avg_alpha=0.8,
        	title="Baseband",
        	peak_hold=False,
        )
        self.nb.GetPage(0).Add(self.wxgui_fftsink2_0.win)
        self.rtlsdr_source_0_0 = osmosdr.source( args="numchan=" + str(1) + " " + "" )
        self.rtlsdr_source_0_0.set_sample_rate(samp_rate)
        self.rtlsdr_source_0_0.set_center_freq(freq_tune, 0)
        self.rtlsdr_source_0_0.set_freq_corr(0, 0)
        self.rtlsdr_source_0_0.set_dc_offset_mode(0, 0)
        self.rtlsdr_source_0_0.set_iq_balance_mode(0, 0)
        self.rtlsdr_source_0_0.set_gain_mode(False, 0)
        self.rtlsdr_source_0_0.set_gain(14, 0)
        self.rtlsdr_source_0_0.set_if_gain(24, 0)
        self.rtlsdr_source_0_0.set_bb_gain(gain, 0)
        self.rtlsdr_source_0_0.set_antenna("", 0)
        self.rtlsdr_source_0_0.set_bandwidth(0, 0)
          
        self.root_raised_cosine_filter_0 = filter.fir_filter_ccf(2, firdes.root_raised_cosine(
        	1, 19000, 2375, .35, 100))
        self.pfb_arb_resampler_xxx_1 = pfb.arb_resampler_fff(
        	  240000.0/250000,
                  taps=None,
        	  flt_size=32)
        self.pfb_arb_resampler_xxx_1.declare_sample_delay(0)
        	
        self.pfb_arb_resampler_xxx_0 = pfb.arb_resampler_ccf(
        	  19000/250e3,
                  taps=None,
        	  flt_size=32)
        self.pfb_arb_resampler_xxx_0.declare_sample_delay(0)
        	
        self.gr_rds_parser_0 = rds.parser(True, False, 0)
        self.gr_rds_panel_0 = rds.rdsPanel(freq, self.GetWin())
        self.Add(self.gr_rds_panel_0.panel)
        self.gr_rds_decoder_0 = rds.decoder(False, False)
        self.freq_xlating_fir_filter_xxx_2 = filter.freq_xlating_fir_filter_fcf(5, (firdes.low_pass(1.0,240000,13e3,3e3,firdes.WIN_HAMMING)), 38000, 240000)
        self.freq_xlating_fir_filter_xxx_1_0 = filter.freq_xlating_fir_filter_fcc(1, (firdes.low_pass(2500.0,250000,2.6e3,2e3,firdes.WIN_HAMMING)), 57e3, 250000)
        self.freq_xlating_fir_filter_xxx_0 = filter.freq_xlating_fir_filter_ccc(1, (firdes.low_pass(1, samp_rate, 80000, 20000)), freq_offset, samp_rate)
        self.fir_filter_xxx_1 = filter.fir_filter_fff(5, (firdes.low_pass(1.0,240000,13e3,3e3,firdes.WIN_HAMMING)))
        self.fir_filter_xxx_1.declare_sample_delay(0)
        self.digital_psk_demod_0 = digital.psk.psk_demod(
          constellation_points=2,
          differential=False,
          samples_per_symbol=4,
          excess_bw=0.35,
          phase_bw=6.28/100.0,
          timing_bw=6.28/100.0,
          mod_code="gray",
          verbose=False,
          log=False,
          )
        self.digital_diff_decoder_bb_0 = digital.diff_decoder_bb(2)
        self.blocks_sub_xx_0 = blocks.sub_ff(1)
        self.blocks_multiply_const_vxx_0_0 = blocks.multiply_const_vff((10**(1.*(volume)/10), ))
        self.blocks_multiply_const_vxx_0 = blocks.multiply_const_vff((10**(1.*(volume)/10), ))
        self.blocks_keep_one_in_n_0 = blocks.keep_one_in_n(gr.sizeof_char*1, 2)
        self.blocks_complex_to_real_0 = blocks.complex_to_real(1)
        self.blocks_add_xx_0 = blocks.add_vff(1)
        self.audio_sink_0 = audio.sink(48000, "", True)
        self.analog_wfm_rcv_0 = analog.wfm_rcv(
        	quad_rate=samp_rate,
        	audio_decimation=8,
        )
        self.analog_fm_deemph_0_0_0 = analog.fm_deemph(fs=48000, tau=75e-6)
        self.analog_fm_deemph_0_0 = analog.fm_deemph(fs=48000, tau=75e-6)

        ##################################################
        # Connections
        ##################################################
        self.msg_connect((self.gr_rds_decoder_0, 'out'), (self.gr_rds_parser_0, 'in'))    
        self.msg_connect((self.gr_rds_parser_0, 'out'), (self.gr_rds_panel_0, 'in'))    
        self.connect((self.analog_fm_deemph_0_0, 0), (self.blocks_multiply_const_vxx_0_0, 0))    
        self.connect((self.analog_fm_deemph_0_0_0, 0), (self.blocks_multiply_const_vxx_0, 0))    
        self.connect((self.analog_wfm_rcv_0, 0), (self.freq_xlating_fir_filter_xxx_1_0, 0))    
        self.connect((self.analog_wfm_rcv_0, 0), (self.pfb_arb_resampler_xxx_1, 0))    
        self.connect((self.analog_wfm_rcv_0, 0), (self.wxgui_fftsink2_0_0, 0))    
        self.connect((self.analog_wfm_rcv_0, 0), (self.wxgui_waterfallsink2_0, 0))    
        self.connect((self.blocks_add_xx_0, 0), (self.analog_fm_deemph_0_0_0, 0))    
        self.connect((self.blocks_complex_to_real_0, 0), (self.blocks_add_xx_0, 1))    
        self.connect((self.blocks_complex_to_real_0, 0), (self.blocks_sub_xx_0, 1))    
        self.connect((self.blocks_complex_to_real_0, 0), (self.wxgui_fftsink2_0_0_0_1, 0))    
        self.connect((self.blocks_keep_one_in_n_0, 0), (self.digital_diff_decoder_bb_0, 0))    
        self.connect((self.blocks_multiply_const_vxx_0, 0), (self.audio_sink_0, 0))    
        self.connect((self.blocks_multiply_const_vxx_0_0, 0), (self.audio_sink_0, 1))    
        self.connect((self.blocks_sub_xx_0, 0), (self.analog_fm_deemph_0_0, 0))    
        self.connect((self.digital_diff_decoder_bb_0, 0), (self.gr_rds_decoder_0, 0))    
        self.connect((self.digital_psk_demod_0, 0), (self.blocks_keep_one_in_n_0, 0))    
        self.connect((self.fir_filter_xxx_1, 0), (self.blocks_add_xx_0, 0))    
        self.connect((self.fir_filter_xxx_1, 0), (self.blocks_sub_xx_0, 0))    
        self.connect((self.fir_filter_xxx_1, 0), (self.wxgui_fftsink2_0_0_0, 0))    
        self.connect((self.freq_xlating_fir_filter_xxx_0, 0), (self.analog_wfm_rcv_0, 0))    
        self.connect((self.freq_xlating_fir_filter_xxx_0, 0), (self.wxgui_fftsink2_0, 0))    
        self.connect((self.freq_xlating_fir_filter_xxx_1_0, 0), (self.pfb_arb_resampler_xxx_0, 0))    
        self.connect((self.freq_xlating_fir_filter_xxx_2, 0), (self.blocks_complex_to_real_0, 0))    
        self.connect((self.pfb_arb_resampler_xxx_0, 0), (self.root_raised_cosine_filter_0, 0))    
        self.connect((self.pfb_arb_resampler_xxx_0, 0), (self.wxgui_fftsink2_0_0_0_1_0_1, 0))    
        self.connect((self.pfb_arb_resampler_xxx_1, 0), (self.fir_filter_xxx_1, 0))    
        self.connect((self.pfb_arb_resampler_xxx_1, 0), (self.freq_xlating_fir_filter_xxx_2, 0))    
        self.connect((self.root_raised_cosine_filter_0, 0), (self.digital_psk_demod_0, 0))    
        self.connect((self.root_raised_cosine_filter_0, 0), (self.wxgui_scopesink2_1, 0))    
        self.connect((self.rtlsdr_source_0_0, 0), (self.freq_xlating_fir_filter_xxx_0, 0))    

    def get_freq_offset(self):
        return self.freq_offset

    def set_freq_offset(self, freq_offset):
        self.freq_offset = freq_offset
        self.set_freq_tune(self.freq - self.freq_offset)
        self.freq_xlating_fir_filter_xxx_0.set_center_freq(self.freq_offset)

    def get_freq(self):
        return self.freq

    def set_freq(self, freq):
        self.freq = freq
        self._freq_slider.set_value(self.freq)
        self._freq_text_box.set_value(self.freq)
        self.set_freq_tune(self.freq - self.freq_offset)
        self.gr_rds_panel_0.set_frequency(self.freq);

    def get_volume(self):
        return self.volume

    def set_volume(self, volume):
        self.volume = volume
        self._volume_slider.set_value(self.volume)
        self._volume_text_box.set_value(self.volume)
        self.blocks_multiply_const_vxx_0.set_k((10**(1.*(self.volume)/10), ))
        self.blocks_multiply_const_vxx_0_0.set_k((10**(1.*(self.volume)/10), ))

    def get_samp_rate(self):
        return self.samp_rate

    def set_samp_rate(self, samp_rate):
        self.samp_rate = samp_rate
        self.freq_xlating_fir_filter_xxx_0.set_taps((firdes.low_pass(1, self.samp_rate, 80000, 20000)))
        self.rtlsdr_source_0_0.set_sample_rate(self.samp_rate)
        self.wxgui_fftsink2_0.set_sample_rate(self.samp_rate)

    def get_gain(self):
        return self.gain

    def set_gain(self, gain):
        self.gain = gain
        self._gain_slider.set_value(self.gain)
        self._gain_text_box.set_value(self.gain)
        self.rtlsdr_source_0_0.set_bb_gain(self.gain, 0)

    def get_freq_tune(self):
        return self.freq_tune

    def set_freq_tune(self, freq_tune):
        self.freq_tune = freq_tune
        self.rtlsdr_source_0_0.set_center_freq(self.freq_tune, 0)


def main(top_block_cls=rds_rx, options=None):

    tb = top_block_cls()
    tb.Start(True)
    tb.Wait()


if __name__ == '__main__':
    main()
