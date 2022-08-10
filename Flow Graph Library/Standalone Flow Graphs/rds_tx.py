#!/usr/bin/env python2
# -*- coding: utf-8 -*-
##################################################
# GNU Radio Python Flow Graph
# Title: Rds Tx
# Generated: Wed Nov  4 14:10:46 2020
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
from gnuradio import blocks
from gnuradio import digital
from gnuradio import eng_notation
from gnuradio import filter
from gnuradio import gr
from gnuradio import uhd
from gnuradio.eng_option import eng_option
from gnuradio.filter import firdes
from gnuradio.wxgui import forms
from grc_gnuradio import wxgui as grc_wxgui
from optparse import OptionParser
import math
import rds
import time
import wx


class rds_tx(grc_wxgui.top_block_gui):

    def __init__(self):
        grc_wxgui.top_block_gui.__init__(self, title="Rds Tx")
        _icon_path = "/usr/share/icons/hicolor/32x32/apps/gnuradio-grc.png"
        self.SetIcon(wx.Icon(_icon_path, wx.BITMAP_TYPE_ANY))

        ##################################################
        # Variables
        ##################################################
        self.usrp_rate = usrp_rate = 19e3*20
        self.test = test = 57e3
        self.stereo_gain = stereo_gain = .3
        self.rds_gain = rds_gain = .5
        self.ps = ps = "WDR 3"
        self.pilot_gain = pilot_gain = .3
        self.outbuffer = outbuffer = 10
        self.input_gain = input_gain = .3
        self.freq = freq = 106.5e6
        self.fm_max_dev = fm_max_dev = 80e3

        ##################################################
        # Blocks
        ##################################################
        _test_sizer = wx.BoxSizer(wx.VERTICAL)
        self._test_text_box = forms.text_box(
        	parent=self.GetWin(),
        	sizer=_test_sizer,
        	value=self.test,
        	callback=self.set_test,
        	label='test',
        	converter=forms.float_converter(),
        	proportion=0,
        )
        self._test_slider = forms.slider(
        	parent=self.GetWin(),
        	sizer=_test_sizer,
        	value=self.test,
        	callback=self.set_test,
        	minimum=55e3,
        	maximum=59e3,
        	num_steps=100,
        	style=wx.SL_HORIZONTAL,
        	cast=float,
        	proportion=1,
        )
        self.Add(_test_sizer)
        _rds_gain_sizer = wx.BoxSizer(wx.VERTICAL)
        self._rds_gain_text_box = forms.text_box(
        	parent=self.GetWin(),
        	sizer=_rds_gain_sizer,
        	value=self.rds_gain,
        	callback=self.set_rds_gain,
        	label='rds_gain',
        	converter=forms.float_converter(),
        	proportion=0,
        )
        self._rds_gain_slider = forms.slider(
        	parent=self.GetWin(),
        	sizer=_rds_gain_sizer,
        	value=self.rds_gain,
        	callback=self.set_rds_gain,
        	minimum=0,
        	maximum=3,
        	num_steps=100,
        	style=wx.SL_HORIZONTAL,
        	cast=float,
        	proportion=1,
        )
        self.Add(_rds_gain_sizer)
        self._ps_text_box = forms.text_box(
        	parent=self.GetWin(),
        	value=self.ps,
        	callback=self.set_ps,
        	label="PS",
        	converter=forms.str_converter(),
        )
        self.Add(self._ps_text_box)
        _pilot_gain_sizer = wx.BoxSizer(wx.VERTICAL)
        self._pilot_gain_text_box = forms.text_box(
        	parent=self.GetWin(),
        	sizer=_pilot_gain_sizer,
        	value=self.pilot_gain,
        	callback=self.set_pilot_gain,
        	label='pilot_gain',
        	converter=forms.float_converter(),
        	proportion=0,
        )
        self._pilot_gain_slider = forms.slider(
        	parent=self.GetWin(),
        	sizer=_pilot_gain_sizer,
        	value=self.pilot_gain,
        	callback=self.set_pilot_gain,
        	minimum=0,
        	maximum=3,
        	num_steps=100,
        	style=wx.SL_HORIZONTAL,
        	cast=float,
        	proportion=1,
        )
        self.Add(_pilot_gain_sizer)
        _input_gain_sizer = wx.BoxSizer(wx.VERTICAL)
        self._input_gain_text_box = forms.text_box(
        	parent=self.GetWin(),
        	sizer=_input_gain_sizer,
        	value=self.input_gain,
        	callback=self.set_input_gain,
        	label='input_gain',
        	converter=forms.float_converter(),
        	proportion=0,
        )
        self._input_gain_slider = forms.slider(
        	parent=self.GetWin(),
        	sizer=_input_gain_sizer,
        	value=self.input_gain,
        	callback=self.set_input_gain,
        	minimum=0,
        	maximum=10,
        	num_steps=100,
        	style=wx.SL_HORIZONTAL,
        	cast=float,
        	proportion=1,
        )
        self.Add(_input_gain_sizer)
        self.uhd_usrp_sink_0 = uhd.usrp_sink(
        	",".join(("", "")),
        	uhd.stream_args(
        		cpu_format="fc32",
        		channels=range(1),
        	),
        )
        self.uhd_usrp_sink_0.set_subdev_spec("A:A", 0)
        self.uhd_usrp_sink_0.set_samp_rate(1e6)
        self.uhd_usrp_sink_0.set_center_freq(freq, 0)
        self.uhd_usrp_sink_0.set_gain(60, 0)
        self.uhd_usrp_sink_0.set_antenna("TX/RX", 0)
        _stereo_gain_sizer = wx.BoxSizer(wx.VERTICAL)
        self._stereo_gain_text_box = forms.text_box(
        	parent=self.GetWin(),
        	sizer=_stereo_gain_sizer,
        	value=self.stereo_gain,
        	callback=self.set_stereo_gain,
        	label='stereo_gain',
        	converter=forms.float_converter(),
        	proportion=0,
        )
        self._stereo_gain_slider = forms.slider(
        	parent=self.GetWin(),
        	sizer=_stereo_gain_sizer,
        	value=self.stereo_gain,
        	callback=self.set_stereo_gain,
        	minimum=0,
        	maximum=3,
        	num_steps=100,
        	style=wx.SL_HORIZONTAL,
        	cast=float,
        	proportion=1,
        )
        self.Add(_stereo_gain_sizer)
        self.low_pass_filter_0 = filter.interp_fir_filter_fff(1, firdes.low_pass(
        	1, usrp_rate, 2.5e3, .5e3, firdes.WIN_HAMMING, 6.76))
        (self.low_pass_filter_0).set_max_output_buffer(10)
        self.gr_unpack_k_bits_bb_0 = blocks.unpack_k_bits_bb(2)
        (self.gr_unpack_k_bits_bb_0).set_max_output_buffer(10)
        self.gr_sub_xx_0 = blocks.sub_ff(1)
        self.gr_sig_source_x_0_1 = analog.sig_source_f(usrp_rate, analog.GR_SIN_WAVE, 19e3, 1, 0)
        self.gr_sig_source_x_0_0 = analog.sig_source_f(usrp_rate, analog.GR_SIN_WAVE, test, 1, 0)
        self.gr_sig_source_x_0 = analog.sig_source_f(usrp_rate, analog.GR_SIN_WAVE, 38e3, 1, 0)
        self.gr_rds_encoder_0 = rds.encoder(1, 14, True, ps, 89.8e6,
        			True, False, 13, 3,
        			147, "Happy Birthday Karen")
        	
        (self.gr_rds_encoder_0).set_max_output_buffer(10)
        self.gr_multiply_xx_1 = blocks.multiply_vff(1)
        self.gr_multiply_xx_0 = blocks.multiply_vff(1)
        (self.gr_multiply_xx_0).set_max_output_buffer(10)
        self.gr_map_bb_1 = digital.map_bb(([1,2]))
        (self.gr_map_bb_1).set_max_output_buffer(10)
        self.gr_map_bb_0 = digital.map_bb(([-1,1]))
        (self.gr_map_bb_0).set_max_output_buffer(10)
        self.gr_frequency_modulator_fc_0 = analog.frequency_modulator_fc(2*math.pi*fm_max_dev/usrp_rate)
        (self.gr_frequency_modulator_fc_0).set_max_output_buffer(10)
        self.gr_diff_encoder_bb_0 = digital.diff_encoder_bb(2)
        (self.gr_diff_encoder_bb_0).set_max_output_buffer(10)
        self.gr_char_to_float_0 = blocks.char_to_float(1, 1)
        (self.gr_char_to_float_0).set_max_output_buffer(10)
        self.gr_add_xx_1 = blocks.add_vff(1)
        (self.gr_add_xx_1).set_max_output_buffer(10)
        self.gr_add_xx_0 = blocks.add_vff(1)
        self.fractional_resampler_xx_0_0_0 = filter.fractional_resampler_cc(0, 38/100.0)
        self.fractional_resampler_xx_0_0 = filter.fractional_resampler_ff(0, 44.1/380)
        self.fractional_resampler_xx_0 = filter.fractional_resampler_ff(0, 44.1/380)
        self.blocks_repeat_0 = blocks.repeat(gr.sizeof_float*1, 160)
        self.blocks_pack_k_bits_bb_0 = blocks.pack_k_bits_bb(8)
        self.blocks_null_source_0 = blocks.null_source(gr.sizeof_float*1)
        self.blocks_multiply_const_vxx_0_1 = blocks.multiply_const_vff((input_gain, ))
        self.blocks_multiply_const_vxx_0_0_1 = blocks.multiply_const_vff((pilot_gain, ))
        self.blocks_multiply_const_vxx_0_0 = blocks.multiply_const_vff((rds_gain, ))
        (self.blocks_multiply_const_vxx_0_0).set_max_output_buffer(10)
        self.blocks_multiply_const_vxx_0 = blocks.multiply_const_vff((input_gain, ))
        self.blocks_head_0 = blocks.head(gr.sizeof_char*1, 13*100)
        self.blocks_file_sink_0 = blocks.file_sink(gr.sizeof_char*1, "/home/user/FISSURE/Crafted Packets/rdsA2.bin", False)
        self.blocks_file_sink_0.set_unbuffered(False)

        ##################################################
        # Connections
        ##################################################
        self.connect((self.blocks_head_0, 0), (self.blocks_file_sink_0, 0))    
        self.connect((self.blocks_multiply_const_vxx_0, 0), (self.fractional_resampler_xx_0, 0))    
        self.connect((self.blocks_multiply_const_vxx_0_0, 0), (self.gr_add_xx_1, 0))    
        self.connect((self.blocks_multiply_const_vxx_0_0_1, 0), (self.gr_add_xx_1, 1))    
        self.connect((self.blocks_multiply_const_vxx_0_1, 0), (self.fractional_resampler_xx_0_0, 0))    
        self.connect((self.blocks_null_source_0, 0), (self.blocks_multiply_const_vxx_0, 0))    
        self.connect((self.blocks_null_source_0, 0), (self.blocks_multiply_const_vxx_0_1, 0))    
        self.connect((self.blocks_pack_k_bits_bb_0, 0), (self.blocks_head_0, 0))    
        self.connect((self.blocks_repeat_0, 0), (self.low_pass_filter_0, 0))    
        self.connect((self.fractional_resampler_xx_0, 0), (self.gr_add_xx_0, 0))    
        self.connect((self.fractional_resampler_xx_0, 0), (self.gr_sub_xx_0, 0))    
        self.connect((self.fractional_resampler_xx_0_0, 0), (self.gr_add_xx_0, 1))    
        self.connect((self.fractional_resampler_xx_0_0, 0), (self.gr_sub_xx_0, 1))    
        self.connect((self.fractional_resampler_xx_0_0_0, 0), (self.uhd_usrp_sink_0, 0))    
        self.connect((self.gr_add_xx_0, 0), (self.gr_add_xx_1, 3))    
        self.connect((self.gr_add_xx_1, 0), (self.gr_frequency_modulator_fc_0, 0))    
        self.connect((self.gr_char_to_float_0, 0), (self.blocks_repeat_0, 0))    
        self.connect((self.gr_diff_encoder_bb_0, 0), (self.gr_map_bb_1, 0))    
        self.connect((self.gr_frequency_modulator_fc_0, 0), (self.fractional_resampler_xx_0_0_0, 0))    
        self.connect((self.gr_map_bb_0, 0), (self.gr_char_to_float_0, 0))    
        self.connect((self.gr_map_bb_1, 0), (self.gr_unpack_k_bits_bb_0, 0))    
        self.connect((self.gr_multiply_xx_0, 0), (self.blocks_multiply_const_vxx_0_0, 0))    
        self.connect((self.gr_multiply_xx_1, 0), (self.gr_add_xx_1, 2))    
        self.connect((self.gr_rds_encoder_0, 0), (self.blocks_pack_k_bits_bb_0, 0))    
        self.connect((self.gr_rds_encoder_0, 0), (self.gr_diff_encoder_bb_0, 0))    
        self.connect((self.gr_sig_source_x_0, 0), (self.gr_multiply_xx_1, 0))    
        self.connect((self.gr_sig_source_x_0_0, 0), (self.gr_multiply_xx_0, 0))    
        self.connect((self.gr_sig_source_x_0_1, 0), (self.blocks_multiply_const_vxx_0_0_1, 0))    
        self.connect((self.gr_sub_xx_0, 0), (self.gr_multiply_xx_1, 1))    
        self.connect((self.gr_unpack_k_bits_bb_0, 0), (self.gr_map_bb_0, 0))    
        self.connect((self.low_pass_filter_0, 0), (self.gr_multiply_xx_0, 1))    

    def get_usrp_rate(self):
        return self.usrp_rate

    def set_usrp_rate(self, usrp_rate):
        self.usrp_rate = usrp_rate
        self.gr_frequency_modulator_fc_0.set_sensitivity(2*math.pi*self.fm_max_dev/self.usrp_rate)
        self.gr_sig_source_x_0.set_sampling_freq(self.usrp_rate)
        self.gr_sig_source_x_0_0.set_sampling_freq(self.usrp_rate)
        self.gr_sig_source_x_0_1.set_sampling_freq(self.usrp_rate)
        self.low_pass_filter_0.set_taps(firdes.low_pass(1, self.usrp_rate, 2.5e3, .5e3, firdes.WIN_HAMMING, 6.76))

    def get_test(self):
        return self.test

    def set_test(self, test):
        self.test = test
        self._test_slider.set_value(self.test)
        self._test_text_box.set_value(self.test)
        self.gr_sig_source_x_0_0.set_frequency(self.test)

    def get_stereo_gain(self):
        return self.stereo_gain

    def set_stereo_gain(self, stereo_gain):
        self.stereo_gain = stereo_gain
        self._stereo_gain_slider.set_value(self.stereo_gain)
        self._stereo_gain_text_box.set_value(self.stereo_gain)

    def get_rds_gain(self):
        return self.rds_gain

    def set_rds_gain(self, rds_gain):
        self.rds_gain = rds_gain
        self._rds_gain_slider.set_value(self.rds_gain)
        self._rds_gain_text_box.set_value(self.rds_gain)
        self.blocks_multiply_const_vxx_0_0.set_k((self.rds_gain, ))

    def get_ps(self):
        return self.ps

    def set_ps(self, ps):
        self.ps = ps
        self._ps_text_box.set_value(self.ps)
        self.gr_rds_encoder_0.set_ps(self.ps)

    def get_pilot_gain(self):
        return self.pilot_gain

    def set_pilot_gain(self, pilot_gain):
        self.pilot_gain = pilot_gain
        self._pilot_gain_slider.set_value(self.pilot_gain)
        self._pilot_gain_text_box.set_value(self.pilot_gain)
        self.blocks_multiply_const_vxx_0_0_1.set_k((self.pilot_gain, ))

    def get_outbuffer(self):
        return self.outbuffer

    def set_outbuffer(self, outbuffer):
        self.outbuffer = outbuffer

    def get_input_gain(self):
        return self.input_gain

    def set_input_gain(self, input_gain):
        self.input_gain = input_gain
        self._input_gain_slider.set_value(self.input_gain)
        self._input_gain_text_box.set_value(self.input_gain)
        self.blocks_multiply_const_vxx_0.set_k((self.input_gain, ))
        self.blocks_multiply_const_vxx_0_1.set_k((self.input_gain, ))

    def get_freq(self):
        return self.freq

    def set_freq(self, freq):
        self.freq = freq
        self.uhd_usrp_sink_0.set_center_freq(self.freq, 0)

    def get_fm_max_dev(self):
        return self.fm_max_dev

    def set_fm_max_dev(self, fm_max_dev):
        self.fm_max_dev = fm_max_dev
        self.gr_frequency_modulator_fc_0.set_sensitivity(2*math.pi*self.fm_max_dev/self.usrp_rate)


def main(top_block_cls=rds_tx, options=None):

    tb = top_block_cls()
    tb.Start(True)
    tb.Wait()


if __name__ == '__main__':
    main()
