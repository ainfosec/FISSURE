#!/usr/bin/env python
##################################################
# Gnuradio Python Flow Graph
# Title: Ais Demod Grc
# Generated: Tue Oct  9 17:56:41 2012
##################################################

from gnuradio import digital
from gnuradio import eng_notation
from gnuradio import gr
from gnuradio.eng_option import eng_option
from gnuradio.gr import firdes
from gnuradio.wxgui import scopesink2
from grc_gnuradio import wxgui as grc_wxgui
from optparse import OptionParser
import numpy
import wx

class ais_demod_grc(grc_wxgui.top_block_gui):

	def __init__(self):
		grc_wxgui.top_block_gui.__init__(self, title="Ais Demod Grc")
		_icon_path = "/usr/share/icons/hicolor/32x32/apps/gnuradio-grc.png"
		self.SetIcon(wx.Icon(_icon_path, wx.BITMAP_TYPE_ANY))

		##################################################
		# Variables
		##################################################
		self.sps = sps = 6
		self.samp_rate = samp_rate = 100e3
		self.nfilts = nfilts = 32
		self.data_rate = data_rate = 9600

		##################################################
		# Blocks
		##################################################
		self.wxgui_scopesink2_2 = scopesink2.scope_sink_f(
			self.GetWin(),
			title="Scope Plot",
			sample_rate=samp_rate/sps,
			v_scale=0,
			v_offset=0,
			t_scale=0,
			ac_couple=False,
			xy_mode=False,
			num_inputs=1,
			trig_mode=gr.gr_TRIG_MODE_AUTO,
			y_axis_label="Counts",
		)
		self.Add(self.wxgui_scopesink2_2.win)
		self.random_source_x_0 = gr.vector_source_b(map(int, numpy.random.randint(0, 2, 1000)), True)
		self.gr_throttle_0 = gr.throttle(gr.sizeof_gr_complex*1, samp_rate*sps)
		self.gr_quadrature_demod_cf_0 = gr.quadrature_demod_cf(1)
		self.gr_map_bb_0 = gr.map_bb(([-1, 1]))
		self.digital_pfb_clock_sync_xxx_0 = digital.pfb_clock_sync_ccf(sps, 0.004, (gr.firdes.gaussian(nfilts, float(nfilts)/sps, 0.4,  int(11*nfilts*sps))), nfilts, nfilts/2, 1.5, 1)
		self.digital_pfb_clock_sync_xxx_0.set_beta((0.004**2)*0.25)
		self.digital_gmskmod_bc_0 = digital.gmskmod_bc(sps, 0.4, 4)

		##################################################
		# Connections
		##################################################
		self.connect((self.gr_quadrature_demod_cf_0, 0), (self.wxgui_scopesink2_2, 0))
		self.connect((self.gr_throttle_0, 0), (self.digital_pfb_clock_sync_xxx_0, 0))
		self.connect((self.digital_gmskmod_bc_0, 0), (self.gr_throttle_0, 0))
		self.connect((self.random_source_x_0, 0), (self.gr_map_bb_0, 0))
		self.connect((self.gr_map_bb_0, 0), (self.digital_gmskmod_bc_0, 0))
		self.connect((self.digital_pfb_clock_sync_xxx_0, 0), (self.gr_quadrature_demod_cf_0, 0))

	def get_sps(self):
		return self.sps

	def set_sps(self, sps):
		self.sps = sps
		self.wxgui_scopesink2_2.set_sample_rate(self.samp_rate/self.sps)
		self.digital_pfb_clock_sync_xxx_0.set_taps((gr.firdes.gaussian(self.nfilts, float(self.nfilts)/self.sps, 0.4,  int(11*self.nfilts*self.sps))))

	def get_samp_rate(self):
		return self.samp_rate

	def set_samp_rate(self, samp_rate):
		self.samp_rate = samp_rate
		self.wxgui_scopesink2_2.set_sample_rate(self.samp_rate/self.sps)

	def get_nfilts(self):
		return self.nfilts

	def set_nfilts(self, nfilts):
		self.nfilts = nfilts
		self.digital_pfb_clock_sync_xxx_0.set_taps((gr.firdes.gaussian(self.nfilts, float(self.nfilts)/self.sps, 0.4,  int(11*self.nfilts*self.sps))))

	def get_data_rate(self):
		return self.data_rate

	def set_data_rate(self, data_rate):
		self.data_rate = data_rate

if __name__ == '__main__':
	parser = OptionParser(option_class=eng_option, usage="%prog: [options]")
	(options, args) = parser.parse_args()
	tb = ais_demod_grc()
	tb.Run(True)

