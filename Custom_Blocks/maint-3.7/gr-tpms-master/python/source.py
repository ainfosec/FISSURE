#!/usr/bin/env python

# Copyright 2014 Jared Boone <jared@sharebrained.com>
#
# This file is part of gr-tpms.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2, or (at your option)
# any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; see the file COPYING.  If not, write to
# the Free Software Foundation, Inc., 51 Franklin Street,
# Boston, MA 02110-1301, USA.
#

from gnuradio import blocks
from gnuradio import gr
from gnuradio import filter
from gnuradio.filter import firdes

class source_hackrf(gr.hier_block2):
	def __init__(self, target_frequency, if_sampling_rate):
		super(source_hackrf, self).__init__(
			"source_hackrf",
			gr.io_signature(0, 0, 0),
			gr.io_signature(1, 1, gr.sizeof_gr_complex*1),
		)

		import osmosdr

		rf_sampling_rate = 10000000
		baseband_bandwidth = 1750000
		offset_frequency = 400000		# Keep well below roll-off of baseband filter.
		rf_gain = 14			# Gains set assuming a front-end filter keeps out-of-band noise down.
		if_gain = 40
		bb_gain = 24
		if_filter_attenuation = 60

		rf_decimation, rf_decimation_remainder = divmod(rf_sampling_rate, if_sampling_rate)
		if rf_decimation_remainder != 0:
			raise RuntimeError('RF decimation must be an integer')
		rf_decimation = int(round(rf_decimation))
		tuning_frequency = target_frequency - offset_frequency

		self.source = osmosdr.source(args="numchan=1 hackrf=0")
		self.source.set_sample_rate(rf_sampling_rate)
		self.source.set_center_freq(tuning_frequency, 0)
		self.source.set_freq_corr(0, 0)
		self.source.set_dc_offset_mode(0, 0)
		self.source.set_iq_balance_mode(0, 0)
		self.source.set_gain_mode(False, 0)
		self.source.set_gain(rf_gain, 0)
		self.source.set_if_gain(if_gain, 0)
		self.source.set_bb_gain(bb_gain, 0)
		self.source.set_antenna("", 0)
		self.source.set_bandwidth(baseband_bandwidth, 0)

		if_taps = firdes.low_pass_2(1.0, rf_sampling_rate, if_sampling_rate*0.45, if_sampling_rate*0.1, if_filter_attenuation)
		self.if_filter = filter.freq_xlating_fir_filter_ccc(rf_decimation, (if_taps), offset_frequency, rf_sampling_rate)
		#self.if_filter.set_min_output_buffer(1048576)

		self.connect(self.source, self.if_filter, self)

class source_rtlsdr(gr.hier_block2):
	def __init__(self, target_frequency, if_sampling_rate):
		super(source_rtlsdr, self).__init__(
			"source_rtlsdr",
			gr.io_signature(0, 0, 0),
			gr.io_signature(1, 1, gr.sizeof_gr_complex*1),
		)

		import osmosdr

		model = 'r820t'

		rf_sampling_rate = 2400000
		if model == 'e4000':
			offset_frequency = rf_sampling_rate / 4
			rf_gain = 42			# E4000, Gains set assuming a front-end filter keeps out-of-band noise down.
		elif model == 'r820t':
			offset_frequency = 0
			rf_gain = 42.1			# R820T, Gains set assuming a front-end filter keeps out-of-band noise down.
		else:
			raise RuntimeError('Unknown RTL-SDR receiver model')
		
		if_gain = 42
		bb_gain = 20			# Not sure this has an effect on RTL-SDR.
		baseband_bandwidth = 0	# No effect on RTL-SDR?
		if_filter_attenuation = 60

		rf_decimation, rf_decimation_remainder = divmod(rf_sampling_rate, if_sampling_rate)
		if rf_decimation_remainder != 0:
			raise RuntimeError('RF decimation must be an integer')
		rf_decimation = int(round(rf_decimation))
		tuning_frequency = target_frequency - offset_frequency

		self.source = osmosdr.source(args="numchan=1 rtl=0")
		self.source.set_sample_rate(rf_sampling_rate)
		self.source.set_center_freq(tuning_frequency, 0)
		self.source.set_freq_corr(0, 0)
		self.source.set_dc_offset_mode(0, 0)
		self.source.set_iq_balance_mode(0, 0)
		self.source.set_gain_mode(False, 0)
		self.source.set_gain(rf_gain, 0)
		self.source.set_if_gain(if_gain, 0)
		self.source.set_bb_gain(bb_gain, 0)
		self.source.set_antenna("", 0)
		self.source.set_bandwidth(baseband_bandwidth, 0)

		if_taps = firdes.low_pass_2(1.0, rf_sampling_rate, if_sampling_rate*0.45, if_sampling_rate*0.1, if_filter_attenuation)
		self.if_filter = filter.freq_xlating_fir_filter_ccc(rf_decimation, (if_taps), offset_frequency, rf_sampling_rate)
		#self.if_filter.set_min_output_buffer(1048576)

		self.connect(self.source, self.if_filter, self)

class source_file(gr.hier_block2):
	def __init__(self, file_path, throttle_rate=None):
		super(source_file, self).__init__(
			"source_file",
			gr.io_signature(0, 0, 0),
			gr.io_signature(1, 1, gr.sizeof_gr_complex*1),
		)

		self.source = blocks.file_source(gr.sizeof_gr_complex*1, file_path, False)

		if throttle_rate:
			self.throttle = blocks.throttle(gr.sizeof_gr_complex*1, throttle_rate, True)
			self.connect(self.source, self.throttle, self)
		else:
			self.connect(self.source, self)

