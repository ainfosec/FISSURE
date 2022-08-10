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

from math import floor

from gnuradio import analog
from gnuradio import blocks
from gnuradio import gr
from gnuradio import filter
from gnuradio.filter import firdes

class fsk_center_tracking(gr.hier_block2):
	def __init__(self, sample_rate):
		super(fsk_center_tracking, self).__init__(
			"fsk_center_tracking",
			gr.io_signature(1, 1, gr.sizeof_gr_complex*1),
			gr.io_signature(1, 1, gr.sizeof_gr_complex*1),
		)

		# Arbitrary averaging values that seem to work OK.
		window_symbols = 20
		symbol_rate = 19200
		average_window = int(floor(sample_rate * window_symbols / symbol_rate))

		self.delay = blocks.delay(gr.sizeof_gr_complex*1, average_window)

		self.demod = analog.quadrature_demod_cf(1)
		self.moving_average = blocks.moving_average_ff(average_window, 1.0 / average_window, 4000)
		self.vco = blocks.vco_c(sample_rate, -sample_rate, 1)

		self.multiply = blocks.multiply_vcc(1)

		self.connect((self, 0), (self.delay, 0))
		self.connect((self.delay, 0), (self.multiply, 0))

		self.connect((self, 0), (self.demod, 0))
		self.connect((self.demod, 0), (self.moving_average, 0))
		self.connect((self.moving_average, 0), (self.vco, 0))
		self.connect((self.vco, 0), (self.multiply, 1))

		self.connect((self.multiply, 0), (self, 0))

class fsk_demodulator(gr.hier_block2):
	def __init__(self, sample_rate, offset, deviation, decimation, symbol_rate):
		super(fsk_demodulator, self).__init__(
			"fsk_demodulator",
			gr.io_signature(1, 1, gr.sizeof_gr_complex*1),
			gr.io_signature(1, 1, gr.sizeof_float*1),
		)

		symbol_taps_length = int(floor(float(sample_rate) / symbol_rate))
		symbol_taps = (1,) * symbol_taps_length

		self.symbol_filter_h = filter.freq_xlating_fir_filter_ccf(1, (symbol_taps), offset + deviation, sample_rate)
		self.symbol_filter_l = filter.freq_xlating_fir_filter_ccf(1, (symbol_taps), offset - deviation, sample_rate)

		self.mag_h = blocks.complex_to_mag(1)
		self.mag_l = blocks.complex_to_mag(1)
		self.sub = blocks.sub_ff(1)

		output_filter_cutoff = symbol_rate * 0.75
		output_filter_transition = symbol_rate * 0.25
		output_filter_attenuation = 40
		output_filter_taps = firdes.low_pass_2(1.0, sample_rate, output_filter_cutoff, output_filter_transition, output_filter_attenuation)
		self.output_filter = filter.fir_filter_fff(decimation, (output_filter_taps))

		self.connect((self, 0), (self.symbol_filter_h, 0))
		self.connect((self, 0), (self.symbol_filter_l, 0))
		self.connect((self.symbol_filter_h, 0), (self.mag_h, 0))
		self.connect((self.symbol_filter_l, 0), (self.mag_l, 0))
		self.connect((self.mag_h, 0), (self.sub, 0))
		self.connect((self.mag_l, 0), (self.sub, 1))
		self.connect((self.sub, 0), (self.output_filter, 0))
		self.connect((self.output_filter, 0), (self, 0))
