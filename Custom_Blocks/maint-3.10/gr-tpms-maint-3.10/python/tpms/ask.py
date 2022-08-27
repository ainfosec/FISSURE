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

from gnuradio import gr
from gnuradio import filter
from gnuradio.filter import firdes

import gnuradio.tpms as tpms

class ask_channel_filter(gr.hier_block2):
	def __init__(self, sample_rate, decimation, symbol_rate):
		super(ask_channel_filter, self).__init__(
			"ask_channel_filter",
			gr.io_signature(1, 1, gr.sizeof_float*1),
			gr.io_signature(1, 1, gr.sizeof_float*1),
		)

		output_sampling_rate = float(sample_rate) / decimation
		output_nyquist = output_sampling_rate / 2.0

		filter_attenuation_db = 40
		filter_cutoff = symbol_rate * 1.4 * 0.5
		filter_transition = symbol_rate * 1.4 * 0.2
		if (filter_cutoff + filter_transition) > output_nyquist:
			raise RuntimeError('ASK channel filter exceeds Nyquist frequency')

		filter_taps = firdes.low_pass_2(1.0, sample_rate, filter_cutoff, filter_transition, filter_attenuation_db)
		self.filter = filter.fir_filter_fff(decimation, (filter_taps))
		self.connect((self, 0), (self.filter, 0))

		self.envelope = tpms.ask_env(alpha=0.02)
		self.connect((self.filter, 0), (self.envelope, 0))

		self.connect((self.envelope, 0), (self, 0))		
