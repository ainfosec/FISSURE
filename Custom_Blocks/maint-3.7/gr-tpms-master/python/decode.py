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

import numpy

from gnuradio import digital
from gnuradio import gr

class clock_recovery(gr.hier_block2):
	def __init__(self, input_rate, symbol_rate):
		super(clock_recovery, self).__init__(
			"clock_recovery",
			gr.io_signature(1, 1, gr.sizeof_float*1),
			gr.io_signature(1, 1, gr.sizeof_char*1),
		)

		samples_per_symbol = float(input_rate) / symbol_rate
		omega_relative_limit = 0.02
		gain_mu = 0.4 / samples_per_symbol

		self.clock_recovery = digital.clock_recovery_mm_ff(samples_per_symbol*(1+0.00), 0.25*gain_mu*gain_mu, 0.5, gain_mu, omega_relative_limit)
		self.slicer = digital.binary_slicer_fb()

		self.connect((self, 0), (self.clock_recovery, 0))
		self.connect((self.clock_recovery, 0), (self.slicer, 0))
		self.connect((self.slicer, 0), (self, 0))

class tag_print(gr.sync_block):
	def __init__(self, symbol_rate, bit_count):
		super(tag_print, self).__init__(
			"tag_print",
			[numpy.uint8],
			None
		)

		self.symbol_rate = symbol_rate
		self.bit_count = bit_count

		self._packets = {}

	def work(self, input_items, output_items):
		nread = self.nitems_read(0)
		ninput_items = len(input_items[0])
		tags = self.get_tags_in_range(0, nread, nread + ninput_items)

		for offset, packet in self._packets.items():
			items_needed = self.bit_count - len(packet)
			if items_needed > 0:
				new_packet = numpy.concatenate((packet, input_items[0][:items_needed]))
				self._packets[offset] = new_packet
			if len(self._packets[offset]) >= self.bit_count:
				time_seconds = float(offset) / self.symbol_rate
				bits = ''.join(map(str, self._packets[offset]))
				print('%s %12.6f' % (bits, time_seconds))
				del self._packets[offset]

		for tag in tags:
			local_start = tag.offset - nread
			self._packets[tag.offset] = input_items[0][local_start:local_start + self.bit_count]

		return ninput_items
