#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# GR-GSM based transceiver
# Radio interface for Lime devices
#
# (C) 2019 by Vadim Yanitskiy <axilirator@gmail.com>
#
# All Rights Reserved
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

import limesdr

from radio_if import RadioInterface

class RadioInterfaceLMS(RadioInterface):
	lms_len_tag_name = "packet_len"
	lms_dev_serial = ""
	lms_dev_ch_mode = 1

	# Human-readable description
	def __str__(self):
		return "LMS"

	@property # Signal processing delay of PHY
	def phy_proc_delay(self):
		# FIXME: the current value is measured for USRP B2X0 at 26e6,
		# we should measure it for LimeSDR separately!
		return (285.616 + 2 * self.GSM_SYM_PERIOD_uS) * 1e-6

	def phy_init_source(self):
		self._phy_src = limesdr.source(self.lms_dev_serial,
			self.lms_dev_ch_mode, "")

		self._phy_src.set_sample_rate(self.sample_rate)
		self._phy_src.set_gain(self.rx_gain, 0)

	def phy_init_sink(self):
		self._phy_sink = limesdr.sink(self.lms_dev_serial,
			self.lms_dev_ch_mode, "",
			self.lms_len_tag_name)

		self._phy_sink.set_sample_rate(self.sample_rate)
		self._phy_sink.set_gain(self.tx_gain, 0)

	def phy_set_rx_freq(self, freq):
		self._phy_src.set_center_freq(freq, 0)

	def phy_set_tx_freq(self, freq):
		self._phy_sink.set_center_freq(freq, 0)

	def phy_set_rx_gain(self, gain):
		self._phy_src.set_gain(gain, 0)

	def phy_set_tx_gain(self, gain):
		self._phy_sink.set_gain(gain, 0)
