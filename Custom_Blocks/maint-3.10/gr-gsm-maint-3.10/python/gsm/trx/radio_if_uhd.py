#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# GR-GSM based transceiver
# Radio interface for UHD devices
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

from gnuradio import uhd

from .radio_if import RadioInterface

class RadioInterfaceUHD(RadioInterface):
	# Human-readable description
	def __str__(self):
		return "UHD"

	@property
	def phy_proc_delay(self):
		# FIXME: shall be measured (automatically?) for
		# particular device and particular clock rate.
		# The current value is measured for USRP B2X0 at 26e6.
		return (285.616 + 2 * self.GSM_SYM_PERIOD_uS) * 1e-6

	def phy_init_source(self):
		self._phy_src = uhd.usrp_source(self.phy_args,
			uhd.stream_args(cpu_format = "fc32",
				channels = range(1)))

		self._phy_src.set_clock_rate(26e6, uhd.ALL_MBOARDS)
		self._phy_src.set_antenna(self.rx_antenna, 0)
		self._phy_src.set_samp_rate(self.sample_rate)
		self._phy_src.set_bandwidth(650e3, 0)
		self._phy_src.set_gain(self.rx_gain)

		# Some UHD devices (such as UmTRX) do start the clock
		# not from 0, so it's required to reset it manually.
		# Resetting UHD source will also affect the sink.
		self._phy_src.set_time_now(uhd.time_spec(0.0))

	def phy_init_sink(self):
		self._phy_sink = uhd.usrp_sink(self.phy_args,
			uhd.stream_args(cpu_format = "fc32",
				channels = range(1)), "packet_len")

		self._phy_sink.set_clock_rate(26e6, uhd.ALL_MBOARDS)
		self._phy_sink.set_antenna(self.tx_antenna, 0)
		self._phy_sink.set_samp_rate(self.sample_rate)
		self._phy_sink.set_gain(self.tx_gain)

	def phy_set_rx_freq(self, freq):
		self._phy_src.set_center_freq(freq, 0)

	def phy_set_tx_freq(self, freq):
		self._phy_sink.set_center_freq(freq, 0)

	def phy_set_rx_gain(self, gain):
		self._phy_src.set_gain(gain, 0)

	def phy_set_tx_gain(self, gain):
		self._phy_sink.set_gain(gain, 0)
