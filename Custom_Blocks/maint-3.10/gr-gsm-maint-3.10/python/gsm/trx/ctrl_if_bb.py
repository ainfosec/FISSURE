#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# GR-GSM based transceiver
# CTRL interface for OsmocomBB
#
# (C) 2016-2019 by Vadim Yanitskiy <axilirator@gmail.com>
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

from .ctrl_if import CTRLInterface

class CTRLInterfaceBB(CTRLInterface):
	def __init__(self, trx, *ctrl_if_args):
		CTRLInterface.__init__(self, *ctrl_if_args)
		print("[i] Init CTRL interface (%s)" % self.desc_link())

		# Transceiver instance we belong to
		self.trx = trx

	def parse_cmd(self, request):
		# Power control
		if self.verify_cmd(request, "POWERON", 0):
			print("[i] Recv POWERON CMD")

			# Start transceiver
			if not self.trx.start():
				return -1

			return 0

		elif self.verify_cmd(request, "POWEROFF", 0):
			print("[i] Recv POWEROFF cmd")

			# Stop transceiver
			self.trx.stop()

			return 0

		# Gain control
		elif self.verify_cmd(request, "SETRXGAIN", 1):
			print("[i] Recv SETRXGAIN cmd")

			# TODO: check gain value
			gain = int(request[1])
			self.trx.radio_if.set_rx_gain(gain)

			return 0

		elif self.verify_cmd(request, "SETTXGAIN", 1):
			print("[i] Recv SETTXGAIN cmd")

			# TODO: check gain value
			gain = int(request[1])
			self.trx.radio_if.set_tx_gain(gain)

			return 0

		# Tuning Control
		elif self.verify_cmd(request, "RXTUNE", 1):
			print("[i] Recv RXTUNE cmd")

			# TODO: check freq range
			freq = int(request[1]) * 1000
			self.trx.radio_if.set_rx_freq(freq)

			return 0

		elif self.verify_cmd(request, "TXTUNE", 1):
			print("[i] Recv TXTUNE cmd")

			# TODO: check freq range
			freq = int(request[1]) * 1000
			self.trx.radio_if.set_tx_freq(freq)

			return 0

		# Timeslot management
		elif self.verify_cmd(request, "SETSLOT", 2):
			print("[i] Recv SETSLOT cmd")

			# Obtain TS index
			tn = int(request[1])
			if tn not in range(0, 8):
				print("[!] TS index should be in range: 0..7")
				return -1

			# Channel combination number (see GSM TS 05.02)
			# TODO: check this value
			config = int(request[2])

			# TODO: check return value
			self.trx.radio_if.set_slot(tn, config)

			return 0

		# Power measurement
		elif self.verify_cmd(request, "MEASURE", 1):
			print("[i] Recv MEASURE cmd")

			# TODO: check freq range
			meas_freq = int(request[1]) * 1000
			meas_dbm = self.trx.measure(meas_freq)
			if meas_dbm is None:
				return -1

			return (0, [str(meas_dbm)])

		# Timing Advance control
		elif self.verify_cmd(request, "SETTA", 1):
			print("[i] Recv SETTA cmd")

			# Check TA range
			ta = int(request[1])
			if ta < 0 or ta > 63:
				print("[!] TA value must be in range: 0..63")
				return -1

			self.trx.radio_if.set_ta(ta)
			return 0

		# Misc
		elif self.verify_cmd(request, "ECHO", 0):
			print("[i] Recv ECHO cmd")
			return 0

		# Wrong / unknown command
		else:
			print("[!] Wrong request on CTRL interface")
			return -1
