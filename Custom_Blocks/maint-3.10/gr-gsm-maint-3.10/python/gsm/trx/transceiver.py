#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# GR-GSM based transceiver
# Transceiver implementation
#
# (C) 2018-2019 by Vadim Yanitskiy <axilirator@gmail.com>
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

from .ctrl_if_bb import CTRLInterfaceBB

class Transceiver:
	""" Base transceiver implementation.

	Represents a single transceiver, that can be used as for the BTS side,
	as for the MS side. Each individual instance of Transceiver unifies
	three basic interfaces built on three independent UDP connections:

	  - CLCK (base port + 100/0) - clock indications from TRX to L1,
	  - CTRL (base port + 101/1) - control interface for L1,
	  - DATA (base port + 102/2) - bidirectional data interface for bursts.

	A transceiver can be either in active (i.e. working), or in idle mode.

	NOTE: both CLCK and DATA interfaces are handled by the flow-graph,
	      (see RadioInterface), so we only initialize CTRL interface.

	"""

	def __init__(self, bind_addr, remote_addr, base_port, radio_if):
		# Connection info
		self.remote_addr = remote_addr
		self.bind_addr = bind_addr
		self.base_port = base_port

		# Execution state (running or idle)
		self.running = False

		# Radio interface (handles both CLCK and DATA interfaces)
		self.radio_if = radio_if

		# Init CTRL interface
		self.ctrl_if = CTRLInterfaceBB(self,
			remote_addr, base_port + 101,
			bind_addr, base_port + 1)

	def start(self):
		# Check execution state
		if self.running:
			print("[!] Transceiver is already started")
			return False

		# Make sure that Radio interface is ready, i.e.
		# all parameters (e.g. RX / RX freq) are set.
		if not self.radio_if.ready:
			print("[!] RadioInterface is not ready")
			return False

		print("[i] Starting transceiver...")
		self.radio_if.start()
		self.running = True

		return True

	def stop(self):
		# POWEROFF is also used to reset transceiver,
		# so we should not complain that it isn't running.
		if not self.running:
			print("[i] Resetting transceiver")
			self.radio_if.reset()
			return

		print("[i] Stopping transceiver...")

		# TODO: flush all buffers between blocks
		self.radio_if.stop()
		self.radio_if.wait()

		self.running = False

	def measure(self, freq):
		# TODO: transceiver should be in idle mode
		return self.radio_if.measure(freq)
