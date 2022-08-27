#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# GR-GSM based transceiver
# UDP link implementation
#
# (C) 2017 by Vadim Yanitskiy <axilirator@gmail.com>
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

import socket
import select

class UDPLink:
	def __init__(self, remote_addr, remote_port, bind_addr = '0.0.0.0', bind_port = 0):
		self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		self.sock.bind((bind_addr, bind_port))
		self.sock.setblocking(0)

		# Save remote info
		self.remote_addr = remote_addr
		self.remote_port = remote_port

	def __del__(self):
		self.sock.close()

	def loop(self):
		r_event, w_event, x_event = select.select([self.sock], [], [])

		# Check for incoming data
		if self.sock in r_event:
			data, addr = self.sock.recvfrom(128)
			self.handle_rx(data.decode(), addr)

	def desc_link(self):
		(bind_addr, bind_port) = self.sock.getsockname()

		return "L:%s:%u <-> R:%s:%u" \
			% (bind_addr, bind_port, self.remote_addr, self.remote_port)

	def send(self, data, remote = None):
		if type(data) not in [bytearray, bytes]:
			data = data.encode()

		if remote is None:
			remote = (self.remote_addr, self.remote_port)

		self.sock.sendto(data, remote)

	def handle_rx(self, data, remote):
		raise NotImplementedError
