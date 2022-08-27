#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# GR-GSM based transceiver
# CTRL interface implementation
#
# (C) 2016-2017 by Vadim Yanitskiy <axilirator@gmail.com>
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

from .udp_link import UDPLink

class CTRLInterface(UDPLink):
	def handle_rx(self, data, remote):
		if self.verify_req(data):
			request = self.prepare_req(data)
			rc = self.parse_cmd(request)

			if type(rc) is tuple:
				self.send_response(request, remote, rc[0], rc[1])
			else:
				self.send_response(request, remote, rc)
		else:
			print("[!] Wrong data on CTRL interface")

	def verify_req(self, data):
		# Verify command signature
		return data.startswith("CMD")

	def prepare_req(self, data):
		# Strip signature, paddings and \0
		request = data[4:].strip().strip("\0")
		# Split into a command and arguments
		request = request.split(" ")
		# Now we have something like ["TXTUNE", "941600"]
		return request

	def verify_cmd(self, request, cmd, argc):
		# Check if requested command matches
		if request[0] != cmd:
			return False

		# And has enough arguments
		if len(request) - 1 != argc:
			return False

		# Check if all arguments are numeric
		for v in request[1:]:
			if not v.isdigit():
				return False

		return True

	def send_response(self, request, remote, response_code, params = None):
		# Include status code, for example ["TXTUNE", "0", "941600"]
		request.insert(1, str(response_code))

		# Optionally append command specific parameters
		if params is not None:
			request += params

		# Add the response signature, and join back to string
		response = "RSP " + " ".join(request) + "\0"
		# Now we have something like "RSP TXTUNE 0 941600"
		self.send(response, remote)

	def parse_cmd(self, request):
		raise NotImplementedError
