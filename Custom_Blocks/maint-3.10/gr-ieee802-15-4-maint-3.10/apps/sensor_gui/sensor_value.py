#!/usr/bin/env python
#
# Copyright 2013 Bastian Bloessl <bloessl@ccs-labs.org>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import socket
import struct
import threading
import time
import signal
import gtk
import gobject

import sensor_window

UDP_IP = "127.0.0.1"
UDP_PORT = 52001

gobject.threads_init()

class MainLoop(threading.Thread):

	def __init__(self):
		super(MainLoop, self).__init__()
		self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		self.sock.sendto("sers", ((UDP_IP, UDP_PORT)))
		self.sock.settimeout(2)
		self._stopped = False
		signal.signal(signal.SIGINT, exitHandler)

	def stop(self):
		self._stopped = True

	def stopped(self):
		return self._stopped

	def run(self):
		while not(self.stopped()):
			try:
				data, addr = self.sock.recvfrom(200)
				a = struct.unpack("H", data[0:2])
				print a[0]

				if(a[0] == 0):
					sensorWindow.toggle_lamp()
				else:
					sensorWindow.update(a[0])
			except:
				pass
		print "main loop finished"
		sensorWindow.close_from_mainthread()
		gtk.main_quit()


def exitHandler(signum, frame):
	print "in exit handler"
	sensorWindow._stopped = True


if __name__ == "__main__":
	signal.signal(signal.SIGINT, exitHandler)

	mainThread = MainLoop()
	sensorWindow = sensor_window.SensorWindow(mainThread)

	mainThread.start()

	gtk.main()
	print "ciao"

