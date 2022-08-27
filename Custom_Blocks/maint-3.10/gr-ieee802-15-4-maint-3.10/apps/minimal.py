#!/usr/bin/env python

from socket import *
from struct import *

sock = socket(AF_INET, SOCK_DGRAM)
sock.sendto("hello", ("127.0.0.1", 52001))

while(True):
	data, addr = sock.recvfrom(200)
	(a,) = unpack("H", data[0:2])
	print a
