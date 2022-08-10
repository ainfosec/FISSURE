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

# Section 6.5.2.3
chips = [
	0b11011001110000110101001000101110,
	0b11101101100111000011010100100010,
	0b00101110110110011100001101010010,
	0b00100010111011011001110000110101,
	0b01010010001011101101100111000011,
	0b00110101001000101110110110011100,
	0b11000011010100100010111011011001,
	0b10011100001101010010001011101101,
	0b10001100100101100000011101111011,
	0b10111000110010010110000001110111,
	0b01111011100011001001011000000111,
	0b01110111101110001100100101100000,
	0b00000111011110111000110010010110,
	0b01100000011101111011100011001001,
	0b10010110000001110111101110001100,
	0b11001001011000000111011110111000
	]

# reflect bits
def mirror(n, bits):
	o = 0
	for i in range(bits):
		if(n & (1 << i)):
			o = o | (1 << (bits - 1 - i))
	return o


mapping = []

for c in range(16):
	# ahhhhhh endianess
	c = chips[mirror(c, 4)]
	c = mirror(c, 32)

	for i in range(16):
		rem = c % 4
		c = c / 4

		# QPSK
		if(rem == 0):
			mapping.append(-1-1j)
		elif (rem == 1):
			mapping.append( 1-1j)
		elif (rem == 2):
			mapping.append(-1+1j)
		elif (rem == 3):
			mapping.append( 1+1j)


print mapping
