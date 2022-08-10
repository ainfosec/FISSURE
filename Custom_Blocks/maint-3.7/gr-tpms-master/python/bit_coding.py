#!/usr/bin/env python

# Copyright 2013 Jared Boone <jared@sharebrained.com>
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

def string_to_symbols(s, symbol_length):
	return [s[n:n+symbol_length] for n in range(0, len(s), symbol_length)]

def differential_manchester_decode(s):
	symbols = string_to_symbols(s, 2)
	last_bit = '0'
	result = []
	for symbol in symbols:
		if len(symbol) == 2:
			if symbol[0] == symbol[1]:
				result.append('X')
			elif last_bit != symbol[0]:
				result.append('0')
			else:
				result.append('1')
			last_bit = symbol[1]
		else:
			result.append('X')
	return ''.join(result)

def manchester_decode(s):
	symbols = string_to_symbols(s, 2)
	result = []
	for symbol in symbols:
		if len(symbol) == 2:
			if symbol[0] == symbol[1]:
				result.append('X')
			else:
				result.append(symbol[1])
		else:
			result.append('X')
	return ''.join(result)
