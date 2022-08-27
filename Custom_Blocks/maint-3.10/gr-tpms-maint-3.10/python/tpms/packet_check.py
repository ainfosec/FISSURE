#!/usr/bin/env python

# Copyright 2014 Jared Boone <jared@sharebrained.com>
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

import sys
from datetime import datetime

# from argparse import ArgumentParser

import crcmod

from .bit_coding import *

def crc8(polynomial, init):
	check_fn = crcmod.mkCrcFun(0x100 | polynomial, initCrc=init, rev=False)

	def crc8_fn(data, check):
		data_s = ''.join(map(chr, data))
		calculated = check_fn(data_s)
		return calculated == check

	return crc8_fn

def checksum8(extra):
	def checksum8_fn(data, check):
		calculated = (sum(data) - check + extra) & 0xff
		return calculated == 0

	return checksum8_fn

def no_check():
	def no_check_fn(data, check):
		return True

	return no_check_fn

packet_types = [
	{
		'modulation': 'fsk',
		'symbol_rate': 19220,
		'access_code': '01010101010101010101010101010110',
		'encoding': 'man',
		'prefixes': ('00111111111100',),
		'length': 80,
		'range_data': (0, 72),
		'range_check': (72, 80),
		'check_fn': crc8(polynomial=0x1, init=0xc0),
	},
	{
		'modulation': 'fsk',
		'symbol_rate': 19220,
		'access_code': '01010101010101010101010101010110',
		'encoding': 'man',
		'prefixes': ('00111101',),
		'length': 80,
		'range_data': (0, 72),
		'range_check': (72, 80),
		'check_fn': crc8(polynomial=0x1, init=0xc2),
	},
	{
		'modulation': 'fsk',
		'symbol_rate': 19220,
		'access_code': '01010101010101010101010101010110',
		'encoding': 'man',
		'prefixes': ('00111101', '00101001111000'),
		'length': 80,
		'range_data': (0, 72),
		'range_check': (72, 80),
		'check_fn': crc8(polynomial=0x7, init=0xf3),
	},
	{
		'modulation': 'fsk',
		'symbol_rate': 19220,
		'access_code': '01010101010101010101010101010110',
		'encoding': 'man',
		'prefixes': ('00110', '0101111111', '1111001'),
		'length': 72,
		'range_data': (0, 64),
		'range_check': (64, 72),
		'check_fn': crc8(polynomial=0x1, init=0xff),
	},
	{
		'modulation': 'fsk',
		'symbol_rate': 19220,
		'access_code': '01010101010101010101010101010110',
		'encoding': 'man',
		'prefixes': ('110',),
		'length': 64,
		'range_data': (0, 56),
		'range_check': (56, 64),
		'check_fn': checksum8(extra=6),
	},
	{
		'modulation': 'fsk',
		'symbol_rate': 19220,
		'access_code': '01010101010101010101010101010110',
		'encoding': 'man',
		'prefixes': ('11111101',),
		'length': 80,
		'range_data': (0, 72),
		'range_check': (72, 80),
		'check_fn': crc8(polynomial=0x1, init=0x2),
	},
	{
		'modulation': 'fsk',
		'symbol_rate': 19220,
		'access_code': '01010101010101010101010101010110',
		'encoding': 'man',
		'prefixes': ('0000', '1111'),
		'length': 68,
		'range_data': (4, 60),
		'range_check': (60, 68),
		'check_fn': crc8(polynomial=0x7, init=0x0),
	},
	#######################################################################
	{
		'modulation': 'fsk',
		'symbol_rate': 19250,
		'access_code': '00110011001100110011001100110011010',
		'encoding': 'man',
		'prefixes': (''),
		'length': 64,
	},
	#######################################################################
	{
		'modulation': 'fsk',
		'symbol_rate': 19440,
		'access_code': '01010101010101010101010101010110',
		'encoding': 'man',
		'prefixes': (''),
		'length': 64,
	},
	#######################################################################
	{
		'modulation': 'fsk',
		'symbol_rate': 9910,
		'access_code': '00111111001',
		'encoding': 'diffman',
		'prefixes': ('',),
		'length': 64,	# Some fraction of packets are 68 bits long?
	},
	#######################################################################
	{
		'modulation': 'fsk',
		'symbol_rate': 19224,
		'access_code': '1010101010101010101010101010100110',
		'encoding': 'man',
		'prefixes': ('',),
		'length': 80,
	},
	#######################################################################
	{
		'modulation': 'fsk',
		'symbol_rate': 19950,
		'access_code': '110110101110001',
		'encoding': 'man',
		'prefixes': ('',),
		'length': 69,
	},
	{
		'modulation': 'fsk',
		'symbol_rate': 20480,
		'access_code': '110110101110001',
		'encoding': 'man',
		'prefixes': ('',),
		'length': 69,
	},
	{
		'modulation': 'fsk',
		'symbol_rate': 20040,
		'access_code': '010101010011110',
		'encoding': 'man',
		'prefixes': ('',),
		'length': 72,
	},
	{
		'modulation': 'ask',
		'symbol_rate': 8157,
		'access_code': '111101010101010101010101010101011110',
		'encoding': 'man',
		'prefixes': ('',),
		'length': 37,
	},
	{
		'modulation': 'ask',
		'symbol_rate': 8400,
		'access_code': '1010101010101010101010101010110',
		'encoding': 'man',
		'prefixes': ('110010',),
		'length': 78,
		'range_data': (6, 70),
		'range_check': (70, 78),
		'check_fn': checksum8(extra=186),
	},
	# {
	#	MAY BE TOO SLOW FOR BURST CAPTURE TO CATCH COMPLETE TRANSMISSIONS.
	# 	'modulation': 'ask',
	# 	'symbol_rate': 4000-ish,
	# 	'access_code': '10101010101010101010101010101010101010101010101010011001010110101010'?,
	# },
	# {
	# 	'modulation': 'ask',
	# 	'symbol_rate': 4096,
	# 	'access_code': '10011001100110011001', # Wake up code, followed by separate packet transmission
	# 	'access_code_2': '10011001100110010101010101010110',
	# },
	# {
	# 	'modulation': 'ask',
	# 	'symbol_rate': 2200?,
	# 	'access_code': '1011011011001001001001001001001001001', # Or quite possibly the whole message?
	# },
	# {
	# 	'modulation': 'ask',
	# 	'symbol_rate': 4667,
	# 	'access_code': '10101010101010101010101010101001',
	# 	'encoding': 'man',
	# 	'prefixes': ('110000011010101110011010101100111011111011111011',),
	# 	'length': 96,
	# 	'range_data': ?,
	# 	'range_check': ?,
	# 	'check_fn': None,
	# },
	# {
	# 	'modulation': 'ask',
	# 	'symbol_rate': 10000,
	# 	'access_code': '11001111101010101001',
	# 	'encoding': 'diffman',
	# 	'prefixes': ('0000', '0101'),
	# 	'length': 68,
	# 	'range_data': (4, 60),
	# 	'range_check': (60, 68),
	# 	'check_fn': crc8(polynomial=0x07, init=0x00),
	# },
	{
		'modulation': 'ask',
		'symbol_rate': 10000,
		'access_code': '11001111101010101001',
		'encoding': 'diffman',
		'prefixes': None,
		'length': 64,
		'range_data': (0, 56),
		'range_check': (56, 64),
		'check_fn': crc8(polynomial=0x07, init=0x87),
	},
]

decoders = {
	'man': manchester_decode,
	'diffman': differential_manchester_decode,
}

def prefix_matches(decoded, prefixes):
	if prefixes:
		for prefix in prefixes:
			if decoded.startswith(prefix):
				return True
	else:
		return True

def bit_range_to_bytes(bits):
	c = []
	for n in range(0, len(bits), 8):
		v = int(bits[n:n+8], 2)
		c.append(v)
	return c

def format_time(t):
	return t.strftime('%Y%m%d%H%M%S')

def packet_decode(packet, output_raw=False):
	decoded_results = []

	utcnow = datetime.utcnow()

	raw_matches = set()

	for packet_type in packet_types:
		if (packet['modulation'] == packet_type['modulation']) and \
		   (packet['symbol_rate'] == packet_type['symbol_rate']) and \
		   (packet['access_code'] == packet_type['access_code']):
			decode_result = None
			decoder_fn = decoders[packet_type['encoding']]
			decoded = decoder_fn(packet['data']).split('X')[0]
			if len(decoded) >= 32:
				raw_matches.add((
					packet['modulation'],
					packet['symbol_rate'],
					packet['access_code'],
					packet['data']
				))

			if len(decoded) >= packet_type['length']:
				if prefix_matches(decoded, packet_type['prefixes']):
					if 'check_fn' in packet_type:
						payload_bits = decoded.__getslice__(*packet_type['range_data'])
						payload_bytes = bit_range_to_bytes(payload_bits)
						check_bits = decoded.__getslice__(*packet_type['range_check'])
						check_bytes = int(check_bits, 2)
						check_fn = packet_type['check_fn']
						check_ok = check_fn(payload_bytes, check_bytes)
						if check_ok:
							decode_result = 'success'
						else:
							decode_result = 'check failed'
					else:
						check_ok = True
						decode_result = 'success'

					if check_ok:
						decoded_result = packet_type.copy()
						decoded_result['payload'] = decoded
						decoded_results.append(decoded_result)
				else:
					decode_result = 'no prefix matches'
			else:
				decode_result = 'decoded length %d < %d' % (len(decoded), packet_type['length'])

	if output_raw:
		for modulation, symbol_rate, access_code, data in raw_matches:
			print('%s %s %s %s %s %s' % (
				format_time(utcnow),
				modulation,
				symbol_rate,
				access_code,
				'raw',
				''.join(map(str, data)),
			))

	for decoded_result in decoded_results:
		print('%s %s %s %s %s %s' % (
			format_time(utcnow),
			decoded_result['modulation'],
			decoded_result['symbol_rate'],
			decoded_result['access_code'],
			decoded_result['encoding'],
			decoded_result['payload'],
		))

	sys.stdout.flush()

	return len(decoded_results) > 0
