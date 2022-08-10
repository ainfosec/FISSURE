#!/usr/bin/env python
#

##########################################################################

# Copyright 2010, 2012 Nick Foster
# 
# This file is part of gr-air-modes
# 
# gr-air-modes is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3, or (at your option)
# any later version.
# 
# gr-air-modes is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with gr-air-modes; see the file COPYING.  If not, write to
# the Free Software Foundation, Inc., 51 Franklin Street,
# Boston, MA 02110-1301, USA.
# 

import math

def encode_alt_modes(alt, bit13):
    mbit = False
    qbit = True
    encalt = (int(alt) + 1000) / 25

    if bit13 is True:
        tmp1 = (encalt & 0xfe0) << 2
        tmp2 = (encalt & 0x010) << 1

    else:
        tmp1 = (encalt & 0xff8) << 1
        tmp2 = 0

    return (encalt & 0x0F) | tmp1 | tmp2 | (mbit << 6) | (qbit << 4)

latz = 15

def nz(ctype):
	return 4 * latz - ctype

def dlat(ctype, surface):
	if surface == 1:
		tmp = 90.0
	else:
		tmp = 360.0

	nzcalc = nz(ctype)
	if nzcalc == 0:
		return tmp
	else:
		return tmp / nzcalc

def nl(declat_in):
	if abs(declat_in) >= 87.0:
		return 1.0
	return math.floor( (2.0*math.pi) * math.acos(1.0- (1.0-math.cos(math.pi/(2.0*latz))) / math.cos( (math.pi/180.0)*abs(declat_in) )**2 )**-1)

def dlon(declat_in, ctype, surface):
	if surface:
		tmp = 90.0
	else:
		tmp = 360.0
	nlcalc = max(nl(declat_in)-ctype, 1)
	return tmp / nlcalc

#encode CPR position
def cpr_encode(lat, lon, ctype, surface):
    if surface is True:
        scalar = 2.**19
    else:
        scalar = 2.**17

    #encode using 360 constant for segment size.
    dlati = dlat(ctype, False)
    yz = math.floor(scalar * ((lat % dlati)/dlati) + 0.5)
    rlat = dlati * ((yz / scalar) + math.floor(lat / dlati))
    
    #encode using 360 constant for segment size.
    dloni = dlon(lat, ctype, False)
    xz = math.floor(scalar * ((lon % dloni)/dloni) + 0.5)
    
    yz = int(yz) & (2**17-1)
    xz = int(xz) & (2**17-1)
    
    return (yz, xz) #lat, lon

###############################################################

# Copyright (C) 2015 Junzi Sun (TU Delft)

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

# the polynominal generattor code for CRC
GENERATOR = "1111111111111010000001001"

def hex2bin(hexstr):
    """Convert a hexdecimal string to binary string, with zero fillings. """
    scale = 16
    num_of_bits = len(hexstr) * math.log(scale, 2)
    binstr = bin(int(hexstr, scale))[2:].zfill(int(num_of_bits))
    return binstr

def bin2int(binstr):
    """Convert a binary string to integer. """
    return int(binstr, 2)

def crc(msg, encode=False):
    """Mode-S Cyclic Redundancy Check
    Detect if bit error occurs in the Mode-S message
    Args:
        msg (string): 28 bytes hexadecimal message string
        encode (bool): True to encode the date only and return the checksum
    Returns:
        string: message checksum, or partity bits (encoder)
    """

    msgbin = list(hex2bin(msg))

    if encode:
        msgbin[-24:] = ['0'] * 24

    # loop all bits, except last 24 piraty bits
    for i in range(len(msgbin)-24):
        # if 1, perform modulo 2 multiplication,
        if msgbin[i] == '1':
            for j in range(len(GENERATOR)):
                # modulo 2 multiplication = XOR
                msgbin[i+j] = str((int(msgbin[i+j]) ^ int(GENERATOR[j])))

    # last 24 bits
    reminder = ''.join(msgbin[-24:])
    return reminder
    
###############################################################

'''
   Copyright 2015 Wolfgang Nagele

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
'''
def bin2dec(buf):
  if 0 == len(buf): # Crap input
    return -1
  return int(buf, 2)

# Ported from: http://www.radarspotters.eu/forum/index.php?topic=5617.msg41293#msg41293
def get_parity(msg, extended):
  msg_length = len(msg)
  payload = msg[:msg_length - 24]
  parity = msg[msg_length - 24:]

  data = bin2dec(payload[0:32])
  if extended:
    data1 = bin2dec(payload[32:64])
    data2 = bin2dec(payload[64:]) << 8

  hex_id = bin2dec(parity) << 8

  for i in range(0, len(payload)):
    if ((data & 0x80000000) != 0):
      data ^= 0xFFFA0480
    data <<= 1

    if extended:
      if ((data1 & 0x80000000) != 0):
        data |= 1
      data1 <<= 1

      if ((data2 & 0x80000000) != 0):
        data1 = data1 | 1
      data2 <<= 1

  return data
  #return (data ^ hex_id) >> 8

###############################################################

"""
Hamming and Manchester Encoding example

Author: Joel Addison
Date: March 2013

Functions to do (7,4) hamming encoding and decoding, including error detection
and correction.
Manchester encoding and decoding is also included, and by default will use
least bit ordering for the byte that is to be included in the array.
"""

def extract_bit(byte, pos):
    """
    Extract a bit from a given byte using MS ordering.
    ie. B7 B6 B5 B4 B3 B2 B1 B0
    """
    return (byte >> pos) & 0x01

def manchester_encode(byte):
    """
    Encode a byte using Manchester encoding. Returns an array of bits.
    Adds two start bits (1, 1) and one stop bit (0) to the array.
    """
    # Add start bits (encoded 1, 1)
    # manchester_encoded = [0, 1, 0, 1]
    manchester_encoded = []

    # Encode byte
    for i in range(7, -1, -1):
        if extract_bit(byte, i):
            manchester_encoded.append(0)
            manchester_encoded.append(1)
        else:
            manchester_encoded.append(1)
            manchester_encoded.append(0)

    # Add stop bit (encoded 0)
    # manchester_encoded.append(1)
    # manchester_encoded.append(0)

    return manchester_encoded

###############################################################

# Copyright (C) 2017-2018 Linar Yusupov

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import numpy
#from scipy.signal import hilbert

def df17_pos_rep_encode(ca, icao, tc, ss, nicsb, alt, time, lat, lon, surface):

    format = 17

    enc_alt =	encode_alt_modes(alt, surface)
    #print "Alt(%r): %X " % (surface, enc_alt)

    #encode that position
    (evenenclat, evenenclon) = cpr_encode(lat, lon, False, surface)
    (oddenclat, oddenclon)   = cpr_encode(lat, lon, True, surface)

    #print "Even Lat/Lon: %X/%X " % (evenenclat, evenenclon)
    #print "Odd  Lat/Lon: %X/%X " % (oddenclat, oddenclon)

    ff = 0
    df17_even_bytes = []
    df17_even_bytes.append((format<<3) | ca)
    df17_even_bytes.append((icao>>16) & 0xff)
    df17_even_bytes.append((icao>> 8) & 0xff)
    df17_even_bytes.append((icao    ) & 0xff)
    # data
    df17_even_bytes.append((tc<<3) | (ss<<1) | nicsb)
    df17_even_bytes.append((enc_alt>>4) & 0xff)
    df17_even_bytes.append((enc_alt & 0xf) << 4 | (time<<3) | (ff<<2) | (evenenclat>>15))
    df17_even_bytes.append((evenenclat>>7) & 0xff)    
    df17_even_bytes.append(((evenenclat & 0x7f) << 1) | (evenenclon>>16))  
    df17_even_bytes.append((evenenclon>>8) & 0xff)   
    df17_even_bytes.append((evenenclon   ) & 0xff)

    df17_str = "{0:02x}{1:02x}{2:02x}{3:02x}{4:02x}{5:02x}{6:02x}{7:02x}{8:02x}{9:02x}{10:02x}".format(*df17_even_bytes[0:11])
    #print df17_str , "%X" % bin2int(crc(df17_str+"000000", encode=True)) , "%X" % get_parity(hex2bin(df17_str+"000000"), extended=True)
    df17_crc = bin2int(crc(df17_str+"000000", encode=True))

    df17_even_bytes.append((df17_crc>>16) & 0xff)
    df17_even_bytes.append((df17_crc>> 8) & 0xff)
    df17_even_bytes.append((df17_crc    ) & 0xff)
 
    ff = 1
    df17_odd_bytes = []
    df17_odd_bytes.append((format<<3) | ca)
    df17_odd_bytes.append((icao>>16) & 0xff)
    df17_odd_bytes.append((icao>> 8) & 0xff)
    df17_odd_bytes.append((icao    ) & 0xff)
    # data
    df17_odd_bytes.append((tc<<3) | (ss<<1) | nicsb)
    df17_odd_bytes.append((enc_alt>>4) & 0xff)
    df17_odd_bytes.append((enc_alt & 0xf) << 4 | (time<<3) | (ff<<2) | (oddenclat>>15))
    df17_odd_bytes.append((oddenclat>>7) & 0xff)    
    df17_odd_bytes.append(((oddenclat & 0x7f) << 1) | (oddenclon>>16))  
    df17_odd_bytes.append((oddenclon>>8) & 0xff)   
    df17_odd_bytes.append((oddenclon   ) & 0xff)

    df17_str = "{0:02x}{1:02x}{2:02x}{3:02x}{4:02x}{5:02x}{6:02x}{7:02x}{8:02x}{9:02x}{10:02x}".format(*df17_odd_bytes[0:11])
    df17_crc = bin2int(crc(df17_str+"000000", encode=True))

    df17_odd_bytes.append((df17_crc>>16) & 0xff)
    df17_odd_bytes.append((df17_crc>> 8) & 0xff)
    df17_odd_bytes.append((df17_crc    ) & 0xff)    
    
    return (df17_even_bytes, df17_odd_bytes)

def frame_1090es_ppm_modulate(even, odd):
    ppm = [ ]

    for i in range(48):    # pause
        ppm.append( 0 )

    ppm.append( 0xA1 )   # preamble
    ppm.append( 0x40 )
    
    for i in range(len(even)):
        word16 = numpy.packbits(manchester_encode(~even[i]))
        ppm.append(word16[0])
        ppm.append(word16[1])


    for i in range(100):    # pause
        ppm.append( 0 )

    ppm.append( 0xA1 )   # preamble
    ppm.append( 0x40 )

    for i in range(len(odd)):
        word16 = numpy.packbits(manchester_encode(~odd[i]))
        ppm.append(word16[0])
        ppm.append(word16[1])

    for i in range(48):    # pause
        ppm.append( 0 )

    #print '[{}]'.format(', '.join(hex(x) for x in ppm))
    
    return bytearray(ppm)

def hackrf_raw_IQ_format(ppm):
    """
    real_signal = []
    bits = numpy.unpackbits(numpy.asarray(ppm, dtype=numpy.uint8))
    for bit in bits:
        if bit == 1:
            I = 127
        else:
            I = 0
        real_signal.append(I)

    analytic_signal = hilbert(real_signal)

    #for i in range(len(real_signal)):
    #    print i, real_signal[i], int(analytic_signal[i])
    """

    signal = []
    bits = numpy.unpackbits(numpy.asarray(ppm, dtype=numpy.uint8))
    for bit in bits:
        if bit == 1:
            I = 127
            Q = 127
        else:
            I = 0
            Q = 0
        signal.append(I)
        signal.append(Q)

    return bytearray(signal)
    
if __name__ == "__main__":

    from sys import argv, exit
    
    argc = len(argv)
    if argc != 5:
      print
      print 'Usage: '+ argv[0] +'  <ICAO> <Latitude> <Longtitude> <Altitude>'
      print
      print '    Example: '+ argv[0] +'  0xABCDEF 12.34 56.78 9999.0'
      print
      exit(2)

    icao = int(argv[1], 16)
    lat = float(argv[2])
    lon = float(argv[3])
    alt = float(argv[4])

    ca = 5
    tc = 11
    ss = 0
    nicsb = 0    
    time = 0       
    surface = False

    (df17_even, df17_odd) = df17_pos_rep_encode(ca, icao, tc, ss, nicsb, alt, time, lat, lon, surface)

    #print ''.join(format(x, '02x') for x in df17_even)
    #print ''.join(format(x, '02x') for x in df17_odd)

    df17_array = frame_1090es_ppm_modulate(df17_even, df17_odd)

    #OutFile = open("filename.bin", "wb")
    #OutFile.write(df17_array)

    samples_array = hackrf_raw_IQ_format(df17_array)

    SamplesFile = open("Samples.iq8s", "wb")
    SamplesFile.write(samples_array)

###############################################################
