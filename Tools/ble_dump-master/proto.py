#!/usr/bin/env python
#
#  ble-dump: constants and helper functions
#
#  Copyright (C) 2016 Jan Wagner <mail@jwagner.eu>
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#

from time import time
from struct import pack, unpack

# Bluetooth LE constants and definitions
BLE_PREAMBLE = '\xAA'
BLE_ACCESS_ADDR = 0x8e89bed6

BLE_PREAMBLE_LEN = 1
BLE_ADDR_LEN = 4
BLE_PDU_HDR_LEN = 2
BLE_CRC_LEN = 3

BLE_PDU_TYPE = {}
BLE_PDU_TYPE['ADV_IND'] = 0b0000
BLE_PDU_TYPE['ADV_DIRECT_IND'] = 0b0001
BLE_PDU_TYPE['ADV_NONCONN_IND'] = 0b0010
BLE_PDU_TYPE['SCAN_REQ'] = 0b0011
BLE_PDU_TYPE['SCAN_RSP'] = 0b0100
BLE_PDU_TYPE['CONNECT_REQ'] = 0b0101
BLE_PDU_TYPE['ADV_SCAN_IND'] = 0b0110

BLE_CHANS = { 37:0, 0:1, 1:2, 2:3, 3:4, 4:5, 5:6, 6:7, 7:8, 8:9, 9:10, 10:11, 38:12, 11:13, 12:14, 13:15, 14:16, 15:17, 16:18, 17:19, 18:20, 19:21, 20:22, 21:23, 22:24, 23:25, 24:26, 25:27, 26:28, 27:29, 28:30, 29:31, 30:32, 31:33, 32:34, 33:35, 34:36, 35:37, 36:38, 39:39 }

# Swap bits of a 8-bit value
def swap_bits(value):
    return (value * 0x0202020202  & 0x010884422010) % 1023

# (De)Whiten data based on BLE channel
def dewhitening(data, channel):
  ret = []
  lfsr = swap_bits(channel) | 2

  for d in data:
    d = swap_bits(ord(d[:1]))
    for i in 128, 64, 32, 16, 8, 4, 2, 1:
      if lfsr & 0x80:
        lfsr ^= 0x11
        d ^= i

      lfsr <<= 1
      i >>=1
    ret.append(swap_bits(d))

  return ret

# 24-bit CRC function
def crc(data, length, init=0x555555):
  ret = [(init >> 16) & 0xff, (init >> 8) & 0xff, init & 0xff]

  for d in data[:length]:
    for v in range(8):
      t = (ret[0] >> 7) & 1;

      ret[0] <<= 1
      if ret[1] & 0x80:
        ret[0] |= 1

      ret[1] <<= 1
      if ret[2] & 0x80:
        ret[1] |= 1

      ret[2] <<= 1

      if d & 1 != t:
        ret[2] ^= 0x5b
        ret[1] ^= 0x06

      d >>= 1

  ret[0] = swap_bits((ret[0] & 0xFF))
  ret[1] = swap_bits((ret[1] & 0xFF))
  ret[2] = swap_bits((ret[2] & 0xFF))

  return ret

# PCAP Header constants
PCAP_MAGIC = 0xa1b2c3d4
PCAP_MAJOR = 2
PCAP_MINOR = 4
PCAP_ZONE = 0
PCAP_SIG = 0
PCAP_SNAPLEN = 0xffff
PCAP_NETWORK = 256

# Open PCAP file descriptor
def open_pcap(filename):
  pcap_fd = open(filename, 'wb')

  # Write PCAP file header
  pcap_fd.write(pack('<LHHLLLL', PCAP_MAGIC, PCAP_MAJOR, PCAP_MINOR, PCAP_ZONE, PCAP_SIG, PCAP_SNAPLEN, PCAP_NETWORK))
  return pcap_fd

# Write BLE packet to PCAP fd
def write_pcap(fd, ble_channel, ble_access_address, ble_data):
  now = time()
  sec = int(now)
  usec = int((now - sec) * 1000000)
  ble_len = int(len(ble_data) + 14)
  ble_flags = 0x3c37

  # Write PCAP packet header
  fd.write(pack('<LLLLBBBBLHL', sec, usec, ble_len, ble_len, ble_channel, 0xff, 0xff, 0x00, ble_access_address, ble_flags, ble_access_address))

  # Write BLE packet
  fd.write(''.join(chr(x) for x in ble_data))
  fd.flush()
