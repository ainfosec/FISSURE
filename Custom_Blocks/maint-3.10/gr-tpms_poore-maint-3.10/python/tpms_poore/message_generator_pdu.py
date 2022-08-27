#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# 
# Copyright 2021 <+YOU OR YOUR COMPANY+>.
# 
# This is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3, or (at your option)
# any later version.
# 
# This software is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this software; see the file COPYING.  If not, write to
# the Free Software Foundation, Inc., 51 Franklin Street,
# Boston, MA 02110-1301, USA.
# 

import numpy
from gnuradio import gr
import pmt
import time
import threading
import crcmod
import sys


class message_generator_pdu(gr.sync_block):
    """
    From github.com/xnk/pacific-tpms - Werner Johansson
    * Offset | Length | Description | Notes
    
    * 0 | 28 | Sensor ID |
        7 hex digits
        
    * 28 | 1 | Battery Status | 
        1 if low, 0 if ok or 'over' in Toyota speak
        
    * 29 | 2 | Counter | 
        Counts 1,2,3 for every message out of the sensor. Car seems to 
        ignore this and happily accepts the same counter over and over 
        without ever changing
        
    * 31 | 1 | Unknown | 
        Must be zero for the packet to be recognized by the car (haven't 
        seen a real sensor ever set this bit)
        
    * 32 | 1 | Rapid pressure drop? | 
        Seems to be ignored by the car, I've seen some sensors setting 
        this bit to 1 when pressure is changing fast. This also triggers 
        multiple transmissions in rapid succession
        
    * 33 | 1 | Self-test failed? | 
        My sensors set this to 0 but when I send a message with this bit 
        set to 1 to the car the TPMS light starts flashing and the values 
        in the message are ignored
        
    * 34 | 8 | Tire pressure | 
        PSI/0.363 + 40 or kPa/2.48 + 40, diagnostics reports this in PSI
        
    * 42 | 8 | Inverted tire pressure | 
        xor 0xff of above
        
    * 50 | 8 | Tire temperature | 
        Celsius + 40 resulting in a range from -40 to 215C, diagnostics 
        insists on reporting this in Fahrenheit though
        
    * 58 | 8 | CRC over bits 0-57 | 
        Truncated polynomial 19, init value 0
        
    """

    def __init__(self, repetition_interval, configuration, sensor_id, battery_status, counter, unknown1, unknown2,
                 self_test, tire_pressure, tire_temp):
        gr.sync_block.__init__(self,
                               name="message_generator_pdu",
                               in_sig=None,
                               out_sig=None)

        self.message_port_register_out(pmt.intern('out'))

        # Default Values
        self.repetition_interval = repetition_interval
        self.configuration = configuration
        self.sensor_id = sensor_id
        self.battery_status = battery_status
        self.counter = counter
        self.unknown1 = unknown1
        self.unknown2 = unknown2
        self.self_test = self_test
        self.tire_pressure = tire_pressure
        self.tire_temp = tire_temp

        # Run in a Thread
        c_thread = threading.Thread(target=self.generateMessage, args=())
        c_thread.daemon = True
        c_thread.start()

    def generateMessage(self):
        while True:
            print("GENERATE MESSAGE")

            # Access Code
            # '000000111111001', some say the access code is: '00111111001' but the last '01' must translate to a
            # manchester encoded '0' in the sensor id for all the fields to align
            access_code = '0000001111110'

            # Sensor ID
            # sensor_id = '0101001010001010010100010000'  # 528A510
            sensor_id = bin(int(self.sensor_id, 16))[2:].zfill(28)

            # Battery Status
            # nothing when set to 0 or 1, might be part of counter, observed both 0 and 1 from the same sensor
            # battery_status = '1'
            battery_status = self.battery_status

            # Counter
            # counter = '00'  # nothing when set to all values, observed counter-like behavior for these bits
            counter = self.counter

            # Unknown1
            # unknown1 = '0'  # nothing when set to 0 or 1, always 0
            unknown1 = self.unknown1

            # Unknown2
            # unknown2 = '0'  # nothing when set to 0 or 1, always 0
            unknown2 = self.unknown2

            # Self-Test Failed
            # self_test_failed = '0'  # Makes light flash when set to 1, always 0
            self_test_failed = self.self_test

            # Tire Pressure
            # tire_pressure = '10101111'  # 49
            # tire_pressure = '01101110'  # light starting threshold = 01101110 = 110 = (110-40)*.363 = 25.41
            # tire_pressure = '11111111'
            tire_pressure = "{0:08b}".format(int((self.tire_pressure / 0.363) + 40))

            # Tire Pressure Complement
            # tire_pressure_complement = '01010000'
            # tire_pressure_complement = '10010001'
            # tire_pressure_complement = '00000000'
            tire_pressure_complement = ''.join('1' if x == '0' else '0' for x in tire_pressure)

            # Tire Temperature
            # tire_temperature = '01111010'  # Nothing happens when set to 00000000-11111111
            tire_temperature = "{0:08b}".format(int(self.tire_temp + 40))

            # CRC
            # crc = '00001101'
            bits_no_crc = sensor_id + battery_status + counter + unknown1 + unknown2 + self_test_failed + \
                tire_pressure + tire_pressure_complement + tire_temperature
            crc_data = '000000' + bits_no_crc + ''
            crc_data_bytes = []
            for n in range(0, len(crc_data) // 8):
                crc_data_bytes.append(int(crc_data[n * 8:n * 8 + 8], 2))
            crc_data_bytes = str(bytearray(crc_data_bytes))
            check_fn = crcmod.mkCrcFun(0x100 | 0x13, initCrc=0x0, rev=False)
            crc = '{0:08b}'.format(check_fn(crc_data_bytes))

            # Assemble the Message
            get_msg = sensor_id + battery_status + counter + unknown1 + unknown2 + self_test_failed + tire_pressure + \
                tire_pressure_complement + tire_temperature + crc

            # UnDiff
            get_undiff = '0'
            for b in range(0, len(get_msg)):
                # Change
                if get_msg[b] == '1':
                    if get_undiff[-1] == '0':
                        get_undiff = get_undiff + '1'
                    else:
                        get_undiff = get_undiff + '0'
                # Same
                else:
                    if get_undiff[-1] == '0':
                        get_undiff = get_undiff + '0'
                    else:
                        get_undiff = get_undiff + '1'

                        # Manchester Encode
            get_man = ''
            for m in get_undiff:
                if m == '0':
                    get_man = get_man + '01'
                else:
                    get_man = get_man + '10'

            # Assemble
            # there are always a few extra bits, next line needs a round number too
            data = access_code + get_man + '00000'
            hex_data = '%0*X' % ((len(data) + 0) // 4, int(data, 2))  # 03F2D2B4AB4AD2AD555554D2CD4B54CD4CB2A0
            data = hex_data.decode('hex')  # Python 2
            # data = bytes.fromhex(hex_string)  # Python 3

            # Send the PDU
            car = pmt.make_dict()
            # data = '\x03\xF2\xD2\xB4\xAB\x4A\xD2\xAD\x54\xD5\x52\xD3\x34\xB5\x54\xCD\x2A\xAC\xB0\x00'  # real data
            # data = '\xFF\xF2\xD2\xB4\xAB\x4A\xD2\xAD\x54\xD5\x52\xD3\x34\xB5\x54\xCD\x2A\xAC\x00\x00'  # delay test
            # data = bytes(data)
            data = numpy.frombuffer(data, dtype=numpy.uint8)
            cdr = pmt.to_pmt(data)
            pdu = pmt.cons(car, cdr)

            try:
                self.message_port_pub(pmt.intern('out'), pdu)
            except:
                sys.exit(1)

            # Sleep and Repeat
            time.sleep(self.repetition_interval)