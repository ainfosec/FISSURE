#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# MIT License
#
# Copyright (c) 2019 - 2022 Assured Information Security, Inc.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#

import binascii
from functools import reduce
import struct
from tabnanny import check
import numpy, scipy
from scipy.signal import chirp
from gnuradio import gr
import pmt
import time

class encoder(gr.sync_block):
    """
    docstring for block encoder

    TODO option for emitting preamble or not
    TODO list of messages to send on a loop
    """
    def __init__(self, mid, data, interval, sample_rate):
        gr.sync_block.__init__(self,
            name="J2497_encoder",
            in_sig=[],
            out_sig=[numpy.complex64])

        self.data_chirp_data = encoder.generate_single_complex_chirp(sample_rate)
        self.preamble_chirp_data = self.data_chirp_data
        self.replay_data = numpy.zeros(0,numpy.complex64)
        self.transmit = False
        self.replay_index = 0
        self.replay_stop_index = 0
        self.samp_rate = sample_rate

        self.rev_mid_bits = bin(int(mid,16))[2:].zfill(8)[::-1]  # e.g. 0x0A -> 01010000
        self.mid_hex = mid
        self.rev_data_bits = ''.join(['{0:08b}'.format(int(data[i:i+2],16))[::-1] for i in range(0, len(data), 2)])  # e.g. fe89 -> 0111111110010001
        self.data_hex = data
        self.interval = interval
        self.timer = time.time()
        self.count = 0

    @staticmethod
    def generate_single_chirp(samp_rate, phase=0):
        wave = numpy.hstack((
            numpy.tile(numpy.hstack((
                chirp(numpy.linspace(0, 63E-6, int(63E-6 * samp_rate)),
                    f0=203E3, f1=400E3, t1=63E-6, phi=-90 + phase, method='linear'),
                chirp(numpy.linspace(63E-6, 67E-6, int(4E-6 * samp_rate)),
                    f0=400E3, f1=100E3, t1=67E-6, phi=-90 + phase, method='linear'),
                chirp(numpy.linspace(67E-6, 100E-6, int(33E-6 * samp_rate)),
                    f0=100E3, f1=200E3, t1=100E-6, phi=-90 + phase, method='linear')
            )), 1)
        ))
        target_len = int(100e-6 * samp_rate)
        wave = numpy.append(wave, numpy.zeros(numpy.max([0, target_len - len(wave)])))
        return wave

    @staticmethod
    def generate_single_complex_chirp(samp_rate):
        return        encoder.generate_single_chirp(samp_rate) \
               + 1j * encoder.generate_single_chirp(samp_rate, phase=-90)

    def work(self, input_items, output_items):
        in0 = 0
        out = output_items[0]

        # Rough Interval Timer
        if time.time() > (self.timer + self.interval):
            self.timer = time.time()
            self.count = self.count + 1
            self.generateMsg()

        # Transmit
        if self.transmit is True:

            # Begin
            if self.replay_index + len(out) > self.replay_stop_index:
                out[:] = numpy.append(self.replay_data[self.replay_index:self.replay_stop_index], numpy.zeros(len(out)-(self.replay_stop_index-self.replay_index)))
                self.transmit = False
            else:
                out[:] = self.replay_data[self.replay_index:self.replay_index + len(out)]
                self.replay_index = self.replay_index + len(out)

        # Do Nothing
        else:
            out[:] = in0

        return len(output_items[0])

    @staticmethod
    def toSignedChar(num):
        if type(num) is bytes:
            return struct.unpack('b',num)[0]
        else:
            return struct.unpack('b',struct.pack('B',num & 0xFF))[0]

    def checksum(self):
        msg = binascii.unhexlify(self.mid_hex + self.data_hex)
        return struct.pack('b', self.toSignedChar(~reduce(lambda x,y: (x + y) & 0xFF, list(msg)) + 1))[0]

    def generateMsg(self):
        """ Generates the IQ data for the J2497 message.
        """
        # Extract Input Data
        #print("Handle Message")
        body_rev_bits = self.rev_mid_bits + self.rev_data_bits
        rev_mid_bits = self.rev_mid_bits

        # Construct Preamble
        preamble = "00" + "0" + rev_mid_bits + "1"

        # Construct Data Portion
        data = "11111"  # Sync
        for i in range(0, len(body_rev_bits), 8):
            # Start Bit
            data = data + "0"

            # Data Bit
            data = data + body_rev_bits[i: i+8]

            # Stop Bit
            data = data + "1"

        intflipped = '{0:08b}'.format(self.checksum())
        checksum = intflipped[::-1]                        # Reverse bit order
        #print "CHECKSUM: " + str(checksum)

        # Append Checksum and End of Msg
        data = data + "0" + checksum + "1" + "1111111"
        data_len = len(data)

        try:
            print(('Message #' + str(int(self.count)) + ': ' + data + ' | MID: 0x' + self.mid_hex + ' | Data: 0x' + self.data_hex + ' | Checksum: 0x' + '%0*X' % (2,int(checksum[::-1],2)) ))
        except:
            print(('Message #' + str(int(self.count)) + ': ' + data))

        # Create the Preamble Signal
        self.replay_data = numpy.zeros(0,numpy.complex64)
        for n in preamble:
            # 0 = Chirp
            if n == "0":
                self.replay_data = numpy.append(self.replay_data, self.preamble_chirp_data)
                self.replay_data = numpy.append(self.replay_data, numpy.zeros(int(self.samp_rate * 114e-6) - len(self.preamble_chirp_data)))

            # 1 = Silence
            else:
                self.replay_data = numpy.append(self.replay_data, numpy.zeros(int(self.samp_rate * 114e-6)))

        # Append the Data Signal
        for n in data:
            if n == "1":
                self.replay_data = numpy.append(self.replay_data, self.data_chirp_data)
            else:
                self.replay_data = numpy.append(self.replay_data, self.data_chirp_data * -1.)

        # Begin to Transmit
        self.replay_index = 0
        self.replay_stop_index = len(self.replay_data)
        self.transmit = True

