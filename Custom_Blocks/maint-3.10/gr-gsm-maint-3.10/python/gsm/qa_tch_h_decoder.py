#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @file
# @author (C) 2018 by Vasil Velichkov <vvvelichkov@gmail.com>
# @section LICENSE
#
# Gr-gsm is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3, or (at your option)
# any later version.
#
# Gr-gsm is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with gr-gsm; see the file COPYING.  If not, write to
# the Free Software Foundation, Inc., 51 Franklin Street,
# Boston, MA 02110-1301, USA.
#
#

import numpy as np
from gnuradio import gr, gr_unittest, blocks
from gnuradio import gsm
import pmt

class qa_tch_h_decoder (gr_unittest.TestCase):

    def setUp (self):
        self.tb = gr.top_block ()
        self.b = [
            "0001010001011010010000111100010101011011110000001011100101110010011101011000001001110100100010011111111000001001011000001100100010001011011000010000",
            "0000000110100000010101000111011101101100010000101101000011000010011101011000001001110100001111000111000010100010111111011000001010111101110001000000",
            "0000001101101000100100101101000011110011010110111100110000100010011101011000001001110100001110011100011000010000000111110100111110001101101100100000",
            "0000011111010101110111001101111001001111010010000011111111010010011101011000001001110100010110000010000000000011100101111111010101111101111011101000",
            "0001001110111000101001110001010011001101101111000010111100010010011101011000001001110100111000111011000111111100001011011011111001011100110111001000",
            "0000110110000101000011001001011110110110001110001000010001000010011101011000001001110100000010100001010001011000000110001110011110001000111100110000",
            "0000001101100010101011110100000010110100111110010010001100010010011101011000001001110100100000110001101011011101011110000110100010111100101011011000",
            "0001111110100000011111010011100100001101011101000011011000000010011101011000001001110100100111110010000011100011000011001110001111110000001010011000",
            "0001010100101010111010111001000100010100000010101011010011011010011101011000001001110100010100011100101110101110000000000111101011111111100011000000",
            "0000000011011011101011000101000001001110001011101000100001011010011101011000001001110100000100011110101010100011010101010100101011101010000100000000",
            "0001010110101001110001111001110100011010000110100000111001110010011101011000001001110100100100010101000100001100100000111111000001010111100011000000",
            "0001100000100001100001100101101001101110001000101011100001010010011101011000001001110100110010110101000100100011011101111100000011100010000100000000",
            "0001010110100000010010111001000100011110101010100001010001110010011101011000001001110100110100010100000110001100000000100111000011011111100011000000",
            "0000101001110011000001000101001001101110001001100000100001110010011101011000001001110100100110110100001000100011111101111110101011100000100100000000",

            #FACCH framces 14 - 21
            "0001011000000010000000001000010111001000101111010000000010110010011101011000001001110101100000100000010010100000101000011000100011100010100000110000",
            "0000010101111010111010000001100001110101111100001010101001100010011101011000001001110101111101111101101110000010110011111111110101010000001000110000",
            "0000000000111110101010100001000000001000101110100010100100011010011101011000001001110101001010101011101010100000010100000000101111101000000000010000",
            "0000001010010101011111011011101010101000000001011111111110101010011101011000001001110101101000010000010101111011111010100001010001011101111010101000",
            "0001010100101010111010111001000100010100000010101011010011011010011101011000001001110100010100011100101110101110000000000111101011111111100011000000",
            "0000000011011011101011000101000001001110001011101000100001011010011101011000001001110100000100011110101010100011010101010100101011101010000100000000",
            "0001010110101001110001111001110100011010000110100000111001110010011101011000001001110100100100010101000100001100100000111111000001010111100011000000",
            "0001100000100001100001100101101001101110001000101011100001010010011101011000001001110100110010110101000100100011011101111100000011100010000100000000",
        ]

    def tearDown (self):
        self.tb = None

    def tchh_multirate (self, frames, timeslots, bursts, multirate, subchan):
        """
            Common TCH/H MultiRate test code
        """
        src = gsm.burst_source(frames, timeslots, bursts)
        decoder = gsm.tch_h_decoder(subchan, multirate, False);
        dst = blocks.message_debug()

        self.tb.msg_connect(src, "out", decoder, "bursts")
        self.tb.msg_connect(decoder, "voice", dst, "store")

        self.tb.run ()

        result = []
        for i in range(0, dst.num_messages()):
            pdu = dst.get_message(i)
            self.assertEqual(True, pmt.is_pair(pdu))
            data = pmt.cdr(pdu)
            self.assertEqual(True, pmt.is_blob(data))
            result.append(pmt.to_python(data).tolist())
        return result

    def test_amr7_40 (self):
        """
            TCH/H MultiRate AMR 7.40
        """
        b = self.b
        self.assertListEqual(self.tchh_multirate(
            multirate = "28111a40",
            subchan   = 0,
            frames    = [259215, 259217, 259220, 259222, 259220, 259222, 259224, 259226],
            timeslots = [     6,      6,      6,      6,      6,      6,      6,      6],
            bursts    = [  b[8],   b[9],  b[10],  b[11],  b[10],  b[11],  b[12],  b[13]]),
            [
                [0x23,0x21,0x41,0x4d,0x52,0x0a],
                [0x20,0xff,0x3c,0x67,0xe0,0x00,0x1f,0x3d,0x01,0xf0,0xfc,0x3f,0x77,0x18,0x61,0x86,0x00,0x00,0x00,0x00]
            ])

    def test_4_75 (self):
        """
            TCH/H MultiRate AMR 4.75
        """
        b = self.b
        self.assertListEqual(self.tchh_multirate(
            multirate = "28111a40",
            subchan   = 0,
            frames    = [259666, 259668, 259670, 259672, 259670, 259672, 259675, 259677],
            timeslots = [     6,      6,      6,      6,      6,      6,      6,      6],
            bursts    = [  b[2],   b[3],   b[4],   b[5],   b[4],   b[5],   b[6],    b[7]]),
            [
                [0x23,0x21,0x41,0x4d,0x52,0x0a],
                [0x00,0x67,0x19,0x24,0xd5,0x1b,0xd1,0x29,0x3f,0xa1,0x50,0x5f,0x3e]
            ])

    def test_amr7_40_and_4_75 (self):
        """
            TCH/H MultiRate AMR 7.40 and 4.75
            Two 7.40 followed by two 4.75 frames
        """
        b = self.b
        self.assertListEqual(self.tchh_multirate(
            multirate= "28111a40",
            subchan  = 0,
            frames   = [259657, 259659, 259662, 259664,
                        259662, 259664, 259666, 259668,
                        259666, 259668, 259670, 259672,
                        259670, 259672, 259675, 259677,
                        259675, 259677, 259679, 259681],
            timeslots= [     6,      6,      6,      6,
                             6,      6,      6,      6,
                             6,      6,      6,      6,
                             6,      6,      6,      6,
                             6,      6,      6,      6],
            bursts   = [  b[0],   b[1],   b[2],    b[3],
                          b[0],   b[1],   b[2],    b[3],
                          b[2],   b[3],   b[4],    b[5],
                          b[2],   b[3],   b[4],    b[5],
                          b[4],   b[5],   b[6],    b[7]]),
            [
                [0x23,0x21,0x41,0x4d,0x52,0x0a],
                [0x20,0xe0,0x27,0x2a,0x00,0x21,0x30,0x38,0x75,0xf8,0x14,0x3c,0xec,0xde,0x0b,0x47,0x6f,0x9c,0xc6,0x70],
                [0x20,0xe0,0x27,0x2a,0x00,0x21,0x30,0x38,0x75,0xf8,0x14,0x3c,0xec,0xde,0x0b,0x47,0x6f,0x9c,0xc6,0x70],
                [0x00,0x67,0x19,0x24,0xd5,0x1b,0xd1,0x29,0x3f,0xa1,0x50,0x5f,0x3e],
                [0x00,0x67,0x19,0x24,0xd5,0x1b,0xd1,0x29,0x3f,0xa1,0x50,0x5f,0x3e],
            ])

    def facch_test (self, frames, timeslots, bursts):
        '''
            Common FACCH/TH test code
        '''
        src = gsm.burst_source(frames, timeslots, bursts)
        decoder = gsm.tch_h_decoder(0, "28111a40", False);
        dst = blocks.message_debug()
        facch = gsm.message_sink()

        self.tb.msg_connect(src, "out", decoder, "bursts")
        self.tb.msg_connect(decoder, "voice", dst, "store")
        self.tb.msg_connect(decoder, "msgs", facch, "in")

        self.tb.run ()

        self.assertEqual(dst.num_messages(), 0)
        return list(facch.get_messages())

    def test_facch_th (self):
        """
            FACCH/TH test
        """
        b = self.b
        self.assertEqual(self.facch_test(
            frames=     [259207, 259209, 259211, 259213, 259211, 259213, 259215, 259217],
            timeslots = [     6,      6,      6,      6,      6,      6,      6,      6],
            bursts =    [ b[14],  b[15],  b[16],  b[17],  b[16],  b[17],  b[18],   b[19]]),
            ['02 04 01 06 00 00 00 00 00 03 f4 8b 06 00 00 00 03 60 09 03 0f 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b'])

    def test_facch_th_error (self):
        """
            FACCH/TH Error handling test
        """
        b = self.b
        self.assertEqual(self.facch_test(
            frames=     [259207, 259209, 259211, 259213, 259211, 259213, 259215, 259217],
            timeslots = [     6,      6,      6,      6,      6,      6,      6,      6],
            bursts =    [ b[16],  b[17],  b[18],  b[19],   b[18],  b[19],  b[20], b[21]]),
            []) #Must return an empty array

if __name__ == '__main__':
    gr_unittest.run(qa_tch_h_decoder)
