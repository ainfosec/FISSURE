#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @file
# @author (C) 2015 by Roman Khassraf <rkhassraf@gmail.com>
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

from gnuradio import gr, gr_unittest, blocks
import grgsm_swig as grgsm
import arfcn
import os
import sys

class qa_arfcn(gr_unittest.TestCase):
    def test_001_is_valid_arfcn(self):
        self.assertTrue(arfcn.is_valid_arfcn(259))
        self.assertTrue(arfcn.is_valid_arfcn(277))
        self.assertTrue(arfcn.is_valid_arfcn(293))
        self.assertFalse(arfcn.is_valid_arfcn(258))
        self.assertFalse(arfcn.is_valid_arfcn(294))

        self.assertTrue(arfcn.is_valid_arfcn(306))
        self.assertTrue(arfcn.is_valid_arfcn(323))
        self.assertTrue(arfcn.is_valid_arfcn(340))
        self.assertFalse(arfcn.is_valid_arfcn(305))
        self.assertFalse(arfcn.is_valid_arfcn(341))

        self.assertTrue(arfcn.is_valid_arfcn(128))
        self.assertTrue(arfcn.is_valid_arfcn(199))
        self.assertTrue(arfcn.is_valid_arfcn(251))
        self.assertFalse(arfcn.is_valid_arfcn(127))
        self.assertFalse(arfcn.is_valid_arfcn(252))


        self.assertTrue(arfcn.is_valid_arfcn(0))
        self.assertTrue(arfcn.is_valid_arfcn(1))
        self.assertTrue(arfcn.is_valid_arfcn(124))
        self.assertFalse(arfcn.is_valid_arfcn(125))

        self.assertTrue(arfcn.is_valid_arfcn(0))
        self.assertTrue(arfcn.is_valid_arfcn(1))
        self.assertTrue(arfcn.is_valid_arfcn(124))
        self.assertFalse(arfcn.is_valid_arfcn(125))

        self.assertTrue(arfcn.is_valid_arfcn(955))
        self.assertTrue(arfcn.is_valid_arfcn(989))
        self.assertTrue(arfcn.is_valid_arfcn(1023))
        self.assertFalse(arfcn.is_valid_arfcn(954))
        self.assertFalse(arfcn.is_valid_arfcn(1024))

        self.assertTrue(arfcn.is_valid_arfcn(512))
        self.assertTrue(arfcn.is_valid_arfcn(732))
        self.assertTrue(arfcn.is_valid_arfcn(885))
        self.assertFalse(arfcn.is_valid_arfcn(511))
        self.assertFalse(arfcn.is_valid_arfcn(886))
        
        self.assertTrue(arfcn.is_valid_arfcn(512+2**15))
        self.assertTrue(arfcn.is_valid_arfcn(691+2**15))
        self.assertTrue(arfcn.is_valid_arfcn(810+2**15))
        self.assertFalse(arfcn.is_valid_arfcn(511+2**15))
        self.assertFalse(arfcn.is_valid_arfcn(811+2**15))

    def test_002_is_valid_uplink(self):
        self.assertTrue(arfcn.is_valid_uplink(450.6e6))
        self.assertTrue(arfcn.is_valid_uplink(457.4e6))
        self.assertFalse(arfcn.is_valid_uplink(450.4e6))
        self.assertFalse(arfcn.is_valid_uplink(457.6e6))

        self.assertTrue(arfcn.is_valid_uplink(479e6))
        self.assertTrue(arfcn.is_valid_uplink(485.8e6))
        self.assertFalse(arfcn.is_valid_uplink(478.8e6))
        self.assertFalse(arfcn.is_valid_uplink(486e6))

        self.assertTrue(arfcn.is_valid_uplink(824.2e6))
        self.assertTrue(arfcn.is_valid_uplink(848.8e6))
        self.assertFalse(arfcn.is_valid_uplink(824e6))
        self.assertFalse(arfcn.is_valid_uplink(849e6))

        self.assertTrue(arfcn.is_valid_uplink(876.2e6))
        self.assertTrue(arfcn.is_valid_uplink(889.8e6))
        self.assertTrue(arfcn.is_valid_uplink(890.0e6))
        self.assertTrue(arfcn.is_valid_uplink(914.8e6))
        self.assertFalse(arfcn.is_valid_uplink(876e6))
        self.assertFalse(arfcn.is_valid_uplink(915e6))

        self.assertTrue(arfcn.is_valid_uplink(1710.2e6))
        self.assertTrue(arfcn.is_valid_uplink(1784.8e6))
        self.assertFalse(arfcn.is_valid_uplink(1710e6))
        self.assertFalse(arfcn.is_valid_uplink(1785e6))

        self.assertTrue(arfcn.is_valid_uplink(1850.2e6))
        self.assertTrue(arfcn.is_valid_uplink(1909.8e6))
        self.assertFalse(arfcn.is_valid_uplink(1850e6))
        self.assertFalse(arfcn.is_valid_uplink(1910e6))

    def test_003_is_valid_downlink(self):
        self.assertTrue(arfcn.is_valid_downlink(460.6e6))
        self.assertTrue(arfcn.is_valid_downlink(467.4e6))
        self.assertFalse(arfcn.is_valid_downlink(460.4e6))
        self.assertFalse(arfcn.is_valid_downlink(467.6e6))

        self.assertTrue(arfcn.is_valid_downlink(489e6))
        self.assertTrue(arfcn.is_valid_downlink(495.8e6))
        self.assertFalse(arfcn.is_valid_downlink(488.8e6))
        self.assertFalse(arfcn.is_valid_downlink(496e6))

        self.assertTrue(arfcn.is_valid_downlink(869.2e6))
        self.assertTrue(arfcn.is_valid_downlink(893.8e6))
        self.assertFalse(arfcn.is_valid_downlink(869e6))
        self.assertFalse(arfcn.is_valid_downlink(894e6))

        self.assertTrue(arfcn.is_valid_downlink(921.2e6))
        self.assertTrue(arfcn.is_valid_downlink(934.8e6))
        self.assertTrue(arfcn.is_valid_downlink(935.0e6))
        self.assertTrue(arfcn.is_valid_downlink(959.8e6))
        self.assertFalse(arfcn.is_valid_downlink(921e6))
        self.assertFalse(arfcn.is_valid_downlink(960e6))

        self.assertTrue(arfcn.is_valid_downlink(1805.2e6))
        self.assertTrue(arfcn.is_valid_downlink(1879.8e6))
        self.assertFalse(arfcn.is_valid_downlink(1805e6))
        self.assertFalse(arfcn.is_valid_downlink(1880e6))

        self.assertTrue(arfcn.is_valid_downlink(1930.2e6))
        self.assertTrue(arfcn.is_valid_downlink(1989.8e6))
        self.assertFalse(arfcn.is_valid_downlink(1930e6))
        self.assertFalse(arfcn.is_valid_downlink(1990e6))

    def test_004_arfcn2uplink(self):
        self.assertEqual(450.6e6, arfcn.arfcn2uplink(259))
        self.assertEqual(457.4e6, arfcn.arfcn2uplink(293))

        self.assertEqual(479e6, arfcn.arfcn2uplink(306))
        self.assertEqual(485.8e6, arfcn.arfcn2uplink(340))

        self.assertEqual(824.2e6, arfcn.arfcn2uplink(128))
        self.assertEqual(848.8e6, arfcn.arfcn2uplink(251))

        self.assertEqual(890.2e6, arfcn.arfcn2uplink(1))
        self.assertEqual(914.8e6, arfcn.arfcn2uplink(124))

        self.assertEqual(890.0e6, arfcn.arfcn2uplink(0))
        self.assertEqual(914.8e6, arfcn.arfcn2uplink(124))
        self.assertEqual(880.2e6, arfcn.arfcn2uplink(975))
        self.assertEqual(889.8e6, arfcn.arfcn2uplink(1023))

        self.assertEqual(890.0e6, arfcn.arfcn2uplink(0))
        self.assertEqual(914.8e6, arfcn.arfcn2uplink(124))
        self.assertEqual(876.2e6, arfcn.arfcn2uplink(955))
        self.assertEqual(889.8e6, arfcn.arfcn2uplink(1023))

        self.assertEqual(1710.2e6, arfcn.arfcn2uplink(512))
        self.assertEqual(1784.8e6, arfcn.arfcn2uplink(885))

        self.assertEqual(1850.2e6, arfcn.arfcn2uplink(512+2**15))
        self.assertEqual(1909.8e6, arfcn.arfcn2uplink(810+2**15))

    def test_005_arfcn2downlink(self):
        self.assertEqual(460.6e6, arfcn.arfcn2downlink(259))
        self.assertEqual(467.4e6, arfcn.arfcn2downlink(293))

        self.assertEqual(489e6, arfcn.arfcn2downlink(306))
        self.assertEqual(495.8e6, arfcn.arfcn2downlink(340))

        self.assertEqual(869.2e6, arfcn.arfcn2downlink(128))
        self.assertEqual(893.8e6, arfcn.arfcn2downlink(251))

        self.assertEqual(935.2e6, arfcn.arfcn2downlink(1))
        self.assertEqual(959.8e6, arfcn.arfcn2downlink(124))

        self.assertEqual(935.0e6, arfcn.arfcn2downlink(0))
        self.assertEqual(959.8e6, arfcn.arfcn2downlink(124))
        self.assertEqual(925.2e6, arfcn.arfcn2downlink(975))
        self.assertEqual(934.8e6, arfcn.arfcn2downlink(1023))

        self.assertEqual(935.0e6, arfcn.arfcn2downlink(0))
        self.assertEqual(959.8e6, arfcn.arfcn2downlink(124))
        self.assertEqual(921.2e6, arfcn.arfcn2downlink(955))
        self.assertEqual(934.8e6, arfcn.arfcn2downlink(1023))

        self.assertEqual(1805.2e6, arfcn.arfcn2downlink(512))
        self.assertEqual(1879.8e6, arfcn.arfcn2downlink(885))

        self.assertEqual(1930.2e6, arfcn.arfcn2downlink(512+2**15))
        self.assertEqual(1989.8e6, arfcn.arfcn2downlink(810+2**15))
    def test_006_uplink2arfcn(self):
        self.assertEqual(259, arfcn.uplink2arfcn(450.6e6))
        self.assertEqual(293, arfcn.uplink2arfcn(457.4e6))

        self.assertEqual(306, arfcn.uplink2arfcn(479e6))
        self.assertEqual(340, arfcn.uplink2arfcn(485.8e6))

        self.assertEqual(128, arfcn.uplink2arfcn(824.2e6))
        self.assertEqual(251, arfcn.uplink2arfcn(848.8e6))

        self.assertEqual(1, arfcn.uplink2arfcn(890.2e6))
        self.assertEqual(124, arfcn.uplink2arfcn(914.8e6))

        self.assertEqual(0, arfcn.uplink2arfcn(890.0e6))
        self.assertEqual(124, arfcn.uplink2arfcn(914.8e6))
        self.assertEqual(975, arfcn.uplink2arfcn(880.2e6))
        self.assertEqual(1023, arfcn.uplink2arfcn(889.8e6))

        self.assertEqual(0, arfcn.uplink2arfcn(890.0e6))
        self.assertEqual(124, arfcn.uplink2arfcn(914.8e6))
        self.assertEqual(955, arfcn.uplink2arfcn(876.2e6))
        self.assertEqual(1023, arfcn.uplink2arfcn(889.8e6))

        self.assertEqual(512, arfcn.uplink2arfcn(1710.2e6))
        self.assertEqual(885, arfcn.uplink2arfcn(1784.8e6))

        self.assertEqual(512+2**15, arfcn.uplink2arfcn(1850.2e6))
        self.assertEqual(810+2**15, arfcn.uplink2arfcn(1909.8e6))

    def test_007_downlink2arfcn(self):
        self.assertEqual(259, arfcn.downlink2arfcn(460.6e6))
        self.assertEqual(293, arfcn.downlink2arfcn(467.4e6))

        self.assertEqual(306, arfcn.downlink2arfcn(489e6,))
        self.assertEqual(340, arfcn.downlink2arfcn(495.8e6))

        self.assertEqual(128, arfcn.downlink2arfcn(869.2e6))
        self.assertEqual(251, arfcn.downlink2arfcn(893.8e6))

        self.assertEqual(1, arfcn.downlink2arfcn(935.2e6))
        self.assertEqual(124, arfcn.downlink2arfcn(959.8e6))

        self.assertEqual(0, arfcn.downlink2arfcn(935.0e6))
        self.assertEqual(124, arfcn.downlink2arfcn(959.8e6))
        self.assertEqual(975, arfcn.downlink2arfcn(925.2e6))
        self.assertEqual(1023, arfcn.downlink2arfcn(934.8e6))

        self.assertEqual(0, arfcn.downlink2arfcn(935.0e6))
        self.assertEqual(124, arfcn.downlink2arfcn(959.8e6))
        self.assertEqual(955, arfcn.downlink2arfcn(921.2e6))
        self.assertEqual(1023, arfcn.downlink2arfcn(934.8e6))

        self.assertEqual(512, arfcn.downlink2arfcn(1805.2e6))
        self.assertEqual(885, arfcn.downlink2arfcn(1879.8e6))

        self.assertEqual(512+2**15, arfcn.downlink2arfcn(1930.2e6))
        self.assertEqual(810+2**15, arfcn.downlink2arfcn(1989.8e6))

    def test_008_get_arfcn_ranges(self):
        self.assertEqual(1, len(arfcn.get_arfcn_ranges('GSM450')))
        self.assertEqual(1, len(arfcn.get_arfcn_ranges('GSM480')))
        self.assertEqual(1, len(arfcn.get_arfcn_ranges('GSM850')))
        self.assertEqual(2, len(arfcn.get_arfcn_ranges('GSM900')))
        self.assertEqual(1, len(arfcn.get_arfcn_ranges('DCS1800')))
        self.assertEqual(1, len(arfcn.get_arfcn_ranges('PCS1900')))


if __name__ == '__main__':
    gr_unittest.run(qa_arfcn, "qa_arfcn.xml")
