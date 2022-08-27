#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2017 Clayton Smith.
#
# SPDX-License-Identifier: GPL-3.0-or-later
#

from gnuradio import gr, gr_unittest
# from gnuradio import blocks
try:
    from nrsc5 import l2_encoder
except ImportError:
    import os
    import sys
    dirname, filename = os.path.split(os.path.abspath(__file__))
    sys.path.append(os.path.join(dirname, "bindings"))
    from nrsc5 import l2_encoder

class qa_l2_encoder(gr_unittest.TestCase):

    def setUp(self):
        self.tb = gr.top_block()

    def tearDown(self):
        self.tb = None

    def test_instance(self):
        instance = l2_encoder(num_progs=1, first_prog=0, size=146176)
        instance = l2_encoder(num_progs=1, first_prog=0, size=109312)
        instance = l2_encoder(num_progs=1, first_prog=0, size=72448)
        instance = l2_encoder(num_progs=1, first_prog=0, size=30000)
        instance = l2_encoder(num_progs=1, first_prog=0, size=24000)
        instance = l2_encoder(num_progs=1, first_prog=0, size=18272)
        instance = l2_encoder(num_progs=1, first_prog=0, size=9216)
        instance = l2_encoder(num_progs=1, first_prog=0, size=4608)
        instance = l2_encoder(num_progs=1, first_prog=0, size=3750)
        instance = l2_encoder(num_progs=1, first_prog=0, size=2304)

    def test_001_descriptive_test_name(self):
        # set up fg
        self.tb.run()
        # check data


if __name__ == '__main__':
    gr_unittest.run(qa_l2_encoder)
