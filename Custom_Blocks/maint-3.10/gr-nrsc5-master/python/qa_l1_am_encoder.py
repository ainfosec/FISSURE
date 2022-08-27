#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2019 Clayton Smith.
#
# SPDX-License-Identifier: GPL-3.0-or-later
#

from gnuradio import gr, gr_unittest
# from gnuradio import blocks
try:
    from nrsc5 import l1_am_encoder
except ImportError:
    import os
    import sys
    dirname, filename = os.path.split(os.path.abspath(__file__))
    sys.path.append(os.path.join(dirname, "bindings"))
    from nrsc5 import l1_am_encoder

class qa_l1_am_encoder(gr_unittest.TestCase):

    def setUp(self):
        self.tb = gr.top_block()

    def tearDown(self):
        self.tb = None

    def test_instance(self):
        instance = l1_am_encoder(sm=1)
        instance = l1_am_encoder(sm=3)

    def test_001_descriptive_test_name(self):
        # set up fg
        self.tb.run()
        # check data


if __name__ == '__main__':
    gr_unittest.run(qa_l1_am_encoder)
