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
    from nrsc5 import l1_fm_encoder
except ImportError:
    import os
    import sys
    dirname, filename = os.path.split(os.path.abspath(__file__))
    sys.path.append(os.path.join(dirname, "bindings"))
    from nrsc5 import l1_fm_encoder

class qa_l1_fm_encoder(gr_unittest.TestCase):

    def setUp(self):
        self.tb = gr.top_block()

    def tearDown(self):
        self.tb = None

    def test_instance(self):
        instance = l1_fm_encoder(psm=1)
        instance = l1_fm_encoder(psm=2)
        instance = l1_fm_encoder(psm=3)
        instance = l1_fm_encoder(psm=11)
        instance = l1_fm_encoder(psm=5)
        instance = l1_fm_encoder(psm=5, ssm=1)
        instance = l1_fm_encoder(psm=5, ssm=2)
        instance = l1_fm_encoder(psm=5, ssm=3)
        instance = l1_fm_encoder(psm=5, ssm=4)
        instance = l1_fm_encoder(psm=6)
        instance = l1_fm_encoder(psm=6, ssm=1)
        instance = l1_fm_encoder(psm=6, ssm=2)
        instance = l1_fm_encoder(psm=6, ssm=3)
        instance = l1_fm_encoder(psm=6, ssm=4)

    def test_001_descriptive_test_name(self):
        # set up fg
        self.tb.run()
        # check data


if __name__ == '__main__':
    gr_unittest.run(qa_l1_fm_encoder)
