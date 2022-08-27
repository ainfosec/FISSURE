#
# Copyright 2008,2009 Free Software Foundation, Inc.
#
# SPDX-License-Identifier: GPL-3.0-or-later
#

# The presence of this file turns this directory into a Python package

'''
This is the GNU Radio IEEE802_15_4 module. Place your Python package
description here (python/__init__.py).
'''
import os

# import pybind11 generated symbols into the ieee802_15_4 namespace
try:
    # this might fail if the module is python-only
    from .ieee802_15_4_python import *
except ModuleNotFoundError:
    pass

# import any pure python here
from .css_constants import *
from .css_phy import physical_layer as css_phy
from .css_mod import modulator as css_modulator
from .css_demod import demodulator as css_demodulator
#
