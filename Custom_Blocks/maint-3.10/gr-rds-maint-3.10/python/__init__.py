#
# Copyright 2008,2009 Free Software Foundation, Inc.
#
# SPDX-License-Identifier: GPL-3.0-or-later
#

# The presence of this file turns this directory into a Python package

'''
This is the GNU Radio RDS module. Place your Python package
description here (python/__init__.py).
'''
import os

# import pybind11 generated symbols into the rds namespace
try:
    from .bindings.rds_python import *
except ModuleNotFoundError:
    from .rds_python import *

# import any pure python here
from .rdspanel import rdsPanel
