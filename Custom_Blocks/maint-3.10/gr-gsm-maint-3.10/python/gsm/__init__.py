#
# Copyright 2008,2009 Free Software Foundation, Inc.
#
# This application is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3, or (at your option)
# any later version.
#
# This application is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#

# The presence of this file turns this directory into a Python package

'''
This is the GNU Radio GSM module. Place your Python package
description here (python/__init__.py).
'''

import os

if "CMAKE_BINARY_DIR" in os.environ:
    dirname, filename = os.path.split(os.path.abspath(__file__))

    # As the directory structure in the repository is different then the one after the package
    # gets installed we need to add those subdirectories to the __path__ otherwise python3 is
    # not able to load the modules using the relative import syntax and grcc compilation and
    # some unit tests fail.
    __path__ += [
        # Load the local (not yet installed) python modules from the local subdirectories
        os.path.join(dirname, "misc_utils"),
        os.path.join(dirname, "receiver"),
        os.path.join(dirname, "demapping"),
        os.path.join(dirname, "transmitter"),
        os.path.join(dirname, "trx")]

# import pybind11 generated symbols into the gsm namespace
try:
    # this might fail if the module is python-only
    from .gsm_python import *
except ModuleNotFoundError:
    pass

try:
    # import any pure python here

    #from fcch_burst_tagger import fcch_burst_tagger
    #from sch_detector import sch_detector
    #from fcch_detector import fcch_detector
    from .clock_offset_corrector_tagged import clock_offset_corrector_tagged
    from .gsm_input import gsm_input
    from .gsm_bcch_ccch_demapper import gsm_bcch_ccch_demapper
    from .gsm_bcch_ccch_sdcch4_demapper import gsm_bcch_ccch_sdcch4_demapper
    from .gsm_sdcch8_demapper import gsm_sdcch8_demapper
    from .gsm_gmsk_mod import gsm_gmsk_mod
    from .fn_time import *
    from .txtime_bursts_tagger import *
    from .arfcn import *
    from .device import *
except ImportError as e:
    import traceback; traceback.print_exc()
    raise
