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

# ----------------------------------------------------------------
# Temporary workaround for ticket:181 (swig+python problem)
import sys
_RTLD_GLOBAL = 0
try:
    from dl import RTLD_GLOBAL as _RTLD_GLOBAL
except ImportError:
    try:
	from DLFCN import RTLD_GLOBAL as _RTLD_GLOBAL
    except ImportError:
	pass

if _RTLD_GLOBAL != 0:
    _dlopenflags = sys.getdlopenflags()
    sys.setdlopenflags(_dlopenflags|_RTLD_GLOBAL)
# ----------------------------------------------------------------


# import swig generated symbols into the gsm namespace
from grgsm_swig import *

# import any pure python here

from hier_block import hier_block
#from fcch_burst_tagger import fcch_burst_tagger
#from sch_detector import sch_detector
#from fcch_detector import fcch_detector
from clock_offset_corrector_tagged import clock_offset_corrector_tagged
from gsm_input import gsm_input
from gsm_bcch_ccch_demapper import gsm_bcch_ccch_demapper
from gsm_bcch_ccch_sdcch4_demapper import gsm_bcch_ccch_sdcch4_demapper
from gsm_sdcch8_demapper import gsm_sdcch8_demapper
from gsm_gmsk_mod import gsm_gmsk_mod
from fn_time import *
from txtime_bursts_tagger import *
import arfcn
import device


#

# ----------------------------------------------------------------
# Tail of workaround
if _RTLD_GLOBAL != 0:
    sys.setdlopenflags(_dlopenflags)      # Restore original flags
# ----------------------------------------------------------------
