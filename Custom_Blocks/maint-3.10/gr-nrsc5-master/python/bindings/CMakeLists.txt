# Copyright 2020 Free Software Foundation, Inc.
#
# This file is part of GNU Radio
#
# SPDX-License-Identifier: GPL-3.0-or-later
#

########################################################################
# Check if there is C++ code at all
########################################################################
if(NOT nrsc5_sources)
    MESSAGE(STATUS "No C++ sources... skipping python bindings")
    return()
endif(NOT nrsc5_sources)

########################################################################
# Check for pygccxml
########################################################################
GR_PYTHON_CHECK_MODULE_RAW(
    "pygccxml"
    "import pygccxml"
    PYGCCXML_FOUND
    )

include(GrPybind)

########################################################################
# Python Bindings
########################################################################
list(APPEND nrsc5_python_files
    hdc_encoder_python.cc
    l1_am_encoder_python.cc
    l1_fm_encoder_python.cc
    l2_encoder_python.cc
    psd_encoder_python.cc
    sis_encoder_python.cc python_bindings.cc)

GR_PYBIND_MAKE_OOT(nrsc5
   ../..
   gr::nrsc5
   "${nrsc5_python_files}")

install(TARGETS nrsc5_python DESTINATION ${GR_PYTHON_DIR}/nrsc5 COMPONENT pythonapi)
