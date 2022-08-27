# Copyright 2020 Free Software Foundation, Inc.
#
# This file is part of GNU Radio
#
# SPDX-License-Identifier: GPL-3.0-or-later
#

########################################################################
# Check if there is C++ code at all
########################################################################
if(NOT iridium_sources)
    MESSAGE(STATUS "No C++ sources... skipping python bindings")
    return()
endif(NOT iridium_sources)

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

list(APPEND iridium_python_files
    burst_downmix_python.cc
    fft_burst_tagger_python.cc
    iridium_qpsk_demod_python.cc
    iuchar_to_complex_python.cc
    pdu_null_sink_python.cc
    pdu_round_robin_python.cc
    tagged_burst_to_pdu_python.cc
    frame_sorter_python.cc
    iridium_frame_printer_python.cc
    fft_channelizer_python.cc python_bindings.cc)

GR_PYBIND_MAKE_OOT(iridium 
   ../..
   gr::iridium
   "${iridium_python_files}")

install(TARGETS iridium_python DESTINATION ${GR_PYTHON_DIR}/iridium COMPONENT pythonapi)
