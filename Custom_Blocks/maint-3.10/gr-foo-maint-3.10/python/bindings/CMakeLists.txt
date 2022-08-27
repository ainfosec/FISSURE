# Copyright 2020 Free Software Foundation, Inc.
#
# This file is part of GNU Radio
#
# SPDX-License-Identifier: GPL-3.0-or-later
#

########################################################################
# Check if there is C++ code at all
########################################################################
if(NOT foo_sources)
    MESSAGE(STATUS "No C++ sources... skipping python bindings")
    return()
endif(NOT foo_sources)

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

list(APPEND foo_python_files
    python_bindings.cc

    burst_tagger_python.cc
    channel_model_python.cc
    packet_dropper_python.cc
    packet_pad2_python.cc
    packet_pad_python.cc
    pad_tagged_stream_python.cc
    periodic_msg_source_python.cc
    random_periodic_msg_source_python.cc
    rtt_measure_python.cc
    wireshark_connector_python.cc
    )

GR_PYBIND_MAKE_OOT(foo 
   ../..
   gr::foo
   "${foo_python_files}")

install(TARGETS foo_python DESTINATION ${GR_PYTHON_DIR}/foo COMPONENT pythonapi)
