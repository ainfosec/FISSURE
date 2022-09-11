# Copyright 2020 Free Software Foundation, Inc.
#
# This file is part of GNU Radio
#
# SPDX-License-Identifier: GPL-3.0-or-later
#

########################################################################
# Check if there is C++ code at all
########################################################################
if(NOT ainfosec_sources)
    MESSAGE(STATUS "No C++ sources... skipping python bindings")
    return()
endif(NOT ainfosec_sources)

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

list(APPEND ainfosec_python_files
    wideband_detector1_python.cc
    python_bindings.cc)

GR_PYBIND_MAKE_OOT(ainfosec
   ../../..
   gr::ainfosec
   "${ainfosec_python_files}")

# copy bindings extension for use in QA test module
add_custom_command(TARGET ainfosec_python POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:ainfosec_python>
    ${CMAKE_BINARY_DIR}/test_modules/gnuradio/ainfosec/
)

install(TARGETS ainfosec_python DESTINATION ${GR_PYTHON_DIR}/gnuradio/ainfosec COMPONENT pythonapi)
