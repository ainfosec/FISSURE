# Copyright 2020 Free Software Foundation, Inc.
#
# This file is part of GNU Radio
#
# SPDX-License-Identifier: GPL-3.0-or-later
#

########################################################################
# Check if there is C++ code at all
########################################################################
if(NOT X10_sources)
    MESSAGE(STATUS "No C++ sources... skipping python bindings")
    return()
endif(NOT X10_sources)

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

list(APPEND X10_python_files
    python_bindings.cc)

GR_PYBIND_MAKE_OOT(X10
   ../../..
   gr::X10
   "${X10_python_files}")

# copy bindings extension for use in QA test module
add_custom_command(TARGET X10_python POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:X10_python>
    ${CMAKE_BINARY_DIR}/test_modules/gnuradio/X10/
)

install(TARGETS X10_python DESTINATION ${GR_PYTHON_DIR}/gnuradio/X10 COMPONENT pythonapi)
