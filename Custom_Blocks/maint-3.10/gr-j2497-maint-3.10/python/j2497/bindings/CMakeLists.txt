# Copyright 2020 Free Software Foundation, Inc.
#
# This file is part of GNU Radio
#
# SPDX-License-Identifier: GPL-3.0-or-later
#

########################################################################
# Check if there is C++ code at all
########################################################################
if(NOT j2497_sources)
    MESSAGE(STATUS "No C++ sources... skipping python bindings")
    return()
endif(NOT j2497_sources)

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

list(APPEND j2497_python_files
    python_bindings.cc)

GR_PYBIND_MAKE_OOT(j2497
   ../../..
   gr::j2497
   "${j2497_python_files}")

# copy bindings extension for use in QA test module
add_custom_command(TARGET j2497_python POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:j2497_python>
    ${CMAKE_BINARY_DIR}/test_modules/gnuradio/j2497/
)

install(TARGETS j2497_python DESTINATION ${GR_PYTHON_DIR}/gnuradio/j2497 COMPONENT pythonapi)
