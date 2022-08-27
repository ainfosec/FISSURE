# Copyright 2020 Free Software Foundation, Inc.
#
# This file is part of GNU Radio
#
# SPDX-License-Identifier: GPL-3.0-or-later
#

########################################################################
# Check if there is C++ code at all
########################################################################
if(NOT clapper_plus_sources)
    MESSAGE(STATUS "No C++ sources... skipping python bindings")
    return()
endif(NOT clapper_plus_sources)

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

list(APPEND clapper_plus_python_files
    python_bindings.cc)

GR_PYBIND_MAKE_OOT(clapper_plus
   ../../..
   gr::clapper_plus
   "${clapper_plus_python_files}")

# copy bindings extension for use in QA test module
add_custom_command(TARGET clapper_plus_python POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:clapper_plus_python>
    ${CMAKE_BINARY_DIR}/test_modules/gnuradio/clapper_plus/
)

install(TARGETS clapper_plus_python DESTINATION ${GR_PYTHON_DIR}/gnuradio/clapper_plus COMPONENT pythonapi)
