# Copyright 2020 Free Software Foundation, Inc.
#
# This file is part of GNU Radio
#
# SPDX-License-Identifier: GPL-3.0-or-later
#

########################################################################
# Check if there is C++ code at all
########################################################################
if(NOT zwave_poore_sources)
    MESSAGE(STATUS "No C++ sources... skipping python bindings")
    return()
endif(NOT zwave_poore_sources)

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

list(APPEND zwave_poore_python_files
    python_bindings.cc)

GR_PYBIND_MAKE_OOT(zwave_poore
   ../../..
   gr::zwave_poore
   "${zwave_poore_python_files}")

# copy bindings extension for use in QA test module
add_custom_command(TARGET zwave_poore_python POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:zwave_poore_python>
    ${CMAKE_BINARY_DIR}/test_modules/gnuradio/zwave_poore/
)

install(TARGETS zwave_poore_python DESTINATION ${GR_PYTHON_DIR}/gnuradio/zwave_poore COMPONENT pythonapi)
