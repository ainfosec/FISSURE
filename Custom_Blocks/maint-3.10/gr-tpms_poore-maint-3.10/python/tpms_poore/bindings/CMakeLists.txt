# Copyright 2020 Free Software Foundation, Inc.
#
# This file is part of GNU Radio
#
# SPDX-License-Identifier: GPL-3.0-or-later
#

########################################################################
# Check if there is C++ code at all
########################################################################
if(NOT tpms_poore_sources)
    MESSAGE(STATUS "No C++ sources... skipping python bindings")
    return()
endif(NOT tpms_poore_sources)

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

list(APPEND tpms_poore_python_files
    python_bindings.cc)

GR_PYBIND_MAKE_OOT(tpms_poore
   ../../..
   gr::tpms_poore
   "${tpms_poore_python_files}")

# copy bindings extension for use in QA test module
add_custom_command(TARGET tpms_poore_python POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy $<TARGET_FILE:tpms_poore_python>
    ${CMAKE_BINARY_DIR}/test_modules/gnuradio/tpms_poore/
)

install(TARGETS tpms_poore_python DESTINATION ${GR_PYTHON_DIR}/gnuradio/tpms_poore COMPONENT pythonapi)
