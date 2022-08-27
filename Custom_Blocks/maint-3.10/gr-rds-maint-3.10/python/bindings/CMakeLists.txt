# Copyright 2020 Free Software Foundation, Inc.
#
# This file is part of GNU Radio
#
# SPDX-License-Identifier: GPL-3.0-or-later
#

########################################################################
# Check if there is C++ code at all
########################################################################
if(NOT rds_sources)
    MESSAGE(STATUS "No C++ sources... skipping python bindings")
    return()
endif(NOT rds_sources)

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

list(APPEND rds_python_files
    decoder_python.cc
    encoder_python.cc
    parser_python.cc
    python_bindings.cc)

GR_PYBIND_MAKE_OOT(rds 
   ../..
   gr::rds
   "${rds_python_files}")

install(TARGETS rds_python DESTINATION ${GR_PYTHON_DIR}/rds COMPONENT pythonapi)
