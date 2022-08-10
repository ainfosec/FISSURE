# Copyright 2011 Free Software Foundation, Inc.
#
# This file is part of GNU Radio
#
# GNU Radio is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3, or (at your option)
# any later version.
#
# GNU Radio is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with GNU Radio; see the file COPYING.  If not, write to
# the Free Software Foundation, Inc., 51 Franklin Street,
# Boston, MA 02110-1301, USA.

include(GrPython)
include(GrccCompile)
add_subdirectory(helpers)
#add_subdirectory(apps_data)

GRCC_COMPILE(grgsm_livemon)
GRCC_COMPILE(grgsm_livemon_headless)

set(grgsm_flowgraphs "")
OPTION(ENABLE_GRCC "Compile the flowgraphs with grcc" ON)
OPTION(ENABLE_GRGSM_LIVEMON "Compile grgsm_livemon" ON)
OPTION(ENABLE_GRGSM_LIVEMON_HEADLESS "Compile grgsm_livemon_headless" ON)

if(ENABLE_GRCC AND ENABLE_GRGSM_LIVEMON)
    list (APPEND grgsm_flowgraphs ${CMAKE_CURRENT_BINARY_DIR}/grgsm_livemon)
endif(ENABLE_GRCC AND ENABLE_GRGSM_LIVEMON)

if(ENABLE_GRCC AND ENABLE_GRGSM_LIVEMON_HEADLESS)
    list (APPEND grgsm_flowgraphs ${CMAKE_CURRENT_BINARY_DIR}/grgsm_livemon_headless)
endif(ENABLE_GRCC AND ENABLE_GRGSM_LIVEMON_HEADLESS)

GR_PYTHON_INSTALL(
    PROGRAMS
    ${grgsm_flowgraphs}
    grgsm_scanner
    grgsm_decode
    grgsm_trx
    DESTINATION bin
)

# The add_dependencies(...) is very important for the parallel build `make -j $(nproc)`
# The `pygen_apps` target is generated in GR_PYTHON_INSTALL function which calls
# GR_UNIQUE_TARGET that we redefine in GrccCompile.
add_dependencies(pygen_apps _grgsm_swig)

install(
    PROGRAMS
    DESTINATION bin
)
