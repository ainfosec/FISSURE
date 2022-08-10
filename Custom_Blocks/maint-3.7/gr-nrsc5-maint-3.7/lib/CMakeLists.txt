# Copyright 2011,2012,2016 Free Software Foundation, Inc.
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

########################################################################
# Setup library
########################################################################
include(GrPlatform) #define LIB_SUFFIX

include_directories(${Boost_INCLUDE_DIR})
link_directories(${Boost_LIBRARY_DIRS})

list(APPEND nrsc5_sources
    l1_fm_encoder_impl.cc
    sis_encoder_impl.cc
    l2_encoder_impl.cc
    hdc_encoder_impl.cc
    psd_encoder_impl.cc
)

set(nrsc5_sources "${nrsc5_sources}" PARENT_SCOPE)
if(NOT nrsc5_sources)
	MESSAGE(STATUS "No C++ sources... skipping lib/")
	return()
endif(NOT nrsc5_sources)

add_library(gnuradio-nrsc5 SHARED ${nrsc5_sources})
target_link_libraries(gnuradio-nrsc5 ${Boost_LIBRARIES} ${GNURADIO_ALL_LIBRARIES} fdk-aac)
set_target_properties(gnuradio-nrsc5 PROPERTIES DEFINE_SYMBOL "gnuradio_nrsc5_EXPORTS")

if(APPLE)
    set_target_properties(gnuradio-nrsc5 PROPERTIES
        INSTALL_NAME_DIR "${CMAKE_INSTALL_PREFIX}/lib"
    )
endif(APPLE)

########################################################################
# Install built library files
########################################################################
include(GrMiscUtils)
GR_LIBRARY_FOO(gnuradio-nrsc5 RUNTIME_COMPONENT "nrsc5_runtime" DEVEL_COMPONENT "nrsc5_devel")

########################################################################
# Build and register unit test
########################################################################
include(GrTest)

include_directories(${CPPUNIT_INCLUDE_DIRS})

list(APPEND test_nrsc5_sources
    ${CMAKE_CURRENT_SOURCE_DIR}/test_nrsc5.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/qa_nrsc5.cc
)

add_executable(test-nrsc5 ${test_nrsc5_sources})

target_link_libraries(
  test-nrsc5
  ${GNURADIO_RUNTIME_LIBRARIES}
  ${Boost_LIBRARIES}
  ${CPPUNIT_LIBRARIES}
  gnuradio-nrsc5
)

GR_ADD_TEST(test_nrsc5 test-nrsc5)

########################################################################
# Print summary
########################################################################
message(STATUS "Using install prefix: ${CMAKE_INSTALL_PREFIX}")
message(STATUS "Building for version: ${VERSION} / ${LIBVER}")
