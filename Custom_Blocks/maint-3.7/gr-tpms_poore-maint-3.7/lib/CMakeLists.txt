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
list(APPEND tpms_poore_sources
    )

set(tpms_poore_sources "${tpms_poore_sources}" PARENT_SCOPE)
if(NOT tpms_poore_sources)
	MESSAGE(STATUS "No C++ sources... skipping lib/")
	return()
endif(NOT tpms_poore_sources)

add_library(gnuradio-tpms_poore SHARED ${tpms_poore_sources})
target_link_libraries(gnuradio-tpms_poore ${Boost_LIBRARIES} ${GNURADIO_ALL_LIBRARIES})
set_target_properties(gnuradio-tpms_poore PROPERTIES DEFINE_SYMBOL "gnuradio_tpms_poore_EXPORTS")

if(APPLE)
    set_target_properties(gnuradio-tpms_poore PROPERTIES
        INSTALL_NAME_DIR "${CMAKE_INSTALL_PREFIX}/lib"
    )
endif(APPLE)

########################################################################
# Install built library files
########################################################################
include(GrMiscUtils)
GR_LIBRARY_FOO(gnuradio-tpms_poore RUNTIME_COMPONENT "tpms_poore_runtime" DEVEL_COMPONENT "tpms_poore_devel")

########################################################################
# Build and register unit test
########################################################################
include(GrTest)

include_directories(${CPPUNIT_INCLUDE_DIRS})

list(APPEND test_tpms_poore_sources
    ${CMAKE_CURRENT_SOURCE_DIR}/test_tpms_poore.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/qa_tpms_poore.cc
)

add_executable(test-tpms_poore ${test_tpms_poore_sources})

target_link_libraries(
  test-tpms_poore
  ${GNURADIO_RUNTIME_LIBRARIES}
  ${Boost_LIBRARIES}
  ${CPPUNIT_LIBRARIES}
  gnuradio-tpms_poore
)

GR_ADD_TEST(test_tpms_poore test-tpms_poore)

########################################################################
# Print summary
########################################################################
message(STATUS "Using install prefix: ${CMAKE_INSTALL_PREFIX}")
message(STATUS "Building for version: ${VERSION} / ${LIBVER}")

