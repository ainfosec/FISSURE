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

list(APPEND zwave_poore_sources
)

set(zwave_poore_sources "${zwave_poore_sources}" PARENT_SCOPE)
if(NOT zwave_poore_sources)
	MESSAGE(STATUS "No C++ sources... skipping lib/")
	return()
endif(NOT zwave_poore_sources)

add_library(gnuradio-zwave_poore SHARED ${zwave_poore_sources})
target_link_libraries(gnuradio-zwave_poore ${Boost_LIBRARIES} ${GNURADIO_ALL_LIBRARIES})
set_target_properties(gnuradio-zwave_poore PROPERTIES DEFINE_SYMBOL "gnuradio_zwave_poore_EXPORTS")

if(APPLE)
    set_target_properties(gnuradio-zwave_poore PROPERTIES
        INSTALL_NAME_DIR "${CMAKE_INSTALL_PREFIX}/lib"
    )
endif(APPLE)

########################################################################
# Install built library files
########################################################################
include(GrMiscUtils)
GR_LIBRARY_FOO(gnuradio-zwave_poore RUNTIME_COMPONENT "zwave_poore_runtime" DEVEL_COMPONENT "zwave_poore_devel")

########################################################################
# Build and register unit test
########################################################################
include(GrTest)

include_directories(${CPPUNIT_INCLUDE_DIRS})

list(APPEND test_zwave_poore_sources
    ${CMAKE_CURRENT_SOURCE_DIR}/test_zwave_poore.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/qa_zwave_poore.cc
)

add_executable(test-zwave_poore ${test_zwave_poore_sources})

target_link_libraries(
  test-zwave_poore
  ${GNURADIO_RUNTIME_LIBRARIES}
  ${Boost_LIBRARIES}
  ${CPPUNIT_LIBRARIES}
  gnuradio-zwave_poore
)

GR_ADD_TEST(test_zwave_poore test-zwave_poore)

########################################################################
# Print summary
########################################################################
message(STATUS "Using install prefix: ${CMAKE_INSTALL_PREFIX}")
message(STATUS "Building for version: ${VERSION} / ${LIBVER}")

