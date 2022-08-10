# Copyright 2011,2012 Free Software Foundation, Inc.
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
list(APPEND iridium_sources
    fft_burst_tagger_impl.cc
    iuchar_to_complex_impl.cc
    tagged_burst_to_pdu_impl.cc
    burst_downmix_impl.cc
    pdu_null_sink_impl.cc
    iridium_qpsk_demod_cpp_impl.cc
    pdu_round_robin_impl.cc )

set(iridium_sources "${iridium_sources}" PARENT_SCOPE)
if(NOT iridium_sources)
	MESSAGE(STATUS "No C++ sources... skipping lib/")
	return()
endif(NOT iridium_sources)

add_library(gnuradio-iridium SHARED ${iridium_sources})
target_link_libraries(gnuradio-iridium ${Boost_LIBRARIES} ${GNURADIO_ALL_LIBRARIES})
set_target_properties(gnuradio-iridium PROPERTIES DEFINE_SYMBOL "gnuradio_iridium_EXPORTS")

if(APPLE)
    set_target_properties(gnuradio-iridium PROPERTIES
        INSTALL_NAME_DIR "${CMAKE_INSTALL_PREFIX}/lib"
    )
endif(APPLE)

##set_target_properties(gnuradio-iridium PROPERTIES CXX_STANDARD_REQUIRED 11)
set(CMAKE_CXX_FLAGS "-std=c++11")

########################################################################
# Install built library files
########################################################################
install(TARGETS gnuradio-iridium
    LIBRARY DESTINATION lib${LIB_SUFFIX} # .so/.dylib file
    ARCHIVE DESTINATION lib${LIB_SUFFIX} # .lib file
    RUNTIME DESTINATION bin              # .dll file
)

########################################################################
# Build and register unit test
########################################################################
include(GrTest)

include_directories(${CPPUNIT_INCLUDE_DIRS})

list(APPEND test_iridium_sources
    ${CMAKE_CURRENT_SOURCE_DIR}/test_iridium.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/qa_iridium.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/qa_fft_burst_tagger.cc
)

add_executable(test-iridium ${test_iridium_sources})

target_link_libraries(
  test-iridium
  ${GNURADIO_RUNTIME_LIBRARIES}
  ${Boost_LIBRARIES}
  ${CPPUNIT_LIBRARIES}
  gnuradio-iridium
)

GR_ADD_TEST(test_iridium test-iridium)
