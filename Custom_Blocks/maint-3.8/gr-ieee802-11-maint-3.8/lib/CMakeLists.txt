#
# Copyright (C) 2013, 2016 Bastian Bloessl <bloessl@ccs-labs.org>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

########################################################################
# Setup library
########################################################################
include(GrPlatform) #define LIB_SUFFIX
check_include_file("xmmintrin.h" SSE2_SUPPORTED)

if(SSE2_SUPPORTED)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -msse2")
    add_definitions(-DIEEE80211_MSSE2)
endif(SSE2_SUPPORTED)

########################################################################
# Setup library
########################################################################
list(APPEND ieee802_11_sources
    chunks_to_symbols_impl.cc
    constellations_impl.cc
    decode_mac.cc
    equalizer/base.cc
    equalizer/comb.cc
    equalizer/ls.cc
    equalizer/lms.cc
    equalizer/sta.cc
    ether_encap_impl.cc
    frame_equalizer_impl.cc
    mac.cc
    mapper.cc
    parse_mac.cc
    signal_field_impl.cc
    sync_long.cc
    sync_short.cc
    utils.cc
    viterbi_decoder/base.cc
)

# use SSE2 optimized viterbi implementation if SSE2 is enabled
if(SSE2_SUPPORTED)
    list(APPEND ieee802_11_sources
        viterbi_decoder/viterbi_decoder_x86.cc
    )
else()
    list(APPEND ieee802_11_sources
        viterbi_decoder/viterbi_decoder_generic.cc
    )
endif(SSE2_SUPPORTED)

set(ieee802_11_sources "${ieee802_11_sources}" PARENT_SCOPE)
if(NOT ieee802_11_sources)
    MESSAGE(STATUS "No C++ sources... skipping lib/")
    return()
endif(NOT ieee802_11_sources)

add_library(gnuradio-ieee802_11 SHARED ${ieee802_11_sources})
target_link_libraries(gnuradio-ieee802_11
        gnuradio::gnuradio-runtime
        gnuradio::gnuradio-filter
        gnuradio::gnuradio-blocks
        gnuradio::gnuradio-analog
        gnuradio::gnuradio-fft
        gnuradio::gnuradio-digital)
target_include_directories(gnuradio-ieee802_11
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../include>
    PUBLIC $<INSTALL_INTERFACE:include>
  )
set_target_properties(gnuradio-ieee802_11 PROPERTIES DEFINE_SYMBOL "gnuradio_ieee802_11_EXPORTS")

if(APPLE)
    set_target_properties(gnuradio-ieee802_11 PROPERTIES
        INSTALL_NAME_DIR "${CMAKE_INSTALL_PREFIX}/lib"
    )
endif(APPLE)

########################################################################
# Install built library files
########################################################################
include(GrMiscUtils)
GR_LIBRARY_FOO(gnuradio-ieee802_11)

########################################################################
# Print summary
########################################################################
message(STATUS "Using install prefix: ${CMAKE_INSTALL_PREFIX}")
message(STATUS "Building for version: ${VERSION} / ${LIBVER}")

########################################################################
# Build and register unit test
########################################################################
include(GrTest)

# If your unit tests require special include paths, add them here
#include_directories()
# List all files that contain Boost.UTF unit tests here
list(APPEND test_ieee802_11_sources
)
