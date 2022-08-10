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
list(APPEND ais_sources
    freqest_impl.cc
    invert_impl.cc
    pdu_to_nmea_impl.cc
    msk_timing_recovery_cc_impl.cc
    corr_est_cc_impl.cc
)

set(ais_sources "${ais_sources}" PARENT_SCOPE)

add_library(gnuradio-ais SHARED ${ais_sources})
target_link_libraries(gnuradio-ais gnuradio::gnuradio-runtime gnuradio::gnuradio-fft gnuradio::gnuradio-filter)
target_include_directories(gnuradio-ais
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../include>
    PUBLIC $<INSTALL_INTERFACE:include>
    )
set_target_properties(gnuradio-ais PROPERTIES DEFINE_SYMBOL "gnuradio_ais_EXPORTS")
set_target_properties(gnuradio-ais PROPERTIES SOVERSION "${VERSION_MAJOR}")
set_target_properties(gnuradio-ais PROPERTIES VERSION "${VERSION_MAJOR}.${VERSION_MINOR}")

if(APPLE)
    set_target_properties(gnuradio-ais PROPERTIES
        INSTALL_NAME_DIR "${CMAKE_INSTALL_PREFIX}/lib"
    )
endif(APPLE)

include(GrMiscUtils)
GR_LIBRARY_FOO(gnuradio-ais)

message(STATUS "Using install prefix: ${CMAKE_INSTALL_PREFIX}")
message(STATUS "Building for version: ${VERSION} / ${LIBVER}")
