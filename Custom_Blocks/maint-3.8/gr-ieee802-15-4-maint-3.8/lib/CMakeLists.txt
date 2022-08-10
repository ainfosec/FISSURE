#
# Copyright 2013 Free Software Foundation, Inc.
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

#####################################################################
# Setup library
#####################################################################
include(GrPlatform) #define LIB_SUFFIX

list(APPEND ieee802_15_4_sources
    access_code_prefixer.cc
    access_code_removal_b_impl.cc
    bc_connection.cc
    chips_to_bits_fb_impl.cc
    codeword_demapper_ib_impl.cc
    codeword_mapper_bi_impl.cc
    codeword_soft_demapper_fb_impl.cc
    deinterleaver_ff_impl.cc
    dqcsk_demapper_cc_impl.cc
    dqcsk_mapper_fc_impl.cc
    dqpsk_mapper_ff_impl.cc
    dqpsk_soft_demapper_cc_impl.cc
    frame_buffer_cc_impl.cc
    interleaver_ii_impl.cc
    mac.cc
    multiuser_chirp_detector_cc_impl.cc
    packet_sink.cc
    phr_prefixer_impl.cc
    phr_removal_impl.cc
    preamble_sfd_prefixer_ii_impl.cc
    preamble_tagger_cc_impl.cc
    qpsk_demapper_fi_impl.cc
    qpsk_mapper_if_impl.cc
    rime_connection.cc
    rime_stack.cc
    ruc_connection.cc
    stubborn_sender.cc
    uc_connection.cc
    zeropadding_b_impl.cc
    zeropadding_removal_b_impl.cc
)

set(ieee802_15_4_sources "${ieee802_15_4_sources}" PARENT_SCOPE)
if(NOT ieee802_15_4_sources)
    MESSAGE(STATUS "No C++ sources... skipping lib/")
    return()
endif(NOT ieee802_15_4_sources)

add_library(gnuradio-ieee802_15_4 SHARED ${ieee802_15_4_sources})
target_link_libraries(gnuradio-ieee802_15_4 gnuradio::gnuradio-runtime gnuradio::gnuradio-blocks)
target_include_directories(gnuradio-ieee802_15_4
    PUBLIC $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/../include>
    PUBLIC $<INSTALL_INTERFACE:include>
  )
set_target_properties(gnuradio-ieee802_15_4 PROPERTIES DEFINE_SYMBOL "gnuradio_ieee802_15_4_EXPORTS")

if(APPLE)
    set_target_properties(gnuradio-ieee802_15_4 PROPERTIES
        INSTALL_NAME_DIR "${CMAKE_INSTALL_PREFIX}/lib"
    )
endif(APPLE)

########################################################################
# Install built library files
########################################################################
include(GrMiscUtils)
GR_LIBRARY_FOO(gnuradio-ieee802_15_4)

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
list(APPEND test_ieee802_15_4_sources
)
# Anything we need to link to for the unit tests go here
list(APPEND GR_TEST_TARGET_DEPS gnuradio-ieee802_15_4)

if(NOT test_ieee802_15_4_sources)
    MESSAGE(STATUS "No C++ unit tests... skipping")
    return()
endif(NOT test_ieee802_15_4_sources)

foreach(qa_file ${test_ieee802_15_4_sources})
    GR_ADD_CPP_TEST("ieee802_15_4_${qa_file}"
        ${CMAKE_CURRENT_SOURCE_DIR}/${qa_file}
    )
endforeach(qa_file)
