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

list(APPEND ieee802_15_4_libs
    ${Boost_LIBRARIES}
    ${GNURADIO_ALL_LIBRARIES}
    ${VOLK_LIBRARIES}
)

add_library(gnuradio-ieee802_15_4 SHARED ${ieee802_15_4_sources})
target_link_libraries(gnuradio-ieee802_15_4 ${ieee802_15_4_libs})
set_target_properties(gnuradio-ieee802_15_4 PROPERTIES DEFINE_SYMBOL "gnuradio_ieee802_15_4_EXPORTS")

#####################################################################
# Install built library files
#####################################################################
install(TARGETS gnuradio-ieee802_15_4
    LIBRARY DESTINATION lib${LIB_SUFFIX} # .so/.dylib file
    ARCHIVE DESTINATION lib${LIB_SUFFIX} # .lib file
    RUNTIME DESTINATION bin              # .dll file
)

