# Copyright 2020 Free Software Foundation, Inc.
#
# This file is part of GNU Radio
#
# SPDX-License-Identifier: GPL-3.0-or-later
#

########################################################################
# Check if there is C++ code at all
########################################################################
if(NOT ieee802_15_4_sources)
    MESSAGE(STATUS "No C++ sources... skipping python bindings")
    return()
endif(NOT ieee802_15_4_sources)

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

list(APPEND ieee802_15_4_python_files
    access_code_prefixer_python.cc
    access_code_removal_b_python.cc
    chips_to_bits_fb_python.cc
    codeword_demapper_ib_python.cc
    codeword_mapper_bi_python.cc
    codeword_soft_demapper_fb_python.cc
    deinterleaver_ff_python.cc
    dqcsk_demapper_cc_python.cc
    dqcsk_mapper_fc_python.cc
    dqpsk_mapper_ff_python.cc
    dqpsk_soft_demapper_cc_python.cc
    frame_buffer_cc_python.cc
    interleaver_ii_python.cc
    mac_python.cc
    multiuser_chirp_detector_cc_python.cc
    packet_sink_python.cc
    phr_prefixer_python.cc
    phr_removal_python.cc
    preamble_sfd_prefixer_ii_python.cc
    preamble_tagger_cc_python.cc
    qpsk_demapper_fi_python.cc
    qpsk_mapper_if_python.cc
    rime_stack_python.cc
    zeropadding_b_python.cc
    zeropadding_removal_b_python.cc
    python_bindings.cc)

GR_PYBIND_MAKE_OOT(ieee802_15_4 
   ../..
   gr::ieee802_15_4
   "${ieee802_15_4_python_files}")

install(TARGETS ieee802_15_4_python DESTINATION ${GR_PYTHON_DIR}/ieee802_15_4 COMPONENT pythonapi)
