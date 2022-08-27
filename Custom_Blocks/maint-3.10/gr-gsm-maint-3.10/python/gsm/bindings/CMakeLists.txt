# Copyright 2020 Free Software Foundation, Inc.
#
# This file is part of GNU Radio
#
# SPDX-License-Identifier: GPL-3.0-or-later
#

########################################################################
# Check if there is C++ code at all
########################################################################
if(NOT gsm_sources)
    MESSAGE(STATUS "No C++ sources... skipping python bindings")
    return()
endif(NOT gsm_sources)

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

list(APPEND gsm_python_files
        burst_file_sink_python.cc
        burst_file_source_python.cc
        burst_fnr_filter_python.cc
        burst_sdcch_subslot_filter_python.cc
        burst_sdcch_subslot_splitter_python.cc
        burst_sink_python.cc
        burst_source_python.cc
        burst_timeslot_filter_python.cc
        burst_timeslot_splitter_python.cc
        burst_to_fn_time_python.cc
        burst_type_filter_python.cc
        bursts_printer_python.cc
        clock_offset_control_python.cc
        collect_system_info_python.cc
        common_python.cc
        constants_python.cc
        control_channels_decoder_python.cc
        controlled_fractional_resampler_cc_python.cc
        controlled_rotator_cc_python.cc
        cx_channel_hopper_python.cc
        decryption_python.cc
        dummy_burst_filter_python.cc
        extract_assignment_cmd_python.cc
        extract_cmc_python.cc
        extract_immediate_assignment_python.cc
        extract_system_info_python.cc
        fn_time_python.cc
        gen_test_ab_python.cc
        message_file_sink_python.cc
        message_file_source_python.cc
        message_printer_python.cc
        message_sink_python.cc
        message_source_python.cc
        msg_to_tag_python.cc
        preprocess_tx_burst_python.cc
        receiver_python.cc
        tch_f_chans_demapper_python.cc
        tch_f_decoder_python.cc
        tch_h_chans_demapper_python.cc
        tch_h_decoder_python.cc
        #time_spec_python.cc
        tmsi_dumper_python.cc
        trx_burst_if_python.cc
        txtime_setter_python.cc
        #udp_socket_python.cc
        universal_ctrl_chans_demapper_python.cc
        uplink_downlink_splitter_python.cc
        python_bindings.cc)

GR_PYBIND_MAKE_OOT(gsm
   ../../../
   gr::gsm
   "${gsm_python_files}")

# copy in bindings .so file for use in QA test module
add_custom_target(
  copy_bindings_for_tests ALL
  COMMAND
    ${CMAKE_COMMAND} -E copy "${CMAKE_CURRENT_BINARY_DIR}/*.so"
    ${CMAKE_BINARY_DIR}/test_modules/gnuradio/gsm/
  DEPENDS gsm_python)

install(TARGETS gsm_python DESTINATION ${GR_PYTHON_DIR}/gnuradio/gsm COMPONENT pythonapi)
