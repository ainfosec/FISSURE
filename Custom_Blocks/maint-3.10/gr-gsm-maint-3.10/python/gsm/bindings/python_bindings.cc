/*
 * Copyright 2020 Free Software Foundation, Inc.
 *
 * This file is part of GNU Radio
 *
 * SPDX-License-Identifier: GPL-3.0-or-later
 *
 */

#include <pybind11/pybind11.h>

#define NPY_NO_DEPRECATED_API NPY_1_7_API_VERSION
#include <numpy/arrayobject.h>

namespace py = pybind11;

// Headers for binding functions
/**************************************/
// The following comment block is used for
// gr_modtool to insert function prototypes
// Please do not delete
/**************************************/
// BINDING_FUNCTION_PROTOTYPES(
void bind_burst_downmix(py::module& m);
void bind_burst_file_source(py::module& m);
void bind_fn_time(py::module& m);
void bind_burst_file_sink(py::module& m);
void bind_msg_to_tag(py::module& m);
void bind_message_printer(py::module& m);
void bind_burst_to_fn_time(py::module& m);
void bind_tmsi_dumper(py::module& m);
void bind_message_file_source(py::module& m);
//void bind_time_spec(py::module& m);
void bind_controlled_fractional_resampler_cc(py::module& m);
void bind_extract_immediate_assignment(py::module& m);
void bind_extract_assignment_cmd(py::module& m);
void bind_bursts_printer(py::module& m);
void bind_message_file_sink(py::module& m);
//void bind_udp_socket(py::module& m);
void bind_controlled_rotator_cc(py::module& m);
void bind_collect_system_info(py::module& m);
void bind_extract_system_info(py::module& m);
void bind_extract_cmc(py::module& m);
void bind_constants(py::module& m);
void bind_burst_fnr_filter(py::module& m);
void bind_burst_sdcch_subslot_splitter(py::module& m);
void bind_burst_timeslot_filter(py::module& m);
void bind_dummy_burst_filter(py::module& m);
void bind_common(py::module& m);
void bind_burst_sdcch_subslot_filter(py::module& m);
void bind_burst_type_filter(py::module& m);
void bind_burst_timeslot_splitter(py::module& m);
void bind_uplink_downlink_splitter(py::module& m);
void bind_txtime_setter(py::module& m);
void bind_gen_test_ab(py::module& m);
void bind_preprocess_tx_burst(py::module& m);
void bind_message_source(py::module& m);
void bind_burst_sink(py::module& m);
void bind_burst_source(py::module& m);
void bind_message_sink(py::module& m);
void bind_constants(py::module& m);
void bind_tch_f_decoder(py::module& m);
void bind_tch_h_decoder(py::module& m);
void bind_control_channels_decoder(py::module& m);
void bind_universal_ctrl_chans_demapper(py::module& m);
void bind_tch_f_chans_demapper(py::module& m);
void bind_tch_h_chans_demapper(py::module& m);
void bind_receiver(py::module& m);
void bind_clock_offset_control(py::module& m);
void bind_cx_channel_hopper(py::module& m);
void bind_trx_burst_if(py::module& m);
void bind_decryption(py::module& m);
// ) END BINDING_FUNCTION_PROTOTYPES


// We need this hack because import_array() returns NULL
// for newer Python versions.
// This function is also necessary because it ensures access to the C API
// and removes a warning.
void* init_numpy()
{
    import_array();
    return NULL;
}

PYBIND11_MODULE(gsm_python, m)
{
    // Initialize the numpy C API
    // (otherwise we will see segmentation faults)
    init_numpy();

    // Allow access to base block methods
    py::module::import("gnuradio.gr");
    py::module::import("gnuradio.gsm");
 
    /**************************************/
    // The following comment block is used for
    // gr_modtool to insert binding function calls
    // Please do not delete
    /**************************************/
    // BINDING_FUNCTION_CALLS(
    bind_burst_file_source(m);
    bind_fn_time(m);
    bind_burst_file_sink(m);
    bind_msg_to_tag(m);
    bind_message_printer(m);
    bind_burst_to_fn_time(m);
    bind_tmsi_dumper(m);
    bind_message_file_source(m);
    //bind_time_spec(m);
    bind_controlled_fractional_resampler_cc(m);
    bind_extract_immediate_assignment(m);
    bind_extract_assignment_cmd(m);
    bind_bursts_printer(m);
    bind_message_file_sink(m);
    //bind_udp_socket(m);
    bind_controlled_rotator_cc(m);
    bind_collect_system_info(m);
    bind_extract_system_info(m);
    bind_extract_cmc(m);
    bind_constants(m);
    bind_burst_fnr_filter(m);
    bind_burst_sdcch_subslot_splitter(m);
    bind_burst_timeslot_filter(m);
    bind_dummy_burst_filter(m);
    bind_common(m);
    bind_burst_sdcch_subslot_filter(m);
    bind_burst_type_filter(m);
    bind_burst_timeslot_splitter(m);
    bind_uplink_downlink_splitter(m);
    bind_txtime_setter(m);
    bind_gen_test_ab(m);
    bind_preprocess_tx_burst(m);
    bind_message_source(m);
    bind_burst_sink(m);
    bind_burst_source(m);
    bind_message_sink(m);
    bind_constants(m);
    bind_tch_f_decoder(m);
    bind_tch_h_decoder(m);
    bind_control_channels_decoder(m);
    bind_tch_f_chans_demapper(m);
    bind_tch_h_chans_demapper(m);
    bind_receiver(m);
    bind_clock_offset_control(m);
    bind_cx_channel_hopper(m);
    bind_trx_burst_if(m);
    bind_decryption(m);
    bind_universal_ctrl_chans_demapper(m);

    // ) END BINDING_FUNCTION_CALLS
}
