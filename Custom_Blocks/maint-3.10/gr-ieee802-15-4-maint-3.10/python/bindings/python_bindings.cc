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
void bind_access_code_prefixer(py::module& m);
void bind_access_code_removal_b(py::module& m);
void bind_chips_to_bits_fb(py::module& m);
void bind_codeword_demapper_ib(py::module& m);
void bind_codeword_mapper_bi(py::module& m);
void bind_codeword_soft_demapper_fb(py::module& m);
void bind_deinterleaver_ff(py::module& m);
void bind_dqcsk_demapper_cc(py::module& m);
void bind_dqcsk_mapper_fc(py::module& m);
void bind_dqpsk_mapper_ff(py::module& m);
void bind_dqpsk_soft_demapper_cc(py::module& m);
void bind_frame_buffer_cc(py::module& m);
void bind_interleaver_ii(py::module& m);
void bind_mac(py::module& m);
void bind_multiuser_chirp_detector_cc(py::module& m);
void bind_packet_sink(py::module& m);
void bind_phr_prefixer(py::module& m);
void bind_phr_removal(py::module& m);
void bind_preamble_sfd_prefixer_ii(py::module& m);
void bind_preamble_tagger_cc(py::module& m);
void bind_qpsk_demapper_fi(py::module& m);
void bind_qpsk_mapper_if(py::module& m);
void bind_rime_stack(py::module& m);
void bind_zeropadding_b(py::module& m);
void bind_zeropadding_removal_b(py::module& m);
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

PYBIND11_MODULE(ieee802_15_4_python, m)
{
    // Initialize the numpy C API
    // (otherwise we will see segmentation faults)
    init_numpy();

    // Allow access to base block methods
    py::module::import("gnuradio.gr");

    /**************************************/
    // The following comment block is used for
    // gr_modtool to insert binding function calls
    // Please do not delete
    /**************************************/
    // BINDING_FUNCTION_CALLS(
    bind_access_code_prefixer(m);
    bind_access_code_removal_b(m);
    bind_chips_to_bits_fb(m);
    bind_codeword_demapper_ib(m);
    bind_codeword_mapper_bi(m);
    bind_codeword_soft_demapper_fb(m);
    bind_deinterleaver_ff(m);
    bind_dqcsk_demapper_cc(m);
    bind_dqcsk_mapper_fc(m);
    bind_dqpsk_mapper_ff(m);
    bind_dqpsk_soft_demapper_cc(m);
    bind_frame_buffer_cc(m);
    bind_interleaver_ii(m);
    bind_mac(m);
    bind_multiuser_chirp_detector_cc(m);
    bind_packet_sink(m);
    bind_phr_prefixer(m);
    bind_phr_removal(m);
    bind_preamble_sfd_prefixer_ii(m);
    bind_preamble_tagger_cc(m);
    bind_qpsk_demapper_fi(m);
    bind_qpsk_mapper_if(m);
    bind_rime_stack(m);
    bind_zeropadding_b(m);
    bind_zeropadding_removal_b(m);
    // ) END BINDING_FUNCTION_CALLS
}
