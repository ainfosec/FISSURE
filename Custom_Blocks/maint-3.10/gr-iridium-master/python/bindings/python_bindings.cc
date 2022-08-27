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
    void bind_fft_burst_tagger(py::module& m);
    void bind_iridium_qpsk_demod(py::module& m);
    void bind_iuchar_to_complex(py::module& m);
    void bind_pdu_null_sink(py::module& m);
    void bind_pdu_round_robin(py::module& m);
    void bind_tagged_burst_to_pdu(py::module& m);
    void bind_frame_sorter(py::module& m);
    void bind_iridium_frame_printer(py::module& m);
    void bind_fft_channelizer(py::module& m);
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

PYBIND11_MODULE(iridium_python, m)
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
    bind_burst_downmix(m);
    bind_fft_burst_tagger(m);
    bind_iridium_qpsk_demod(m);
    bind_iuchar_to_complex(m);
    bind_pdu_null_sink(m);
    bind_pdu_round_robin(m);
    bind_tagged_burst_to_pdu(m);
    bind_frame_sorter(m);
    bind_iridium_frame_printer(m);
    bind_fft_channelizer(m);
    // ) END BINDING_FUNCTION_CALLS
}