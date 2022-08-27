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
void bind_chunks_to_symbols(py::module& m);
void bind_constellations(py::module& m);
void bind_decode_mac(py::module& m);
void bind_ether_encap(py::module& m);
void bind_extract_csi(py::module& m);
void bind_frame_equalizer(py::module& m);
void bind_mac(py::module& m);
void bind_mapper(py::module& m);
void bind_parse_mac(py::module& m);
void bind_signal_field(py::module& m);
void bind_sync_long(py::module& m);
void bind_sync_short(py::module& m);
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

PYBIND11_MODULE(ieee802_11_python, m)
{
    // Initialize the numpy C API
    // (otherwise we will see segmentation faults)
    init_numpy();

    // Allow access to base block methods
    py::module::import("gnuradio.gr");
    py::module::import("gnuradio.digital");

    /**************************************/
    // The following comment block is used for
    // gr_modtool to insert binding function calls
    // Please do not delete
    /**************************************/
    // BINDING_FUNCTION_CALLS(
    bind_chunks_to_symbols(m);
    bind_constellations(m);
    bind_decode_mac(m);
    bind_ether_encap(m);
    bind_extract_csi(m);
    bind_frame_equalizer(m);
    bind_mac(m);
    bind_mapper(m);
    bind_parse_mac(m);
    bind_signal_field(m);
    bind_sync_long(m);
    bind_sync_short(m);
    // ) END BINDING_FUNCTION_CALLS
}
