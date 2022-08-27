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
void bind_burst_tagger(py::module& m);
void bind_channel_model(py::module& m);
void bind_packet_dropper(py::module& m);
void bind_packet_pad2(py::module& m);
void bind_packet_pad(py::module& m);
void bind_pad_tagged_stream(py::module& m);
void bind_periodic_msg_source(py::module& m);
void bind_random_periodic_msg_source(py::module& m);
void bind_rtt_measure(py::module& m);
void bind_wireshark_connector(py::module& m);
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

PYBIND11_MODULE(foo_python, m)
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
    bind_burst_tagger(m);
    bind_channel_model(m);
    bind_packet_dropper(m);
    bind_packet_pad2(m);
    bind_packet_pad(m);
    bind_pad_tagged_stream(m);
    bind_periodic_msg_source(m);
    bind_random_periodic_msg_source(m);
    bind_rtt_measure(m);
    bind_wireshark_connector(m);
    // ) END BINDING_FUNCTION_CALLS
}
