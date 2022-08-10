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

add_sources(
    burst_file_sink_impl.cc
    burst_file_source_impl.cc
    bursts_printer_impl.cc
    collect_system_info_impl.cc
    controlled_fractional_resampler_cc_impl.cc
    controlled_rotator_cc_impl.cc
    extract_cmc_impl.cc
    extract_assignment_cmd_impl.cc
    extract_immediate_assignment_impl.cc
    extract_system_info_impl.cc
    message_file_sink_impl.cc
    message_file_source_impl.cc
    message_printer_impl.cc
    msg_to_tag_impl.cc
    tmsi_dumper_impl.cc
    time_spec.cc
    fn_time.cc
    udp_socket.cc
    burst_to_fn_time_impl.cc
)

