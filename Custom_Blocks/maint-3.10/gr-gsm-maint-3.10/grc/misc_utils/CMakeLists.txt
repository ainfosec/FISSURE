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

install(
    FILES
    gsm_extract_system_info.block.yml
    gsm_extract_immediate_assignment.block.yml
    gsm_collect_system_info.block.yml
    gsm_extract_cmc.block.yml
    gsm_extract_assignment_cmd.block.yml
    gsm_controlled_rotator_cc.block.yml
    gsm_message_printer.block.yml
    gsm_bursts_printer.block.yml
    gsm_clock_offset_corrector_tagged.block.yml
    gsm_tmsi_dumper.block.yml
    gsm_burst_file_sink.block.yml
    gsm_burst_file_source.block.yml
    gsm_message_file_sink.block.yml
    gsm_message_file_source.block.yml
    gsm_msg_to_tag.block.yml
    gsm_controlled_fractional_resampler_cc.block.yml
    gsm_burst_to_fn_time.block.yml
    DESTINATION share/gnuradio/grc/blocks
)
