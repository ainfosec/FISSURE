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

install(FILES
    gsm_extract_system_info.xml
    gsm_extract_immediate_assignment.xml
    gsm_collect_system_info.xml
    gsm_extract_cmc.xml
    gsm_extract_assignment_cmd.xml
    gsm_controlled_rotator_cc.xml
    gsm_message_printer.xml
    gsm_bursts_printer.xml
    gsm_clock_offset_corrector_tagged.xml
    gsm_tmsi_dumper.xml
    gsm_burst_file_sink.xml
    gsm_burst_file_source.xml
    gsm_message_file_sink.xml
    gsm_message_file_source.xml
    gsm_msg_to_tag.xml
    gsm_controlled_fractional_resampler_cc.xml
    gsm_burst_to_fn_time.xml
    DESTINATION share/gnuradio/grc/blocks
)
