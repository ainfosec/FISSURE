# Copyright 2011 Free Software Foundation, Inc.
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
    iridium_fft_burst_tagger.xml
    iridium_iuchar_to_complex.xml
    iridium_tagged_burst_to_pdu.xml
    iridium_burst_downmix.xml
    iridium_iridium-qpsk-demod.xml
    iridium_pdu_null_sink.xml
    iridium_iridium_qpsk_demod_cpp.xml
    iridium_pdu_round_robin.xml
    iridium_iridium_frame_printer.xml
    iridium_frame_sorter.xml DESTINATION share/gnuradio/grc/blocks
)
