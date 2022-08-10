#
# Copyright 2013 Free Software Foundation, Inc.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
install(FILES
    access_code_prefixer.h
    access_code_removal_b.h
    api.h
    chips_to_bits_fb.h
    codeword_demapper_ib.h
    codeword_mapper_bi.h
    codeword_soft_demapper_fb.h
    deinterleaver_ff.h
    dqcsk_demapper_cc.h
    dqcsk_mapper_fc.h
    dqpsk_mapper_ff.h
    dqpsk_soft_demapper_cc.h
    frame_buffer_cc.h
    interleaver_ii.h
    mac.h
    multiuser_chirp_detector_cc.h
    packet_sink.h
    phr_prefixer.h
    phr_removal.h
    preamble_sfd_prefixer_ii.h
    preamble_tagger_cc.h
    qpsk_demapper_fi.h
    qpsk_mapper_if.h
    rime_stack.h
    zeropadding_b.h
    zeropadding_removal_b.h
    DESTINATION include/ieee802_15_4
)
