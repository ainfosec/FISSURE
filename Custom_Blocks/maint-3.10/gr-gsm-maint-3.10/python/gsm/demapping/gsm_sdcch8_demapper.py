#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @file
# @author (C) 2016 by Piotr Krysik <ptrkrysik@gmail.com>
# @section LICENSE
#
# Gr-gsm is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3, or (at your option)
# any later version.
#
# Gr-gsm is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with gr-gsm; see the file COPYING.  If not, write to
# the Free Software Foundation, Inc., 51 Franklin Street,
# Boston, MA 02110-1301, USA.
#
##################################################
# GNU Radio Python Flow Graph
# Title: SDCCH/8 demapper
# Author: Piotr Krysik
# Description: Demapper for SDCCH/8 + SACCH/C8 control channels. This corresponds to channel combination vii specified in GSM 05.02, section 6.4
# Generated: Mon May 23 09:32:48 2016
##################################################

from gnuradio import gr
from gnuradio.filter import firdes
from gnuradio import gsm


class gsm_sdcch8_demapper(gr.hier_block2):

    def __init__(self, timeslot_nr=1):
        gr.hier_block2.__init__(
            self, "SDCCH/8 demapper",
            gr.io_signature(0, 0, 0),
            gr.io_signature(0, 0, 0),
        )
        self.message_port_register_hier_in("bursts")
        self.message_port_register_hier_out("bursts")

        ##################################################
        # Parameters
        ##################################################
        self.timeslot_nr = timeslot_nr

        ##################################################
        # Blocks
        ##################################################

        # 3GPP TS 45.002 version 15.1.0 Release 15
        # Table 4 : Mapping of logical channels onto physical channels (see subclauses 6.3, 6.4, 6.5)
        # SDCCH/8 0 D 0 ... 7 C0 ... Cn NB1 51 B (0 ... 3)
        #           U B (15 ... 18)
        #         1 D B (4 ... 7)
        #           U B (19 ... 22)
        #         2 D B (8 ... 11)
        #           U B (23 ... 26)
        #         3 D B (12 ... 15)
        #           U B (27 ... 30)
        #         4 D B (16 ... 19)
        #           U B (31 ... 34)
        #         5 D B (20 ... 23)
        #           U B (35 ... 38)
        #         6 D B (24 ... 27)
        #           U B (39 ... 42)
        #         7 D B (28 ... 31)
        #           U B (43 ... 46)
        # SACCH/C8 0 D 0 ... 7 C0 ... Cn NB3 102 B (32 ... 35)
        #            U B (47 ... 50)
        #          1 D B (36 ... 39)
        #            U B (51 ... 54)
        #          2 D B (40 ... 43)
        #            U B (55 ... 58)
        #          3 D B (44 ... 47)
        #            U B (59 ... 62)
        #          4 D B (83 ... 86)
        #            U B (98 ... 101)
        #          5 D B (87 ... 90)
        #            U B (0 ... 3)
        #          6 D B (91 ... 94)
        #            U B (4 ... 7)
        #          7 D B (95 ... 98)
        #            U B (8 ... 11)
        self.gsm_universal_ctrl_chans_demapper_0 = gsm.universal_ctrl_chans_demapper(
                timeslot_nr, ([ #downlink
                    0,0,0,0,
                    4,4,4,4,
                    8,8,8,8,
                    12,12,12,12,
                    16,16,16,16,
                    20,20,20,20,
                    24,24,24,24,
                    28,28,28,28,
                    32,32,32,32,
                    36,36,36,36,
                    40,40,40,40,
                    44,44,44,44,
                    0,0,0
                ]), ([
                    8,8,8,8,
                    8,8,8,8,
                    8,8,8,8,
                    8,8,8,8,
                    8,8,8,8,
                    8,8,8,8,
                    8,8,8,8,
                    8,8,8,8,
                    136,136,136,136,
                    136,136,136,136,
                    136,136,136,136,
                    136,136,136,136,
                    0,0,0
                ]), ([
                    0,0,0,0,
                    1,1,1,1,
                    2,2,2,2,
                    3,3,3,3,
                    4,4,4,4,
                    5,5,5,5,
                    6,6,6,6,
                    7,7,7,7,
                    0,0,0,0,
                    1,1,1,1,
                    2,2,2,2,
                    3,3,3,3,
                    0,0,0,0,
                    0,0,0,
                    1,1,1,1,
                    2,2,2,2,
                    3,3,3,3,
                    4,4,4,4,
                    5,5,5,5,
                    6,6,6,6,
                    7,7,7,7,
                    4,4,4,4,
                    5,5,5,5,
                    6,6,6,6,
                    7,7,7,7,
                    0,0,0
                ]), ([ #uplink
                    0,0,0,0,
                    4,4,4,4,
                    8,8,8,8,
                    0,0,0,
                    15,15,15,15,
                    19,19,19,19,
                    23,23,23,23,
                    27,27,27,27,
                    31,31,31,31,
                    35,35,35,35,
                    39,39,39,39,
                    43,43,43,43,
                    47,47,47,47
                ]), ([
                    136,136,136,136,
                    136,136,136,136,
                    136,136,136,136,
                    0,0,0,
                    8,8,8,8,
                    8,8,8,8,
                    8,8,8,8,
                    8,8,8,8,
                    8,8,8,8,
                    8,8,8,8,
                    8,8,8,8,
                    8,8,8,8,
                    136,136,136,136
                ]), ([
                    5,5,5,5,
                    6,6,6,6,
                    7,7,7,7,
                    0,0,0,
                    0,0,0,0,
                    1,1,1,1,
                    2,2,2,2,
                    3,3,3,3,
                    4,4,4,4,
                    5,5,5,5,
                    6,6,6,6,
                    7,7,7,7,
                    0,0,0,0,
                    1,1,1,1,
                    2,2,2,2,
                    3,3,3,3,
                    0,0,0,
                    0,0,0,0,
                    1,1,1,1,
                    2,2,2,2,
                    3,3,3,3,
                    4,4,4,4,
                    5,5,5,5,
                    6,6,6,6,
                    7,7,7,7,
                    4,4,4,4
                ]))

        ##################################################
        # Connections
        ##################################################
        self.msg_connect((self.gsm_universal_ctrl_chans_demapper_0, 'bursts'), (self, 'bursts'))    
        self.msg_connect((self, 'bursts'), (self.gsm_universal_ctrl_chans_demapper_0, 'bursts'))    

    def get_timeslot_nr(self):
        return self.timeslot_nr

    def set_timeslot_nr(self, timeslot_nr):
        self.timeslot_nr = timeslot_nr
