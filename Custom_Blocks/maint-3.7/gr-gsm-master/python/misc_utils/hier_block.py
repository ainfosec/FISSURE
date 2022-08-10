#!/usr/bin/env python2
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

from gnuradio import gr
from distutils.version import LooseVersion as version

#class created to solve incompatibility of reginstration of message inputs
#that was introduced in gnuradio 3.7.9

class hier_block(gr.hier_block2):
    def message_port_register_hier_in(self, port_id):
        if version(gr.version()) >= version('3.7.9'):
            super(hier_block, self).message_port_register_hier_in(port_id)
        else:
            super(hier_block, self).message_port_register_hier_out(port_id)

    def message_port_register_hier_out(self, port_id):
        if version(gr.version()) >= version('3.7.9'):
            super(hier_block, self).message_port_register_hier_out(port_id)
        else:
            super(hier_block, self).message_port_register_hier_in(port_id)

