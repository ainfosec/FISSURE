#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Copyright 2022 gr-ainfosec author.
#
# This is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3, or (at your option)
# any later version.
#
# This software is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this software; see the file COPYING.  If not, write to
# the Free Software Foundation, Inc., 51 Franklin Street,
# Boston, MA 02110-1301, USA.
#


import numpy
from gnuradio import gr
import pmt
import threading
import time
import struct


class adsb_encode(gr.sync_block):
    """
    docstring for block adsb_encode
    """

    def __init__(self, data_filepath):
        gr.sync_block.__init__(self,
                               name="adsb_encode",
                               in_sig=None,
                               out_sig=None)

        self.message_port_register_out(pmt.intern('out'))

        # Store Variables
        self.data_filepath = data_filepath
        self.transmit_interval = float(1)

        # Make a new Thread
        self.stop_event = threading.Event()
        adsb_thread = threading.Thread(target=self.run, args=())
        adsb_thread.daemon = True
        adsb_thread.start()

    def run(self):
        filepath = self.data_filepath

        # Get the Data from the File
        get_file = open(filepath, "rb")
        binary_adsb_data = get_file.read()
        get_file.close()
        binary_adsb_data = struct.unpack(len(binary_adsb_data) * 'b', binary_adsb_data)

        # Transmit the Message
        while not self.stop_event.is_set():
            # Single Loop Start Time
            start_time = time.time()

            # Add the Preamle        
            ppm = []
            ppm.append(0xA1)
            ppm.append(0x40)

            # Encode the Message            
            for i in range(len(binary_adsb_data)):

                # Encode byte
                manchester_encoded = []
                for ii in range(7, -1, -1):
                    if (~binary_adsb_data[i] >> ii) & 0x01:
                        manchester_encoded.append(0)
                        manchester_encoded.append(1)
                    else:
                        manchester_encoded.append(1)
                        manchester_encoded.append(0)

                word16 = numpy.packbits(manchester_encoded)
                ppm.append(word16[0])
                ppm.append(word16[1])

            data_out = bytearray(ppm)

            # Convert Packet to a PMT List
            list_out = pmt.list1(pmt.to_pmt(data_out[0]))
            for n in range(1, len(data_out)):
                list_out = pmt.list_add(list_out, pmt.to_pmt(data_out[n]))

            # Output the Packet in a Message
            try:
                self.message_port_pub(pmt.intern('out'), list_out)
            except:
                # Stop the Thread When the Block's Program Exits
                # ~ print "Stopping the thread"
                self.stop_event.set()

            # Sleep the Remainder of the Transmit Interval
            time_difference = self.transmit_interval - (time.time() - start_time)
            time.sleep(time_difference)  # Doesn't really do anything in this case
