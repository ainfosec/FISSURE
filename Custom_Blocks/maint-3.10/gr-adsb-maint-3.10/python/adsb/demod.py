#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2016-2019 Matt Hostetter.
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

import datetime
import numpy as np

import pmt
from gnuradio import gr

SYMBOL_RATE = 1e6  # symbols/second
MAX_NUM_BITS = 112

class demod(gr.sync_block):
    """
    docstring for block demod
    """
    def __init__(self, fs):
        gr.sync_block.__init__(self, name="demod", in_sig=[np.float32], out_sig=[np.float32])

        # Calculate the samples/symbol
        # ADS-B is modulated at 1 Msym/s with Pulse Position Modulation, so the effective
        # required fs is 2 Msps
        self.fs = fs
        assert self.fs % SYMBOL_RATE == 0, "ADS-B Demodulator is designed to operate on an integer number of samples per symbol, not %f sps" % (self.fs / SYMBOL_RATE)
        self.sps = int(fs // SYMBOL_RATE)

        # Calculate current UTC time at block startup. Then we'll use burst sample offset to derive burst time.
        self.start_timestamp = (datetime.datetime.utcnow() - datetime.datetime(1970, 1, 1)).total_seconds()

        # Array of data bits
        self.bits = []
        self.bit_idx = 0
        self.straddled_packet = 0

        self.set_tag_propagation_policy(gr.TPP_ONE_TO_ONE)
        self.message_port_register_out(pmt.to_pmt("demodulated"))


    def work(self, input_items, output_items):
        in0 = input_items[0]
        out0 = output_items[0]

        # If there was a packet that straddled the previous block and this
        # block, finish decoding it
        if self.straddled_packet == 1:
            self.straddled_packet = 0

        # Get tags from ADS-B Framer block
        tags = self.get_tags_in_range(0, self.nitems_read(0), self.nitems_read(0) + len(in0), pmt.to_pmt("burst"))

        for tag in tags:
            # Grab metadata for this tag
            value = pmt.to_python(tag.value)
            snr = value[1] # SNR in power dBs

            # Calculate the SOB and EOB offsets
            sob_offset = tag.offset + (8)*self.sps # Start of burst index (middle of the "bit 1 pulse")
            eob_offset = tag.offset + (8+112-1)*self.sps + self.sps/2 # End of burst index (middle of the "bit 0 pulse")

            # Find the SOB and EOB indices in this block of samples
            sob_idx = sob_offset - self.nitems_written(0)
            eob_idx = eob_offset - self.nitems_written(0)

            if eob_idx < len(input_items[0]):
                # The packet is fully within this block of samples, so demod
                # the entire burst

                # Grab the amplitudes where the "bit 1 pulse" should be
                bit1_idxs = range(sob_idx, sob_idx + self.sps*MAX_NUM_BITS, self.sps)
                bit1_amps = in0[bit1_idxs]

                # Grab the amplitudes where the "bit 0 pulse" should be
                bit0_idxs = range(sob_idx + self.sps // 2, sob_idx + self.sps // 2 + self.sps*MAX_NUM_BITS, self.sps)
                bit0_amps = in0[bit0_idxs]

                self.bits = np.zeros(MAX_NUM_BITS, dtype=np.uint8)
                self.bits[bit1_amps > bit0_amps] = 1

                # Get a log-likelihood type function for probability of a
                # bit being a 0 or 1.  Confidence of 0 is equally likely 0 or 1.
                # Positive confidence levels are more likely 1 and negative values
                # are more likely 0.
                self.bit_confidence = 10.0*np.log10(bit1_amps/bit0_amps)

                # Send PDU message to decoder
                meta = pmt.to_pmt({
                    "timestamp": self.start_timestamp + tag.offset/self.fs,
                    "snr": snr,
                })
                vector = pmt.to_pmt(self.bits)
                pdu = pmt.cons(meta, vector)
                self.message_port_pub(pmt.to_pmt("demodulated"), pdu)

                if False:
                    # Tag the 0 and 1 bits markers for debug
                    for ii in range(0,len(bit1_idxs)):
                        self.add_item_tag(
                            0,
                            self.nitems_written(0)+bit1_idxs[ii],
                            pmt.to_pmt("bits"),
                            pmt.to_pmt((1, ii, float(self.bit_confidence[ii]))),
                            pmt.to_pmt("demod")
                        )
                        self.add_item_tag(
                            0,
                            self.nitems_written(0)+bit0_idxs[ii],
                            pmt.to_pmt("bits"),
                            pmt.to_pmt((0, ii, float(self.bit_confidence[ii]))),
                            pmt.to_pmt("demod")
                        )

            else:
                # The packet is only partially contained in this block of
                # samples, decode as much as possible
                self.straddled_packet = 1

        out0[:] = in0
        return len(output_items[0])
