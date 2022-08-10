#!/usr/bin/env python
'''
   Copyright 2015 Wolfgang Nagele

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
'''

import numpy
import pmt
from gnuradio import gr

LENGTH = 56


class framer(gr.sync_block):
  def __init__(self, tx_msgq):
    gr.sync_block.__init__(self,
                           name = "ADSB Framer",
                           in_sig = [numpy.byte],
                           out_sig = None)

    self.tx_msgq = tx_msgq

    self.set_tag_propagation_policy(gr.TPP_DONT)


  def work(self, input_items, output_items):
    nread = self.nitems_read(0)

    in0 = input_items[0]
    in0_len = len(in0)

    # Look for preamble tag
    for tag in self.get_tags_in_window(0, 0, in0_len, pmt.intern("adsb_preamble")):
      offset_start = tag.offset - nread
      offset_end = tag.offset - nread + LENGTH * 2 * 2

      if offset_end > in0_len: # Need to wait for buffer to fill before processing
        return 0

      # Try extended length message decoding first
      bin = in0[offset_start:offset_end]
      decoded_msg = self.decode(bin, LENGTH * 2)
      if LENGTH * 2 == len(decoded_msg):
        self.tx_msgq.insert_tail(gr.message_from_string(decoded_msg))
        continue

      # Failed decoding of extended message - try standard length
      bin = bin[0:LENGTH * 2]
      decoded_msg = self.decode(bin, LENGTH)
      if LENGTH == len(decoded_msg):
        self.tx_msgq.insert_tail(gr.message_from_string(decoded_msg, LENGTH))
        continue

    return in0_len


  # Detect binary data based on rising or falling edge
  # See: http://www.radartutorial.eu/13.ssr/sr24.en.html
  def decode(self, payload, length):
    decoded_msg = ""
    for seq in numpy.reshape(payload, (length, 2)):
      if seq[0] == 1 and seq[1] == 0:
        decoded_msg += "1"
      elif seq[0] == 0 and seq[1] == 1:
        decoded_msg += "0"
    return decoded_msg
