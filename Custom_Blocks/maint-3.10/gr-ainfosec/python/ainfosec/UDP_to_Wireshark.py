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
# from scapy.utils import PcapWriter
# from scapy.layers import l2
# import pmt, sys, bitarray, array
# import os, tempfile, time
import subprocess
import socket


class UDP_to_Wireshark(gr.sync_block):
    """
    docstring for block UDP_to_Wireshark
    """

    def __init__(self, port):
        gr.sync_block.__init__(self,
                               name="UDP_to_Wireshark",
                               in_sig=[numpy.uint8],
                               out_sig=[])

        # self.set_msg_handler(pmt.intern("in"), self.handler);
        # self.d = None
        # self.f = None
        # self.p = None

        # self.d = tempfile.mkdtemp()
        # self.f = self.d + '/pcap_fifo'
        # os.mkfifo(self.f)

        # Create UDP Socket
        self.udp_port = port
        self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

        # Find Wireshark
        out = subprocess.Popen(['which', 'wireshark'], stdout=subprocess.PIPE)
        stdout = out.communicate()[0].decode()
        wireshark_cmd = str(stdout.replace('\n', ''))
        subprocess.Popen([wireshark_cmd, '-k', '-i', 'lo'])
        # self.pcap = PcapWriter(self.f, append=False, sync=True)
        # #self.pcap.linktype = 147

    # def start(self):
    #     pass
    # self.d = tempfile.mkdtemp()
    # self.f = self.d + '/pcap_fifo'
    # os.mkfifo(self.f)

    # Find Wireshark
    # out = subprocess.Popen(['which', 'wireshark'],stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
    # stdout,stderr = out.communicate()
    # wireshark_cmd = str(stdout.replace('\n',''))
    # self.p = subprocess.Popen([wireshark_cmd, '-k', '-i', self.f])
    # #self.p = subprocess.Popen(['/home/sae/wireshark-2.6.0/wireshark', '-k', '-i', self.f])
    # #self.p = subprocess.Popen(['/usr/bin/wireshark', '-k', '-i', self.f])
    # self.pcap = PcapWriter(self.f, append=False, sync=True)
    # self.pcap.linktype = 147

    # def stop(self):
    # self.pcap.close()
    # # These don't seem to work for whatever reason...
    # #self.p.terminate()
    # #self.p.kill()
    # os.unlink(self.f)
    # os.rmdir(self.d)

    # def handler(self, pdu):
    # ba = bitarray.bitarray();
    # meta = pmt.car(pdu)
    # x = pmt.to_python(pmt.cdr(pdu))

    # #z = l2.Ether(src='00:00:00:00:00',dst='00:00:00:00:00',type=0x2323)/l2.Raw(x.tostring())
    # #z = l2.Ether(src='ff:ff:ff:ff:ff:ff',dst='00:00:00:00:00:00',type=0x7777)/l2.Raw(x.tostring())
    # #z = l2.Ether(src='00:00:00:00:00:00',dst='00:00:00:00:00:00')/l2.Raw(x.tostring())
    # z = l2.Raw(x.tostring())

    # #z.show()
    # self.pcap.write(z);
    # self.pcap.flush()

    def work(self, input_items, output_items):
        # z = l2.Raw(input_items[0].tostring())
        # z = str(input_items[0])  # [211 147  70  65 114 161 206  17 122 136 204 130 179]
        # z=''
        # z = [z+bytes(i) for i in input_items[0]]
        # print str(z)
        # self.pcap.write(bytes(bytearray(input_items[0])));
        # self.pcap.flush()

        # Convert Message
        # udp_message = message_hex.decode('hex')

        # Send Message
        self.udp_socket.sendto(bytes(bytearray(input_items[0])), ("127.0.0.1", self.udp_port))

        return len(input_items[0])
