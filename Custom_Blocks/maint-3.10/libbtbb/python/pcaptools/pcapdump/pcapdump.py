# Copyright 2009 Joshua Wright
# 
# This file is part of gr-bluetooth
# 
# gr-bluetooth is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2, or (at your option)
# any later version.
# 
# gr-bluetooth is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with gr-bluetooth; see the file COPYING.  If not, write to
# the Free Software Foundation, Inc., 51 Franklin Street,
# Boston, MA 02110-1301, USA.

import struct
import time

PCAPH_MAGIC_NUM = 0xa1b2c3d4
PCAPH_VER_MAJOR = 2
PCAPH_VER_MINOR = 4
PCAPH_THISZONE = 0
PCAPH_SIGFIGS = 0
PCAPH_SNAPLEN = 65535

class PcapReader:

    def __init__(self, savefile):
        '''
        Opens the specified file, validates a libpcap header is present.
        @type savefile: String
        @param savefile: Input libpcap filename to open
        @rtype: None
        '''
        PCAPH_LEN = 24
        self.__fh = open(savefile, mode='rb')
        self._pcaphsnaplen = 0
        header = self.__fh.read(PCAPH_LEN)

        # Read the first 4 bytes for the magic number, determine endianness
        magicnum = struct.unpack("I", header[0:4])[0]
        if magicnum != 0xd4c3b2a1:
            # Little endian
            self.__endflag = "<"
        elif magicnum == 0xa1b2c3d4:
            # Big endign
            self.__endflag = ">"
        else:
            raise Exception('Specified file is not a libpcap capture')

        pcaph = struct.unpack("%sIHHIIII"%self.__endflag, header)
        if pcaph[1] != PCAPH_VER_MAJOR and pcaph[2] != PCAPH_VER_MINOR \
                and pcaph[3] != PCAPH_THISZONE and pcaph[4] != PCAPH_SIGFIGS \
                and pcaph[5] != PCAPH_SNAPLEN:
            raise Exception('Unsupported pcap header format or version')

        self._pcaphsnaplen = pcaph[5]
        self._datalink = pcaph[6]

    def datalink(self):
        return self._datalink

    def close(self):
        '''
        Closes the output packet capture; wrapper for pcap_close().
        @rtype: None
        '''
        self.pcap_close()

    def pcap_close(self):
        '''
        Closes the output packet capture.
        @rtype: None
        '''
        self.__fh.close()

    def pnext(self):
        '''
        Wrapper for pcap_next to mimic method for Daintree SNA
        '''
        return self.pcap_next()
 
    def pcap_next(self):
        '''
        Retrieves the next packet from the capture file.  Returns a list of
        [Hdr, packet] where Hdr is a list of [timestamp, snaplen, plen] and
        packet is a string of the payload content.  Returns None at the end
        of the packet capture.
        @rtype: List
        '''
        # Read the next header block
        PCAPH_RECLEN = 16
        rechdrdata = self.__fh.read(PCAPH_RECLEN)

        try:
            rechdrtmp = struct.unpack("%sIIII"%self.__endflag, rechdrdata)
        except struct.error:
            return [None,None]

        rechdr = [
                float("%s.%s"%(rechdrtmp[0],rechdrtmp[1])), 
                rechdrtmp[2], 
                rechdrtmp[3]
                ]
        if rechdr[1] > rechdr[2] or rechdr[1] > self._pcaphsnaplen or rechdr[2] > self._pcaphsnaplen:
            raise Exception('Corrupted or invalid libpcap record header (included length exceeds actual length)')

        # Read the included packet length
        frame = self.__fh.read(rechdr[1])
        return [rechdr, frame]


class PcapDumper:

    def __init__(self, datalink, savefile):
        '''
        Creates a libpcap file using the specified datalink type.
        @type datalink: Integer
        @param datalink: Datalink type, one of DLT_* defined in pcap-bpf.h
        @type savefile: String
        @param savefile: Output libpcap filename to open
        @rtype: None
        '''
        self.__fh = open(savefile, mode='wb')
        self.__fh.write(''.join([
            struct.pack("I", PCAPH_MAGIC_NUM), 
            struct.pack("H", PCAPH_VER_MAJOR),
            struct.pack("H", PCAPH_VER_MINOR),
            struct.pack("I", PCAPH_THISZONE),
            struct.pack("I", PCAPH_SIGFIGS),
            struct.pack("I", PCAPH_SNAPLEN),
            struct.pack("I", datalink)
            ]))

    def pcap_dump(self, packet, ts_sec=None, ts_usec=None, orig_len=None):
        '''
        Appends a new packet to the libpcap file.  Optionally specify ts_sec
        and tv_usec for timestamp information, otherwise the current time is
        used.  Specify orig_len if your snaplen is smaller than the entire
        packet contents.
        @type ts_sec: Integer
        @param ts_sec: Timestamp, number of seconds since Unix epoch.  Default
        is the current timestamp.
        @type ts_usec: Integer
        @param ts_usec: Timestamp microseconds.  Defaults to current timestamp.
        @type orig_len: Integer
        @param orig_len: Length of the original packet, used if the packet you
        are writing is smaller than the original packet.  Defaults to the
        specified packet's length.
        @type packet: String
        @param packet: Packet contents
        @rtype: None
        '''

        if ts_sec == None or ts_usec == None:
            # There must be a better way here that I don't know -JW
            s_sec, s_usec = str(time.time()).split(".")
            ts_sec = int(s_sec)
            ts_usec = int(s_usec)

        if orig_len == None:
            orig_len = len(packet)

        plen = len(packet)

        self.__fh.write(''.join([
            struct.pack("I", ts_sec),
            struct.pack("I", ts_usec),
            struct.pack("I", orig_len),
            struct.pack("I", plen),
            packet
            ]))

        return


    def close(self):
        '''
        Closes the output packet capture; wrapper for pcap_close().
        @rtype: None
        '''
        self.pcap_close()

    def pcap_close(self):
        '''
        Closed the output packet capture.
        @rtype: None
        '''
        self.__fh.close()
