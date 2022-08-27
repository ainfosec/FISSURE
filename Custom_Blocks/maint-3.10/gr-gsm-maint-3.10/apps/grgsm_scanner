#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @file
# @author (C) 2015 by Piotr Krysik <ptrkrysik@gmail.com>
# @author (C) 2015 by Roman Khassraf <rkhassraf@gmail.com>
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
#
from gnuradio import network
from gnuradio import blocks
from gnuradio import gr
from gnuradio import eng_notation
from gnuradio.eng_option import eng_option
from gnuradio.filter import firdes
from gnuradio.filter import pfb
from math import pi
from optparse import OptionParser
from gnuradio import gsm
import numpy
import os
import osmosdr
import pmt
import time
import sys
import gc

# from wideband_receiver import *

class receiver_with_decoder(gr.hier_block2):
    def __init__(self, OSR=4, chan_num=0, fc=939.4e6, ppm=0, samp_rate=0.2e6):
        gr.hier_block2.__init__(
            self, "Receiver With Decoder",
            gr.io_signature(1, 1, gr.sizeof_gr_complex * 1),
            gr.io_signature(0, 0, 0),
        )
        self.message_port_register_hier_out("bursts")
        self.message_port_register_hier_out("msgs")

        ##################################################
        # Parameters
        ##################################################
        self.OSR = OSR
        self.chan_num = chan_num
        self.fc = fc
        self.ppm = ppm
        self.samp_rate = samp_rate

        ##################################################
        # Variables
        ##################################################
        self.samp_rate_out = samp_rate_out = 1625000.0 / 6.0 * OSR

        ##################################################
        # Blocks
        ##################################################
        self.gsm_receiver_0 = gsm.receiver(OSR, ([chan_num]), ([]))
        self.gsm_input_0 = gsm.gsm_input(
            ppm=ppm,
            osr=OSR,
            fc=fc,
            samp_rate_in=samp_rate,
        )
        self.gsm_control_channels_decoder_0 = gsm.control_channels_decoder()
        self.gsm_clock_offset_control_0 = gsm.clock_offset_control(fc, samp_rate, osr=4)
        self.gsm_bcch_ccch_demapper_0 = gsm.gsm_bcch_ccch_demapper(0)

        ##################################################
        # Connections
        ##################################################
        self.msg_connect(self.gsm_bcch_ccch_demapper_0, 'bursts', self, 'bursts')
        self.msg_connect(self.gsm_bcch_ccch_demapper_0, 'bursts', self.gsm_control_channels_decoder_0, 'bursts')
        self.msg_connect(self.gsm_clock_offset_control_0, 'ctrl', self.gsm_input_0, 'ctrl_in')
        self.msg_connect(self.gsm_control_channels_decoder_0, 'msgs', self, 'msgs')
        self.msg_connect(self.gsm_receiver_0, 'C0', self.gsm_bcch_ccch_demapper_0, 'bursts')
        self.msg_connect(self.gsm_receiver_0, 'measurements', self.gsm_clock_offset_control_0, 'measurements')
        self.connect((self.gsm_input_0, 0), (self.gsm_receiver_0, 0))
        self.connect((self, 0), (self.gsm_input_0, 0))

    def get_OSR(self):
        return self.OSR

    def set_OSR(self, OSR):
        self.OSR = OSR
        self.set_samp_rate_out(1625000.0 / 6.0 * self.OSR)
        self.gsm_input_0.set_osr(self.OSR)

    def get_chan_num(self):
        return self.chan_num

    def set_chan_num(self, chan_num):
        self.chan_num = chan_num

    def get_fc(self):
        return self.fc

    def set_fc(self, fc):
        self.fc = fc
        self.gsm_input_0.set_fc(self.fc)

    def get_ppm(self):
        return self.ppm

    def set_ppm(self, ppm):
        self.ppm = ppm
        self.gsm_input_0.set_ppm(self.ppm)

    def get_samp_rate(self):
        return self.samp_rate

    def set_samp_rate(self, samp_rate):
        self.samp_rate = samp_rate
        self.gsm_input_0.set_samp_rate_in(self.samp_rate)

    def get_samp_rate_out(self):
        return self.samp_rate_out

    def set_samp_rate_out(self, samp_rate_out):
        self.samp_rate_out = samp_rate_out


class wideband_receiver(gr.hier_block2):
    def __init__(self, OSR=4, fc=939.4e6, samp_rate=0.4e6):
        gr.hier_block2.__init__(
            self, "Wideband receiver",
            gr.io_signature(1, 1, gr.sizeof_gr_complex * 1),
            gr.io_signature(0, 0, 0),
        )
        self.message_port_register_hier_out("bursts")
        self.message_port_register_hier_out("msgs")
        self.__init(OSR, fc, samp_rate)

    def __init(self, OSR=4, fc=939.4e6, samp_rate=0.4e6):
        ##################################################
        # Parameters
        ##################################################
        self.OSR = OSR
        self.fc = fc
        self.samp_rate = samp_rate
        self.channels_num = int(samp_rate / 0.2e6)
        self.OSR_PFB = 2

        ##################################################
        # Blocks
        ##################################################
        self.pfb_channelizer_ccf_0 = pfb.channelizer_ccf(
            self.channels_num,
            (),
            self.OSR_PFB,
            100)
        self.pfb_channelizer_ccf_0.set_channel_map(([]))
        self.create_receivers()

        ##################################################
        # Connections
        ##################################################
        self.connect((self, 0), (self.pfb_channelizer_ccf_0, 0))
        for chan in range(0, self.channels_num):
            self.connect((self.pfb_channelizer_ccf_0, chan), (self.receivers_with_decoders[chan], 0))
            self.msg_connect(self.receivers_with_decoders[chan], 'bursts', self, 'bursts')
            self.msg_connect(self.receivers_with_decoders[chan], 'msgs', self, 'msgs')

    def create_receivers(self):
        self.receivers_with_decoders = {}
        for chan in range(0, self.channels_num):
            self.receivers_with_decoders[chan] = receiver_with_decoder(fc=self.fc, OSR=self.OSR, chan_num=chan,
                                                                       samp_rate=self.OSR_PFB * 0.2e6)

    def get_OSR(self):
        return self.OSR

    def set_OSR(self, OSR):
        self.OSR = OSR
        self.create_receivers()

    def get_fc(self):
        return self.fc

    def set_fc(self, fc):
        self.fc = fc
        self.create_receivers()

    def get_samp_rate(self):
        return self.samp_rate


class wideband_scanner(gr.top_block):
    def __init__(self, rec_len=3, sample_rate=2e6, carrier_frequency=939e6, gain=24, ppm=0, args=""):
        gr.top_block.__init__(self, "Wideband Scanner")

        self.rec_len = rec_len
        self.sample_rate = sample_rate
        self.carrier_frequency = carrier_frequency
        self.ppm = ppm

        # if no file name is given process data from rtl_sdr source
        print("Args=", args)
        self.rtlsdr_source = osmosdr.source(args="numchan=" + str(1) + " " +
                str(gsm.device.get_default_args(args)))
        #self.rtlsdr_source.set_min_output_buffer(int(sample_rate*rec_len)) #this line causes segfaults on HackRF
        self.rtlsdr_source.set_sample_rate(sample_rate)

        # capture half of GSM channel lower than channel center (-0.1MHz)
        # this is needed when even number of channels is captured in order to process full captured bandwidth

        self.rtlsdr_source.set_center_freq(carrier_frequency - 0.1e6, 0)

        # correction of central frequency
        # if the receiver has large frequency offset
        # the value of this variable should be set close to that offset in ppm
        self.rtlsdr_source.set_freq_corr(ppm, 0)

        self.rtlsdr_source.set_dc_offset_mode(2, 0)
        self.rtlsdr_source.set_iq_balance_mode(0, 0)
        self.rtlsdr_source.set_gain_mode(True, 0)
        self.rtlsdr_source.set_bandwidth(sample_rate, 0)
        self.rtlsdr_source.set_gain(gain, 0)
        self.rtlsdr_source.set_if_gain(32, 0)
        self.rtlsdr_source.set_bb_gain(30, 0)
        self.head = blocks.head(gr.sizeof_gr_complex * 1, int(rec_len * sample_rate))

        # shift again by -0.1MHz in order to align channel center in 0Hz
        self.blocks_rotator_cc = blocks.rotator_cc(-2 * pi * 0.1e6 / sample_rate)

        self.wideband_receiver = wideband_receiver(OSR=4, fc=carrier_frequency, samp_rate=sample_rate)
        self.gsm_extract_system_info = gsm.extract_system_info()

        self.connect((self.rtlsdr_source, 0), (self.head, 0))
        self.connect((self.head, 0), (self.blocks_rotator_cc, 0))
        self.connect((self.blocks_rotator_cc, 0), (self.wideband_receiver, 0))
        self.msg_connect(self.wideband_receiver, 'msgs', self.gsm_extract_system_info, 'msgs')

    def set_carrier_frequency(self, carrier_frequency):
        self.carrier_frequency = carrier_frequency
        self.rtlsdr_source.set_center_freq(carrier_frequency - 0.1e6, 0)


class channel_info(object):
    def __init__(self, arfcn, freq, cid, lac, mcc, mnc, ccch_conf, power, neighbours, cell_arfcns):
        self.arfcn = arfcn
        self.freq = freq
        self.cid = cid
        self.lac = lac
        self.mcc = mcc
        self.mnc = mnc
        self.ccch_conf = ccch_conf
        self.power = power
        self.neighbours = neighbours
        self.cell_arfcns = cell_arfcns

    def __lt__(self, other):
        return self.arfcn < other.arfcn


    def get_verbose_info(self):
        i = "  |---- Configuration: %s\n" % self.get_ccch_conf()
        i += "  |---- Cell ARFCNs: " + ", ".join(map(str, self.cell_arfcns)) + "\n"
        i += "  |---- Neighbour Cells: " + ", ".join(map(str, self.neighbours)) + "\n"
        return i

    def get_ccch_conf(self):
        if self.ccch_conf == 0:
            return "1 CCCH, not combined"
        elif self.ccch_conf == 1:
            return "1 CCCH, combined"
        elif self.ccch_conf == 2:
            return "2 CCCH, not combined"
        elif self.ccch_conf == 4:
            return "3 CCCH, not combined"
        elif self.ccch_conf == 6:
            return "4 CCCH, not combined"
        else:
            return "Unknown"

    def getKey(self):
        return self.arfcn

    def __cmp__(self, other):
        if hasattr(other, 'getKey'):
            return self.getKey().__cmp__(other.getKey())

    def __repr__(self):
        return "%s(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)" % (
            self.__class__, self.arfcn, self.freq, self.cid, self.lac,
            self.mcc, self.mnc, self.ccch_conf, self.power,
            self.neighbours, self.cell_arfcns)

    def __str__(self):
        return "ARFCN: %4u, Freq: %6.1fM, CID: %5u, LAC: %5u, MCC: %3u, MNC: %3u, Pwr: %3i" % (
            self.arfcn, self.freq / 1e6, self.cid, self.lac, self.mcc, self.mnc, self.power)

def do_scan(samp_rate, band, speed, ppm, gain, args, prn = None, debug = False):
    signallist = []
    channels_num = int(samp_rate / 0.2e6)
    for arfcn_range in gsm.arfcn.get_arfcn_ranges(band):
        first_arfcn = arfcn_range[0]
        last_arfcn = arfcn_range[1]
        last_center_arfcn = last_arfcn - int((channels_num / 2) - 1)

        current_freq = gsm.arfcn.arfcn2downlink(first_arfcn + int(channels_num / 2) - 1)
        last_freq = gsm.arfcn.arfcn2downlink(last_center_arfcn)
        stop_freq = last_freq + 0.2e6 * channels_num

        while current_freq < stop_freq:

            if not debug:
                # silence rtl_sdr output:
                # open 2 fds
                null_fds = [os.open(os.devnull, os.O_RDWR) for x in range(2)]
                # save the current file descriptors to a tuple
                save = os.dup(1), os.dup(2)
                # put /dev/null fds on 1 and 2
                os.dup2(null_fds[0], 1)
                os.dup2(null_fds[1], 2)

            # instantiate scanner and processor
            scanner = wideband_scanner(rec_len=6 - speed,
                                       sample_rate=samp_rate,
                                       carrier_frequency=current_freq,
                                       ppm=ppm, gain=gain, args=args)

            # start recording
            scanner.start()
            scanner.wait()
            scanner.stop()

            freq_offsets = numpy.fft.ifftshift(
                numpy.array(range(int(-numpy.floor(channels_num / 2)), int(numpy.floor((channels_num + 1) / 2)))) * 2e5)
            detected_c0_channels = scanner.gsm_extract_system_info.get_chans()

            found_list = []

            if detected_c0_channels:
                chans = numpy.array(scanner.gsm_extract_system_info.get_chans())
                found_freqs = current_freq + freq_offsets[(chans)]

                cell_ids = numpy.array(scanner.gsm_extract_system_info.get_cell_id())
                lacs = numpy.array(scanner.gsm_extract_system_info.get_lac())
                mccs = numpy.array(scanner.gsm_extract_system_info.get_mcc())
                mncs = numpy.array(scanner.gsm_extract_system_info.get_mnc())
                ccch_confs = numpy.array(scanner.gsm_extract_system_info.get_ccch_conf())
                powers = numpy.array(scanner.gsm_extract_system_info.get_pwrs())

                for i in range(0, len(chans)):
                    cell_arfcn_list = scanner.gsm_extract_system_info.get_cell_arfcns(chans[i])
                    neighbour_list = scanner.gsm_extract_system_info.get_neighbours(chans[i])

                    info = channel_info(gsm.arfcn.downlink2arfcn(found_freqs[i]), found_freqs[i],
                                        cell_ids[i], lacs[i], mccs[i], mncs[i], ccch_confs[i], powers[i],
                                        neighbour_list, cell_arfcn_list)
                    found_list.append(info)

            scanner = None


            if not debug:
                # restore file descriptors so we can print the results
                os.dup2(save[0], 1)
                os.dup2(save[1], 2)
                # close the temporary fds
                os.close(null_fds[0])
                os.close(null_fds[1])
            if prn:
                prn(found_list)
            signallist.extend(found_list)

            current_freq += channels_num * 0.2e6
    return signallist

def argument_parser():
    parser = OptionParser(option_class=eng_option, usage="%prog: [options]")
    bands_list = ", ".join(gsm.arfcn.get_bands())
    parser.add_option("-b", "--band", dest="band", default="GSM900",
                      help="Specify the GSM band for the frequency.\nAvailable bands are: " + bands_list)
    parser.add_option("-s", "--samp-rate", dest="samp_rate", type="float", default=2e6,
                      help="Set sample rate [default=%default] - allowed values even_number*0.2e6")
    parser.add_option("-p", "--ppm", dest="ppm", type="intx", default=0,
                      help="Set frequency correction in ppm [default=%default]")
    parser.add_option("-g", "--gain", dest="gain", type="eng_float", default=24.0,
                      help="Set gain [default=%default]")
    parser.add_option("", "--args", dest="args", type="string", default="",
                      help="Set device arguments [default=%default]."
                      " Use --list-devices the view the available devices")
    parser.add_option("-l", "--list-devices", action="store_true",
                      help="List available SDR devices, use --args to specify hints")
    parser.add_option("--speed", dest="speed", type="intx", default=4,
                      help="Scan speed [default=%default]. Value range 0-5.")
    parser.add_option("-v", "--verbose", action="store_true",
                      help="If set, verbose information output is printed: ccch configuration, cell ARFCN's, neighbour ARFCN's")
    parser.add_option("-d", "--debug", action="store_true",
                      help="Print additional debug messages")

    """
        Dont forget: sudo sysctl kernel.shmmni=32000
    """
    return parser

def main(options = None):
    if options is None:
        (options, args) = argument_parser().parse_args()

    if options.list_devices:
        gsm.device.print_devices(options.args)
        sys.exit(0)

    if options.band not in gsm.arfcn.get_bands():
        parser.error("Invalid GSM band\n")

    if options.speed < 0 or options.speed > 5:
        parser.error("Invalid scan speed.\n")

    if (options.samp_rate / 0.2e6) % 2 != 0:
        parser.error("Invalid sample rate. Sample rate must be an even numer * 0.2e6")

    def printfunc(found_list):
        for info in sorted(found_list):
            print(info)
            if options.verbose:
                print(info.get_verbose_info())
    print("")
    do_scan(options.samp_rate, options.band, options.speed,
            options.ppm, options.gain, options.args, prn = printfunc, debug = options.debug)

if __name__ == '__main__':
    main()
