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

import atexit
import curses
import datetime
import logging
import os
import time
from colorama import Fore, Back, Style

import pmt
from gnuradio import gr
import numpy as np

# Downlink Format, 5 bits
DF_STR_LUT = (
    "Short Air-Air Surveillance (ACAS)",
    "Reserved",
    "Reserved",
    "Reserved",
    "Surveillance Altitude Reply",
    "Surveillance Identity Reply",
    "Reserved",
    "Reserved",
    "Reserved",
    "Reserved",
    "Reserved",
    "All-Call Reply",
    "Reserved",
    "Reserved",
    "Reserved",
    "Reserved",
    "Long Air-Air Surveillance (ACAS)",
    "Extended Squitter",
    "Extended Squitter/Non-Transponder",
    "Military Extended Squitter",
    "Comm-B Altitude Reply",
    "Comm-B Identity Reply",
    "Reserved for Military Use",
    "Reserved",
    "Comm-D (ELM)",
    "Reserved",
    "Reserved",
    "Reserved",
    "Reserved",
    "Reserved",
    "Reserved",
    "Reserved",
)

# (DF 0, 16) Vertical Status, 1 bit
# (3.1.2.8.2.1)
VS_STR_LUT = (
    "In Air",
    "On Ground",
)

# (DF 0, 16) Reply Information, 4 bits
# (3.1.2.8.2.2)
RI_STR_LUT = (
    "Reply to Interr UF=0 AQ=0, No Operating ACAS",
    "Reserved for ACAS",
    "Reserved for ACAS",
    "Reserved for ACAS",
    "Reserved for ACAS",
    "Reserved for ACAS",
    "Reserved for ACAS",
    "Reserved for ACAS",
    "Reply to Interr UF=0 AQ=1, No Max Speed Available",
    "Reply to Interr UF=0 AQ=1, max(v) < 75 kt",
    "Reply to Interr UF=0 AQ=1, 75 < max(v) < 150 kt",
    "Reply to Interr UF=0 AQ=1, 150 < max(v) < 300 kt",
    "Reply to Interr UF=0 AQ=1, 300 < max(v) < 600 kt",
    "Reply to Interr UF=0 AQ=1, 600 < max(v) < 1200 kt",
    "Reply to Interr UF=0 AQ=1, max(v) > 1200 kt",
    "Not Assigned",
)

# (DF 0) Crosslink Capability, 1 bit
# (3.1.2.8.2.3)
CC_STR_LUT = (
    "Does Not Support Crosslink Capability",
    "Does Support Crosslink Capability",
)

# (DF 4, 20) Flight Status, 3 bits
# (3.1.2.6.5.1)
FS_STR_LUT = (
    "No Alert, No SPI, In Air",
    "No Alert, No SPI, On Ground",
    "Alert, No SPI, In Air",
    "Alert, No SPI, On Ground",
    "Alert, SPI, On Ground or In Air",
    "No Alert, SPI, On Ground or In Air",
    "Reserved",
    "Not Assigned",
)

# (DF 4, 20) Downlink Request, 5 bits
# (3.1.2.6.5.2)
DR_STR_LUT = (
    "No Downlink Request",
    "Request to Send Comm-B Message",
    "Reserved for ACAS",
    "Reserved for ACAS",
    "Comm-B Broadcast Message 1 Available",
    "Comm-B Broadcast Message 2 Available",
    "Reserved for ACAS",
    "Reserved for ACAS",
    "Not Assigned",
    "Not Assigned",
    "Not Assigned",
    "Not Assigned",
    "Not Assigned",
    "Not Assigned",
    "Not Assigned",
    "Not Assigned",
    "Downlink ELM",
    "Downlink ELM",
    "Downlink ELM",
    "Downlink ELM",
    "Downlink ELM",
    "Downlink ELM",
    "Downlink ELM",
    "Downlink ELM",
    "Downlink ELM",
    "Downlink ELM",
    "Downlink ELM",
    "Downlink ELM",
    "Downlink ELM",
    "Downlink ELM",
    "Downlink ELM",
    "Downlink ELM",
)

# (DF 4, 20) Indentifier Designator Subfield, 2 bits
# (3.1.2.6.5.3.1)
IDS_STR_LUT = (
    "No Information",
    "IIS Contains Comm-B II Code",
    "IIS Contains Comm-C II Code",
    "IIS Contains Comm-D II Code",
)

# (DF 17) Capability, 3 bits
# (3.1.2.5.2.2.1)
CA_STR_LUT = (
    "Level 1 Transponder, Cannot Set CA 7, On Ground or In Air",
    "Reserved",
    "Reserved",
    "Reserved",
    "Level 2 or Above Transponder, Can Set CA 7, On Ground",
    "Level 2 or Above Transponder, Can Set CA 7, In Air",
    "Level 2 or Above Transponder, Can Set CA 7, On Ground or In Air",
    "DR != 0 or FS in [2,3,4,5], On Ground or In Air",
)

# (DF 18) CF Field, 3 bits
CF_STR_LUT = (
    "AA Field is the ICAO Address",
    "AA Field is an Anonymous Address",
    "Fine TIS-B Message Using ICAO Address",
    "Coarse TIS-B Airborne Position/Velocity Message",
    "TIS-B and ADS-R Management Message",
    "Fine TIS-B Using Non-ICAO Address",
    "ADS-B Rebroadcast",
    "Reserved",
)

# (DF 19) Application Field, 3 bits
AF_STR_LUT = (
    "ADS-B Message",
    "Reserved for Military Use",
    "Reserved for Military Use",
    "Reserved for Military Use",
    "Reserved for Military Use",
    "Reserved for Military Use",
    "Reserved for Military Use",
    "Reserved for Military Use",
)

# (DF 17,18,19) Type Code, 5 bits
TC_STR_LUT = (
    "No Position Information",
    "Identification (Category Set D)",
    "Identification (Category Set C)",
    "Identification (Category Set B)",
    "Identification (Category Set A)",
    "Surface Position",
    "Surface Position",
    "Surface Position",
    "Surface Position",
    "Airborne Position",
    "Airborne Position",
    "Airborne Position",
    "Airborne Position",
    "Airborne Position",
    "Airborne Position",
    "Airborne Position",
    "Airborne Position",
    "Airborne Position",
    "Airborne Position",
    "Airborne Velocity",
    "Airborne Position",
    "Airborne Position",
    "Airborne Position",
    "Reserved for Test Purposes",
    "Reserved for Surface System Status",
    "Reserved",
    "Reserved",
    "Reserved",
    "Extended Squitter Aircraft Emergency Priority Status",
    "Reserved",
    "Reserved",
    "Aircraft Operational Status",
)

# (DF 17,18,19) Surveillance Status, 2 bits
# (2.2.3.2.3.2)
SS_STR_LUT = (
    "No Condition Information",
    "Permanent Alert Condition (Emergency)",
    "Temporary Alert Condition",
    "Special Position Identification (SPI) Condition",
)

# (DF 17,18,19) Time, 1 bit
# (2.2.3.2.3.5)
T_STR_LUT = (
    "Not Synced to 0.2s UTC Epoch",
    "Synced to 0.2s UTC Epoch",
)

# (DF 17,18,19) Callsign, 48 bits (6 bits per character)
# (3.1.2.9.1.2)
CALLSIGN_CHAR_LUT = "_ABCDEFGHIJKLMNOPQRSTUVWXYZ_____ _______________0123456789______"

MAX_NUM_BITS = 112
CPR_TIMEOUT_S = 30 # Seconds consider CPR-encoded lat/lon info invalid
PLANE_TIMEOUT_S = 1*60
INSERTS_PER_TRANSACTION = 50
FT_PER_METER = 3.28084

class decoder(gr.sync_block):
    """
    docstring for block decoder
    """
    def __init__(self, msg_filter, error_corr, print_level):
        # CRC polynomial (0xFFFA048) = 1 + x + x^2 + x^3 + x^4 + x^5 + x^6 + x^7 + x^8 + x^9 + x^10 + x^11 + x^12 + x^14 + x^21 + x^24
        self.crc_poly = np.array([1,1,1,1,1,1,1,1,1,1,1,1,1,0,1,0,0,0,0,0,0,1,0,0,1])
        self.crc_fix_lookup = dict([])
        for burst in range(1, 3):
            self.compute_crc_syndromes_for_contiguous_bursts(56, burst)
            self.compute_crc_syndromes_for_contiguous_bursts(112, burst)

        gr.sync_block.__init__(self, name="ADS-B Decoder", in_sig=None, out_sig=None)

        self.msg_filter = msg_filter
        self.error_corr = error_corr
        self.print_level = print_level


        # Initialize plane dictionary
        self.plane_dict = dict([])

        # Reset packet values
        self.reset()

        if self.print_level == "Brief":
            logging.basicConfig(format='[%(levelname)s] %(message)s', level=logging.CRITICAL)

            atexit.register(curses.endwin)
            self.screen = curses.initscr()
            self.screen.addstr(0, 0, "{:^8s} {:^6s} {:^8s} {:^5s} {:^5s} {:^5s} {:^5s} {:^11s} {:^11s} {:^4s}".format("Time", "ICAO", "Callsign", "Alt", "Climb", "Speed", "Hdng", "Latitude", "Longitude", "Msgs"), curses.A_BOLD)
            self.screen.addstr(1, 0, "{:^8s} {:>6s} {:>8s} {:>5s} {:>5s} {:>5s} {:>5s} {:>11s} {:>11s} {:>4s}".format("", "", "", "ft", "ft/m", "kt", "deg", "deg", "deg", ""), curses.A_DIM)
            self.screen.refresh()
        else:
            logging.basicConfig(format='[%(levelname)s] %(message)s', level=logging.DEBUG)

        self.message_port_register_in(pmt.to_pmt("demodulated"))
        self.message_port_register_out(pmt.to_pmt("decoded"))
        self.message_port_register_out(pmt.to_pmt("unknown"))
        self.set_msg_handler(pmt.to_pmt("demodulated"), self.decode_packet)

    def compute_crc_syndromes_for_contiguous_bursts(self,payload_length, burst_length):
        if payload_length in self.crc_fix_lookup:
            lut = self.crc_fix_lookup[payload_length]
        else:
            lut = dict([])
        for i in range(0,payload_length-burst_length+1):
            zarray = np.zeros(payload_length, dtype=int)

            for j in range(0,burst_length):
                zarray[i+j]=1

            crc_residual = self.compute_crc_2(zarray, self.crc_poly)

            crc_residual_dec = self.bin2dec(crc_residual)

            if  crc_residual_dec in lut:
                print(lut[crc_residual_dec])
                raise "FEC syndrome collision"
            lut[self.bin2dec(crc_residual)] = [j+i for j in  range(0,burst_length)]
        self.crc_fix_lookup[payload_length] = lut

    def decode_packet(self, pdu):
        # Reset decoder values before decoding next burst
        self.reset()

        # Grab packet PDU data
        meta = pmt.to_python(pmt.car(pdu))
        vector = pmt.to_python(pmt.cdr(pdu))
        self.timestamp = meta["timestamp"]
        self.datetime = datetime.datetime.utcfromtimestamp(self.timestamp).strftime("%Y-%m-%d %H:%M:%S.%f UTC")
        self.snr = meta["snr"]
        self.bits = vector

        # Decode the header (common) part of the packet
        self.decode_header()

        parity_passed = self.check_parity()

        if parity_passed == 0:
            parity_passed = self.correct_errors()

        if parity_passed == 1:
            self.decode_header() # do this again to reparse the header should it have fixes
            # If parity check passes, then decode the message contents
            self.decode_message()

            if self.print_level == "Brief":
                self.print_planes()


    def reset(self):
        self.aa_bits = []
        self.aa = -1
        self.aa_str = ""
        self.df = -1
        self.payload_length = -1


    def bin2dec(self, bits):
        return int("".join(map(str, bits)), 2)


    def get_direction(self, heading):
        """
        Notes:
            `heading = 0` Eastbound
            `heading = 90` Northbound
            `heading = 180/-180` Westbound
            `heading = -90` Southbound
        """
        if heading < 0:
            heading += 360.0

        quad = np.floor(heading/90.0)
        residual_angle = heading - quad*90.0
        sub_quad = np.floor((residual_angle+22.5)/45.0)

        if quad == 0:
            if sub_quad == 0:
                dir_str = "E"
            elif sub_quad == 1:
                dir_str = "NE"
            else:
                dir_str = "N"
        elif quad == 1:
            if sub_quad == 0:
                dir_str = "N"
            elif sub_quad == 1:
                dir_str = "NW"
            else:
                dir_str = "W"
        elif quad == 2:
            if sub_quad == 0:
                dir_str = "W"
            elif sub_quad == 1:
                dir_str = "SW"
            else:
                dir_str = "S"
        else:
            if sub_quad == 0:
                dir_str = "S"
            elif sub_quad == 1:
                dir_str = "SE"
            else:
                dir_str = "E"

        return dir_str


    def update_plane(self, aa_str):
        if aa_str in self.plane_dict:
            # The current plane already exists in the dictionary

            # If the plane has timed out, delete its old altimetry values
            # seconds_since_last_seen = (int(time.time()) - self.plane_dict[aa_str]["last_seen"])
            # if seconds_since_last_seen > PLANE_TIMEOUT_S:
            #     # self.webserver_remove_plane(self.aa_str)
            #     self.reset_plane_altimetry(self.plane_dict[aa_str])

            self.plane_dict[aa_str]["num_msgs"] += 1
            self.plane_dict[aa_str]["last_seen"] = int(time.time())

        else:
            # Create empty dictionary for the current plane
            self.plane_dict[aa_str] = dict([])
            self.plane_dict[aa_str]["callsign"] = None
            self.reset_plane_altimetry(self.plane_dict[aa_str])

            self.plane_dict[aa_str]["num_msgs"] = 1
            self.plane_dict[aa_str]["last_seen"] = int(time.time())

        # # Check if any planes have timed out and if so remove them
        # # from the dictionary
        # for key in self.plane_dict.keys():
        #     if (int(time.time()) - self.plane_dict[key]["last_seen"]) > PLANE_TIMEOUT_S:
        #         del self.plane_dict[key]


    def reset_plane_altimetry(self, plane):
        plane["altitude"] = np.NaN
        plane["speed"] = np.NaN
        plane["heading"] = np.NaN
        plane["vertical_rate"] = np.NaN
        plane["latitude"] = np.NaN
        plane["longitude"] = np.NaN
        plane["cpr"] = [(np.NaN, np.NaN, np.NaN), (np.NaN, np.NaN, np.NaN)]


    def print_planes(self):
        index = 0
        for icao in self.plane_dict:
            last_seen = datetime.datetime.utcfromtimestamp(self.timestamp).strftime("%H:%M:%S")

            if self.plane_dict[icao]["callsign"] is not None:
                callsign = "{:8s}".format(self.plane_dict[icao]["callsign"])
            else:
                callsign = " "*8

            if np.isnan(self.plane_dict[icao]["altitude"]) == False:
                altitude = "{:5.0f}".format(self.plane_dict[icao]["altitude"])
            else:
                altitude = " "*5

            if np.isnan(self.plane_dict[icao]["vertical_rate"]) == False:
                vertical_rate = "{:5.0f}".format(self.plane_dict[icao]["vertical_rate"])
            else:
                vertical_rate = " "*5

            if np.isnan(self.plane_dict[icao]["speed"]) == False:
                speed = "{:5.0f}".format(self.plane_dict[icao]["speed"])
            else:
                speed = " "*5

            if np.isnan(self.plane_dict[icao]["heading"]) == False:
                heading = "{:5.0f}".format(self.plane_dict[icao]["heading"])
            else:
                heading = " "*5

            if np.isnan(self.plane_dict[icao]["latitude"]) == False:
                latitude = "{:11.7f}".format(self.plane_dict[icao]["latitude"])
            else:
                latitude = " "*11

            if np.isnan(self.plane_dict[icao]["longitude"]) == False:
                longitude = "{:11.7f}".format(self.plane_dict[icao]["longitude"])
            else:
                longitude = " "*11

            num_msgs = "{:4d}".format(self.plane_dict[icao]["num_msgs"])
            age = "{:3.0f}".format(int(time.time()) - self.plane_dict[icao]["last_seen"])

            self.screen.addstr(2 + index, 0, "{:8s} {:6s} {} {} {} {} {} {} {} {}".format(
                last_seen,
                icao,
                callsign,
                altitude,
                vertical_rate,
                speed,
                heading,
                latitude,
                longitude,
                num_msgs
            ))
            self.screen.refresh()

            index += 1


    def publish_decoded_pdu(self, aa_str):
        decoded = self.plane_dict[aa_str].copy()
        decoded.pop("last_seen", None)
        decoded.pop("cpr", None)
        decoded["timestamp"] = self.timestamp
        decoded["datetime"] = self.datetime
        decoded["icao"] = aa_str
        decoded["df"] = self.df
        decoded["snr"] = self.snr

        meta = pmt.to_pmt(decoded)
        vector = pmt.to_pmt(self.bits)
        pdu = pmt.cons(meta, vector)
        self.message_port_pub(pmt.to_pmt("decoded"), pdu)


    def publish_unknown_pdu(self):
        unknown = dict()
        unknown["timestamp"] = self.timestamp
        unknown["datetime"] = self.datetime
        unknown["df"] = self.df
        unknown["snr"] = self.snr

        meta = pmt.to_pmt(unknown)
        vector = pmt.to_pmt(self.bits)
        pdu = pmt.cons(meta, vector)
        self.message_port_pub(pmt.to_pmt("unknown"), pdu)

    def log(self, level, name, value, subvalue=None):
        level_value = {"critical": 50, "error": 40, "warning": 30, "info": 20, "debug": 10, "notset": 0}.get(level.lower(), 0)
        name_color = {"critical": Fore.RED, "error": Fore.RED, "warning": Fore.YELLOW, "info": Fore.MAGENTA, "debug": Fore.GREEN, "notset": Fore.GREEN}.get(level.lower(), Fore.MAGENTA)
        name_str = "{}{}{}".format(Style.BRIGHT + name_color, name, Style.RESET_ALL)
        # subname_str = " {}{}".format(Style.DIM, subname) if subname else ""
        value_str = "{}{}{}".format(Style.NORMAL, value, Style.RESET_ALL)
        subvalue_str = " {}{}{}".format(Style.DIM, subvalue, Style.RESET_ALL) if subvalue is not None else ""
        msg = "{}: {}{}{}".format(name_str, value_str, subvalue_str, Style.RESET_ALL)
        logging.log(level_value, msg)

    def decode_header(self):
        """
        References:
            http://www.bucharestairports.ro/files/pages_files/Vol_IV_-_4yh_ed,_July_2007.pdf
            http://www.icao.int/APAC/Documents/edocs/cns/SSR_%20modesii.pdf
            http://www.anteni.net/adsb/Doc/1090-WP30-18-DRAFT_DO-260B-V42.pdf
            http://www.cats.com.kh/download.php?path=vdzw4dHS08mjtKi6vNi31Mbn0tnZ2eycn6ydmqPE19rT7Mze4cSYpsetmdXd0w==
            http://www.sigidwiki.com/images/1/15/ADS-B_for_Dummies.pdf
        """
        # Downlink Format, 5 bits
        self.df = self.bin2dec(self.bits[0:0+5])

        if self.msg_filter == "All Messages" or (self.msg_filter == "Extended Squitter Only" and self.df in [17,18,19]):
            logging.info("----------------------------------------------------------------------")
            self.log("info", "Datetime", self.datetime)
            self.log("info", "SNR", "{:1.2f} dB".format(self.snr))
            self.log("info", "Downlink Format (DF)", self.df, DF_STR_LUT[self.df])

    def check_parity(self):
        """
        References:
            http://jetvision.de/sbs/adsb/crc.htm
        """


        if self.msg_filter == "All Messages":
            if self.df in [0,4,5]:
                # 56 bit payload
                self.payload_length = 56

                # Address/Parity, 24 bits
                ap_bits = self.bits[32:32+24]

                crc_bits = self.compute_crc(self.bits[0:self.payload_length-24], self.crc_poly)
                crc = self.bin2dec(crc_bits)

                # XOR the computed CRC with the AP, the result should be the
                # interrogated plane's ICAO address
                self.aa_bits = crc_bits ^ ap_bits
                self.aa = self.bin2dec(self.aa_bits)
                self.aa_str = "{:06x}".format(self.aa)

                # If the ICAO address is in our plane dictionary,
                # then it's safe to assume the CRC passes
                parity_passed = self.aa_str in self.plane_dict

                if parity_passed:
                    self.log("info", "CRC", "Passed", "Recognized AA from AP")
                    self.log("info", "Address Announced (AA)", self.aa_str)
                    self.log("info", "Callsign", self.plane_dict.get(self.aa_str, {}).get("callsign", ""))
                    return 1
                else:
                    self.log("info", "CRC", Fore.RED + "Failed", "Unrecognized AA from AP")
                    self.log("info", "Address Announced (AA)", self.aa_str)
                    return 0

            elif self.df in [11]:
                # 56 bit payload
                self.payload_length = 56

                # Parity/Interrogator ID, 24 bits
                pi_bits = self.bits[32:32+24]
                pi = self.bin2dec(pi_bits)

                crc_bits = self.compute_crc(self.bits[0:self.payload_length-24], self.crc_poly)
                crc = self.bin2dec(crc_bits)

                # result_bits = pi_bits ^ crc_bits
                # print("pi_bits", pi_bits)
                # print("crc_bits", crc_bits)
                # print("result_bits", result_bits)
                # parity_passed = (pi_bits[:7] == crc_bits[:7])

                parity_passed = pi == crc


                # 17 0s
                # Code Label, 3 bits (3.1.2.5.2.1.3)
                # Interrogator Code, 4 bits (3.1.2.5.2.1.2)

                if parity_passed:
                    self.log("info", "CRC", "Passed")
                    return 1
                else:
                    self.log("info", "CRC", Fore.RED + "Failed", "PI^CRC = {}".format(pi^crc))
                    return 0

            elif self.df in [16,20,21,24]:
                # 112 bit payload
                self.payload_length = 112

                # Address/Parity, 24 bits
                ap_bits = self.bits[88:88+24]

                crc_bits = self.compute_crc(self.bits[0:self.payload_length-24], self.crc_poly)
                crc = self.bin2dec(crc_bits)

                # XOR the computed CRC with the AP, the result should be the
                # interrogated plane's ICAO address
                self.aa_bits = crc_bits ^ ap_bits
                self.aa = self.bin2dec(self.aa_bits)
                self.aa_str = "{:06x}".format(self.aa)

                # If the ICAO address is in our plane dictionary,
                # then it's safe to assume the CRC passes
                parity_passed = self.aa_str in self.plane_dict

                if parity_passed:
                    self.log("info", "CRC", "Passed", "Recognized AA from AP")
                    self.log("info", "Address Announced (AA)", self.aa_str)
                    self.log("info", "Callsign", self.plane_dict.get(self.aa_str, {}).get("callsign", ""))
                    return 1
                else:
                    self.log("info", "CRC", Fore.RED + "Failed", "Unrecognized AA from AP")
                    self.log("info", "Address Announced (AA)", self.aa_str)
                    return 0

        if self.msg_filter == "All Messages" or self.msg_filter == "Extended Squitter Only":
            if self.df in [17,18,19]:
                # 112 bit payload
                self.payload_length = 112

                # Parity/Interrogator ID, 24 bits
                pi = self.bin2dec(self.bits[88:88+24])

                crc_bits = self.compute_crc(self.bits[0:self.payload_length-24], self.crc_poly)
                crc = self.bin2dec(crc_bits)

                parity_passed = (pi == crc)

                if parity_passed:
                    self.log("info", "CRC", "Passed")
                    return 1
                else:
                    self.log("info", "CRC", Fore.RED + "Failed", "PI^CRC = {}".format(pi^crc))
                    return 0

        # Unsupported downlink format
        self.log("debug", "DF", self.df, "Unknown DF")

        return 0 # Parity failed


    def compute_crc(self, data, poly):
        """
        References:
            http://www.radarspotters.eu/forum/index.php?topic=5617.msg41293#msg41293
            http://www.eurocontrol.int/eec/gallery/content/public/document/eec/report/1994/022_CRC_calculations_for_Mode_S.pdf
        """
        num_data_bits = len(data)
        num_crc_bits = len(poly)-1

        # Multiply the data by x^(num_crc_bits), which is equivalent to a
        # left shift operation which is equivalent to appending zeros
        data = np.append(data, np.zeros(num_crc_bits, dtype=int))

        for ii in range(0,num_data_bits):
            if data[ii] == 1:
                # XOR the data with the CRC polynomial
                # NOTE: The data polynomial and CRC polynomial are Galois Fields
                # in GF(2)
                data[ii:ii+num_crc_bits+1] ^= poly

        crc = data[num_data_bits:num_data_bits+num_crc_bits]

        return crc
    def compute_crc_2(self, data, poly):
        """
        References:
            http://www.radarspotters.eu/forum/index.php?topic=5617.msg41293#msg41293
            http://www.eurocontrol.int/eec/gallery/content/public/document/eec/report/1994/022_CRC_calculations_for_Mode_S.pdf
        """
        num_data_bits = len(data)-  len(poly)
        num_crc_bits = len(poly)-1

        # Multiply the data by x^(num_crc_bits), which is equivalent to a
        # left shift operation which is equivalent to appending zeros
        #data = np.append(data, np.zeros(num_crc_bits, dtype=int))
        data = data.astype(int)
        for ii in range(0,num_data_bits):
            if data[ii] == 1:
                # XOR the data with the CRC polynomial
                # NOTE: The data polynomial and CRC polynomial are Galois Fields
                # in GF(2)
                data[ii:ii+num_crc_bits+1] ^= poly
        crc = data[num_data_bits:num_data_bits+1+num_crc_bits]
        return crc

    def correct_burst_errors(self):
        if self.payload_length < 1:
            return 0
        crc_bits = self.compute_crc_2(self.bits[0:self.payload_length], self.crc_poly)
        crc_dec= self.bin2dec(crc_bits)
        crc_res = self.bin2dec(self.bits[self.payload_length-24:self.payload_length])
        crc_lookup = crc_dec
        if self.payload_length in self.crc_fix_lookup:
            if  crc_lookup in self.crc_fix_lookup[self.payload_length]:
                bits_to_change =  self.crc_fix_lookup[self.payload_length][crc_lookup]
                self.log("debug" , "FEC", "detected faulty bits",bits_to_change)
                for bt in bits_to_change:
                    self.bits[bt] = self.bits[bt] ^ 1

                crc_bits = self.compute_crc_2(self.bits[0:self.payload_length], self.crc_poly)
                crc_dec= self.bin2dec(crc_bits)
                success = crc_dec == 0

                self.log("debug", "FEC", "Conservative error correction:" + str(success))
                return success
            else:
                self.log("debug", "FEC", "Conservative error correction lookup failed to get syndrome")
        else:
            self.log("debug", "FEC", "Conservative error correction lookup failed to get syndromes for length "  + str(self.payload_length))
    
        return 0

    def correct_errors(self):
        if self.error_corr == "None":
            return 0

        if self.error_corr == "Conservative":
            return self.correct_burst_errors()

        elif self.error_corr == "Brute Force":
#            for l in [56, 112]:
#                self.payload_length = l
#                self.correct_burst_errors()
            self.log("critical", "FEC", "Brute Force error correction to be implemented")
            return 0

        else:
            return 0


    def decode_message(self):
        """
        References:
            http://adsb-decode-guide.readthedocs.org/en/latest/introduction.html
        """
        if self.msg_filter == "All Messages":
            # DF = 0  (3.1.2.8.2) Short Air-Air Surveillance (ACAS)
            # DF = 16 (3.1.2.8.3) Long Air-Air Surveillance (ACAS)
            if self.df in [0,16]:
                # Vertical Status, 1 bit
                vs = self.bits[5]
                self.log("info", "Vertical Status (VS)", vs, VS_STR_LUT[vs])

                # Reply Information, 4 bits
                ri = self.bin2dec(self.bits[13:13+4])
                self.log("info", "Reply Information (RI)", ri, RI_STR_LUT[ri])

                # Altitude Code, 13 bits
                altitude = self.decode_ac13(self.bits[19:19+13])
                self.log("info", "Altitude", "{} ft".format(altitude))

                if self.df == 0:
                    # Crosslink Capability, 1 bits
                    cc = self.bits[6]
                    self.log("info", "Crosslink Capability (CC)", CC_STR_LUT[cc])

                elif self.df == 16:
                    # (4.3.8.4.2.4)
                    # mv_bits = self.bits[32:32+56]
                    # mv = self.decode_mv(self.bits[32:32+56])
                    mv = self.bin2dec(self.bits[32:32+56])

                    vds1 = self.bin2dec(self.bits[32:32+4])
                    vds2 = self.bin2dec(self.bits[36:36+4])

                    self.log("info", "VDS1", vds1)
                    self.log("info", "VDS2", vds2)
                    self.log("debug", "MV", "To be implemented", "0x{:x}".format(mv))

                    # if vds1 == 3 and vds2 == 0:

                # Update planes dictionary
                self.update_plane(self.aa_str)
                if altitude != -1:
                    # If the altitude is not invalid, log it
                    self.plane_dict[self.aa_str]["altitude"] = altitude

            # DF = 4 (3.1.2.6.5) Surveillance Altitude Reply
            # DF = 5 (3.1.2.6.7) Surveillance Identity Reply
            # DF = 20 (3.1.2.6.6) Comm-B Altitude Reply
            # DF = 21 (3.1.2.6.8) Comm-B Identity Reply
            if self.df in [4,5,20,21]:
                # Flight Status, 3 bits
                fs = self.bin2dec(self.bits[5:5+3])
                self.log("info", "Flight Status (FS)", fs, FS_STR_LUT[fs])

                # Downlink Request, 5 bits
                dr = self.bin2dec(self.bits[8:8+5])
                self.log("info", "Downlink Request (DR)", dr, DR_STR_LUT[dr])

                # Utility Message, 6 bits
                iis = self.bin2dec(self.bits[13:13+4])
                ids = self.bin2dec(self.bits[17:17+2])
                self.log("info", "IIS", iis)
                self.log("info", "IDS", ids, IDS_STR_LUT[ids])

                if self.df in [4,20]:
                    # Altitude Code, 13 bits
                    alt = self.decode_ac13(self.bits[19:19+13])
                    self.log("info", "Altitude", "{} ft".format(alt))

                    if self.df == 20:
                        # Message Comm-B, 56 bits
                        mb = self.decode_mb(self.bits[32:32+56])
                        self.log("debug", "Message Comm-B", "To be implemented", "0x{:x}".format(mb))

                    # Update planes dictionary
                    self.update_plane(self.aa_str)
                    if alt != -1:
                        # If the altitude is not invalid, log it
                        self.plane_dict[self.aa_str]["altitude"] = alt

                elif self.df in [5,21]:
                    # Identity Code, 13 bits
                    identity = self.decode_id(self.bits[19:19+13])
                    self.log("info", "Identity Code (IC)", identity)

                    # Update planes dictionary
                    self.update_plane(self.aa_str)
                    # if alt != -1:
                    #     # If the altitude is not invalid, log it
                    #     self.plane_dict[self.aa_str]["altitude"] = alt

                    if self.df == 21:
                        # Message Comm-B, 56 bits
                        mb = self.decode_mb(self.bits[32:32+56])
                        self.log("debug", "Message Comm-B", "To be implemented", "0x{:x}".format(mb))

            # DF = 11 (3.1.2.5.2.2) All-Call Reply
            elif self.df == 11:
                # Capability, 3 bits
                ca = self.bin2dec(self.bits[5:5+3])

                # Address Announced (ICAO Address) 24 bits
                self.aa_bits = self.bits[8:8+24]
                self.aa = self.bin2dec(self.aa_bits)
                self.aa_str = "{:06x}".format(self.aa)

                # Update planes dictionary
                self.update_plane(self.aa_str)

                self.log("info", "Capability (CA)", ca, CA_STR_LUT[ca])
                self.log("info", "Address Announced (AA)", self.aa_str)
                self.log("info", "Callsign", self.plane_dict.get(self.aa_str, {}).get("callsign", ""))

        if self.msg_filter == "All Messages" or self.msg_filter == "Extended Squitter Only":
            # ADS-B Extended Squitter
            if self.df == 17:
                # Capability, 3 bits
                ca = self.bin2dec(self.bits[5:5+3])
                self.log("info", "Capability (CA)", ca, subvalue=CA_STR_LUT[ca])

                # Address Announced (ICAO Address) 24 bits
                self.aa_bits = self.bits[8:8+24]
                self.aa = self.bin2dec(self.aa_bits)
                self.aa_str = "{:06x}".format(self.aa)
                self.log("info", "Address Announced (AA)", self.aa_str)
                self.log("info", "Callsign", self.plane_dict.get(self.aa_str, {}).get("callsign", ""))

                # All CA types contain ADS-B messages
                self.decode_me()

            # ADS-B Extended Squitter from a Non Mode-S transponder
            elif self.df == 18:
                # CF Field, 3 bits
                cf = self.bin2dec(self.bits[5:5+3])
                self.log("info", "CF", cf, CF_STR_LUT[cf])

                # Address Announced (ICAO Address) 24 bits
                self.aa_bits = self.bits[8:8+24]
                self.aa = self.bin2dec(self.aa_bits)
                self.aa_str = "{:06x}".format(self.aa)
                self.log("info", "Address Announced (AA)", self.aa_str)
                self.log("info", "Callsign", self.plane_dict.get(self.aa_str, {}).get("callsign", ""))

                self.log("debug", "DF={} CF={}".format(self.df, cf), "Spotted in the wild!")

                if cf in [0,1,6]:
                    if cf == 1:
                        self.log("debug", "CF={}".format(cf), "Look into this, the AA is not the ICAO address")
                    self.decode_me()
                elif cf in [2,3,5]:
                    self.decode_tisb_me()
                elif cf in [4]:
                    self.log("debug", "TIS-B and ADS-B Management Message", "To be implemented")
                elif cf in [6]:
                    self.log("debug", "ADS-B Message Rebroadcast", "To be implemented")

            # Military Extended Squitter
            elif self.df == 19:
                # Application Field, 3 bits
                af = self.bin2dec(self.bits[5:5+3])
                self.log("info", "Application Field (AF)", af, AF_STR_LUT[af])

                # Address Announced (ICAO Address) 24 bits
                self.aa_bits = self.bits[8:8+24]
                self.aa = self.bin2dec(self.aa_bits)
                self.aa_str = "{:06x}".format(self.aa)
                self.log("info", "Address Announced (AA)", self.aa_str)
                self.log("info", "Callsign", self.plane_dict.get(self.aa_str, {}).get("callsign", ""))
                self.log("debug", "DF={} AF={}".format(self.df, af), "Spotted in the wild!")

                if af in [0]:
                    self.decode_me()
                elif af in [1,2,3,4,5,6,7]:
                    self.log("debug", "AF={}".format(af), "Reserved for Military Use")

        elif self.df == 28:
            self.log("debug", "DF", self.df, "Emergency/priority status")
        elif self.df == 31:
            self.log("debug", "DF", self.df, "Aircraft operational status")
        else:
            self.log("debug", "DF", self.df, "Unknown DF")


    # (3.1.2.6.7.1) Identity Code
    def decode_id(self, bits):
        self.log("debug", "Identity Code", "To be implemented", bits)
        return self.bin2dec(bits)


    # (3.1.2.6.6.1) Message Comm-B, 56 bits
    def decode_mb(self, bits):
        self.log("debug", "Message Comm-B", "To be implemented", bits)
        return self.bin2dec(bits)


    # Altitude Code, 12 bits
    # http://www.eurocontrol.int/eec/gallery/content/public/document/eec/report/1995/002_Aircraft_Position_Report_using_DGPS_Mode-S.pdf
    def decode_ac12(self, bits):
        # Q-bit, 1 bit
        q_bit = bits[7]

        if q_bit == 0:
            # Q-bit = 0, altitude is encoded in multiples of 100 ft
            self.log("debug", "AC=12 Q-bit={}".format(q_bit), "To be implemented")

            return -1

        else:
            # Q-bit = 1, altitude is encoded in multiples of 25 ft

            # Remove the Q-bit from the altitude bits to calculate the
            # altitude
            n = self.bin2dec(np.delete(bits, 7))

            # Altitude in ft
            return n*25 - 1000


    # (3.1.2.6.5.4) Altitude Code, 13 bits
    def decode_ac13(self, bits):
        dec = self.bin2dec(bits)

        if dec != 0:
            # M-bit, 1 bit
            m_bit = bits[6]

            if m_bit == 0:
                # The altitude reading is in feet
                self.log("debug", "Units", "Standard")

                # Q-bit, 1 bit
                q_bit = bits[8]

                if q_bit == 0:
                    # (3.1.1.7.12.2.3)
                    # Q-bit = 0, altitude is encoded in multiples of 100 ft

                    c1 = bits[0]
                    a1 = bits[1]
                    c2 = bits[2]
                    a2 = bits[3]
                    c4 = bits[4]
                    a4 = bits[5]
                    b1 = bits[7]
                    b2 = bits[9]
                    d2 = bits[10]
                    b4 = bits[11]
                    d4 = bits[12]

                    # To be implemented
                    self.log("debug", "AC=13 M-bit=0 Q-bit={}".format(q_bit), "To be implemented, AltCode: {}".format(d2,d4,a1,a2,a4,b1,b2,b4,c1,c2,c4))

                    # Altitude in ft
                    return -1

                else:
                    # (3.1.2.6.5.4, Chapter 3 Appendix)
                    # Q-bit = 1, altitude is encoded in multiples of 25 ft

                    # Remove the Q-bit and M-bit from the altitude bits to calculate the altitude
                    n = self.bin2dec(np.delete(bits, [6, 8]))

                    # Altitude in ft
                    return n*25 - 1000

            else:
                # The altitude reading is in meters
                self.log("debug", "Units", "Metric", "To be implemented")

                # Altitude in ft
                return -1

        else:
            # If all 13 altitude bits are 0, then the altitude field is invalid
            return -1


    # Message Extended Squitter, 56 bits
    def decode_me(self):
        # Type Code, 5 bits
        tc = self.bin2dec(self.bits[32:32+5])
        self.log("info", "Type Code (TC)", tc, TC_STR_LUT[tc])

        ## Airborne/Surface Position ###
        if tc in [0]:
            # Message, 3 bits
            me = self.bits[0:self.payload_length]

        ### Aircraft Identification ###
        elif tc in range(1,5):
            # Grab callsign using character LUT
            callsign = ""

            for ii in range(0,8):
                # There are 8 characters in the callsign, each is represented using
                # 6 bits
                callsign += CALLSIGN_CHAR_LUT[self.bin2dec(self.bits[40+ii*6:40+(ii+1)*6])]

            # Remove invalid characters
            callsign = callsign.replace("_","")

            # Update planes dictionary
            self.update_plane(self.aa_str)
            self.plane_dict[self.aa_str]["callsign"] = callsign
            self.publish_decoded_pdu(self.aa_str)

            # print("Callsign: {}".format(callsign))

        ### Surface Position ###
        elif tc in range(5,9):
            self.log("debug", "TC", tc, "To be implemented")
            self.publish_unknown_pdu()

        ### Airborne Position (Baro Altitude) ###
        elif tc in range(9,19):
            # Surveillance Status, 2 bits
            ss = self.bin2dec(self.bits[37:37+2])

            # NIC Supplement-B, 1 bit
            nic_sb = self.bits[39]

            # Altitude, 12 bits
            alt_bits = self.bits[40:40+12]

            # Time, 1 bit
            time_bit = self.bits[52]

            # CPR Odd/Even Frame Flag, 1 bit
            frame_bit = self.bits[53]

            # Latitude in CPR Format, 17 bits
            lat_cpr = self.bin2dec(self.bits[54:54+17])

            # Longitude in CPR Format, 17 bits
            lon_cpr = self.bin2dec(self.bits[71:71+17])

            # Update planes dictionary
            self.update_plane(self.aa_str)
            assert(frame_bit >= 0 and frame_bit <= 1)
            self.plane_dict[self.aa_str]["cpr"][frame_bit] = (lat_cpr, lon_cpr, int(time.time()))

            (lat, lon) = self.calculate_lat_lon(self.plane_dict[self.aa_str]["cpr"])
            alt = self.decode_ac12(self.bits[40:40+12])

            # TODO: Temporary hack to make sure bad lat/lons don"t get published
            if (lat - self.plane_dict[self.aa_str]["latitude"]) < 0.1 and (lat - self.plane_dict[self.aa_str]["latitude"]) < 0.1:
                valid_lat_lon = True
            else:
                # Figure out what went wrong
                valid_lat_lon = False
                self.log("debug", "valid_lat_lon", valid_lat_lon)
                self.log("debug", "lat_cpr", lat_cpr)
                self.log("debug", "lon_cpr", lon_cpr)
                self.log("debug", "lat", lat)
                self.log("debug", "lon", lon)

            self.plane_dict[self.aa_str]["altitude"] = alt
            if np.isnan(lat) == False and np.isnan(lon) == False:
                self.plane_dict[self.aa_str]["latitude"] = lat
                self.plane_dict[self.aa_str]["longitude"] = lon

            if valid_lat_lon:
                self.publish_decoded_pdu(self.aa_str)

            self.log("info", "Surveillance Status (SS)", ss, SS_STR_LUT[ss])
            self.log("info", "Time", time_bit, T_STR_LUT[time_bit])
            self.log("info", "Latitude", "{} N".format(lat))
            self.log("info", "Longitude", "{} E".format(lon))
            self.log("info", "Altitude", "{} ft".format(alt))


        ### Airborne Velocities ###
        elif tc in [19]:
            # Sub Type, 3 bits
            st = self.bin2dec(self.bits[37:37+3])

            # Ground velocity subtype
            if st in [1,2]:
                # Intent Change Flag, 1 bit
                ic = self.bits[40]

                # Reserved-A, 1 bit
                resv_a = self.bits[41]

                # Velocity Uncertainty (NAC), 3 bits
                nac = self.bin2dec(self.bits[42:42+3])

                # Velocity Sign East-West, 1 bit
                nac = self.bits[45]

                # Velocity Sign East-West, 1 bit
                s_ew = self.bits[45]

                # Velocity East-West, 10 bits
                v_ew = self.bin2dec(self.bits[46:46+10])

                # Velocity Sign North-South, 1 bit
                s_ns = self.bits[56]

                # Velocity North-South, 10 bits
                v_ns = self.bin2dec(self.bits[57:57+10])

                # Vertical Rate Source, 1 bit
                vr_src = self.bits[67]

                # Vertical Rate Sign, 1 bit
                s_vr = self.bits[68]

                # Vertical Rate, 9 bits
                vr = self.bin2dec(self.bits[69:69+9])

                # Reserved-B, 2 bits
                resv_b = self.bin2dec(self.bits[78:78+2])

                # Difference from Baro Altitude and GNSS Height (HAE) Sign, 1 bit
                s_diff = self.bits[80]

                # Difference from Baro Altitude and GNSS Height (HAE), 7 bits
                diff = self.bits[81:81+7]

                # Velocity West to East
                velocity_we = (v_ew - 1)
                # s_ew = 0, flying West ot East
                # s_ew = 1, flying East to West
                if s_ew == 1:
                    velocity_we *= -1 # Flip direction

                # Velocity South to North
                velocity_sn = (v_ns - 1)
                # s_ns = 0, flying South to North
                # s_ns = 1, flying North to South
                if s_ns == 1:
                    velocity_sn *= -1 # Flip direction

                # Speed (knots)
                speed = np.sqrt(velocity_sn**2 + velocity_we**2)

                # Heading (degrees)
                heading = np.arctan2(velocity_sn,velocity_we)*360.0/(2.0*np.pi)

                # Vertical Rate (ft/min)
                vertical_rate = (vr - 1)*64
                # s_vr = 0, ascending
                # s_vr = 1, descending
                if s_vr == 1:
                    vertical_rate *= -1

                # Update planes dictionary
                self.update_plane(self.aa_str)
                self.plane_dict[self.aa_str]["speed"] = speed
                self.plane_dict[self.aa_str]["heading"] = heading
                self.plane_dict[self.aa_str]["vertical_rate"] = vertical_rate
                self.publish_decoded_pdu(self.aa_str)

                self.log("info", "Subtype (ST)", st, "Ground Velocity")
                if ic == 0:
                    self.log("info", "Intent Change (IC)", ic, "No Change in Intent")
                else:
                    self.log("info", "Intent Change (IC)", ic, "No Change in Intent")
                self.log("info", "Speed", "{:1.0f} kt".format(speed))
                self.log("info", "Heading", "{:1.0f} deg ({})".format(heading, self.get_direction(heading)))
                self.log("info", "Climb", "{} ft/min".format(vertical_rate))
                if vr_src == 0:
                    self.log("info", "Climb Source", vr_src, "Geometric Source (GNSS or INS)")
                else:
                    self.log("info", "Climb Source", vr_src, "Barometric Source")

            # Airborne velocity subtype
            elif st in [3,4]:
                self.log("info", "Subtype (ST)", st, "Air Velocity")
            else:
                self.log("debug", "DF={} TC={} ST={}".format(self.df, tc, self.st), "To be implemented")

        ### Airborne Position (GNSS Height) ###
        elif tc in range(20,23):
            self.log("debug", "TC", tc, "To be implemented")
            self.publish_unknown_pdu()

        ### Test Message ###
        elif tc in [23]:
            self.log("debug", "TC", tc, "To be implemented")
            self.publish_unknown_pdu()

        ### Surface System Status ###
        elif tc in [24]:
            self.log("debug", "TC", tc, "To be implemented")
            self.publish_unknown_pdu()

        ### Reserved ###
        elif tc in range(25,28):
            self.log("debug", "TC", tc, "To be implemented")
            self.publish_unknown_pdu()

        ### Extended Squitter A/C Status ###
        elif tc in [28]:
            self.log("debug", "TC", tc, "To be implemented")
            self.publish_unknown_pdu()

        ### Target State and Status (V.2) ###
        elif tc in [29]:
            self.log("debug", "TC", tc, "To be implemented")
            self.publish_unknown_pdu()

        ### Reserved ###
        elif tc in [30]:
            self.log("debug", "TC", tc, "To be implemented")
            self.publish_unknown_pdu()

        ### Aircraft Operation Status ###
        elif tc in [31]:
            self.log("debug", "TC", tc, "To be implemented")
            self.publish_unknown_pdu()

        else:
            self.log("debug", "TC", tc, "To be implemented")
            self.publish_unknown_pdu()


    def decode_tisb_me(self):
        self.log("TIS-B", "To be implemented")
        self.publish_unknown_pdu()


    # http://www.eurocontrol.int/eec/gallery/content/public/document/eec/report/1995/002_Aircraft_Position_Report_using_DGPS_Mode-S.pdf
    def calculate_lat_lon(self, cpr):
        # If the even and odd frame data is still valid, calculate the
        # latitude and longitude
        lat_dec = np.NaN
        lon_dec = np.NaN

        if (int(time.time()) - cpr[0][2]) < CPR_TIMEOUT_S and (int(time.time()) - cpr[1][2]) < CPR_TIMEOUT_S:
            # Get fractional lat/lon for the even and odd frame
            # Even frame
            lat_cpr_even = float(cpr[0][0])/131072
            lon_cpr_even = float(cpr[0][1])/131072

            # Odd frame
            lat_cpr_odd = float(cpr[1][0])/131072
            lon_cpr_odd = float(cpr[1][1])/131072

            # Calculate the latitude index
            j = int(np.floor(59*lat_cpr_even - 60*lat_cpr_odd + 0.5))

            lat_even = 360.0/60*((j % 60) + lat_cpr_even)
            if lat_even >= 270:
                lat_even -= 360

            lat_odd = 360.0/59*((j % 59) + lat_cpr_odd)
            if lat_odd >= 270:
                lat_odd -= 360

            # nl_even_old = self.compute_cpr_nl(lat_even)
            # nl_odd_old = self.compute_cpr_nl(lat_odd)

            nl_even = self.cpr_nl(lat_even)
            nl_odd = self.cpr_nl(lat_odd)

            if nl_even == nl_odd:
                # Even/odd latitudes are in the same latitude zone, use the
                # most recent latitude
                if (cpr[0][2] - cpr[1][2]) > 0:
                    # The even frame is more recent
                    lat_dec = lat_even

                    # Calculate longitude
                    ni = self.cpr_n(lat_even, 0)
                    m = int(np.floor(lon_cpr_even*(self.cpr_nl(lat_even)-1) - lon_cpr_odd*self.cpr_nl(lat_even) + 0.5))
                    lon_dec = (360.0/ni)*((m % ni) + lon_cpr_even)
                    if lon_dec >= 180.0:
                        lon_dec -= 360.0

                else:
                    # The odd frame is more recent
                    lat_dec = lat_odd

                    # Calculate longitude
                    ni = self.cpr_n(lat_odd, 1)
                    m = int(np.floor(lon_cpr_even*(self.cpr_nl(lat_odd)-1) - lon_cpr_odd*self.cpr_nl(lat_odd) + 0.5))
                    lon_dec = (360.0/ni)*((m % ni) + lon_cpr_odd)
                    if lon_dec >= 180.0:
                        lon_dec -= 360.0

            # else:
                # Even/odd latitudes are not in the same latitude zones, wait
                # for more data

        return (lat_dec, lon_dec)


    def cpr_n(self, lat, frame):
        # frame = 0, even frame
        # frame = 1, odd frame
        n = self.cpr_nl(lat) - frame;

        if n > 1:
            return n
        else:
            return 1


    def compute_cpr_nl(self, lat):
        NZ = 60.0
        # TODO: Might need to tweak this equation
        return int(2.0*np.pi/(np.arccos(1.0 - (1.0-np.cos(np.pi/(2.0*NZ)))/(np.cos(2.0*np.pi*abs(lat)/180.0)**2))))


    def cpr_nl(self, lat):
        if lat < 0:
            lat = -lat

        if lat < 10.47047130:
            return 59
        elif lat < 14.82817437:
            return 58
        elif lat < 18.18626357:
            return 57
        elif lat < 21.02939493:
            return 56
        elif lat < 23.54504487:
            return 55
        elif lat < 25.82924707:
            return 54
        elif lat < 27.93898710:
            return 53
        elif lat < 29.91135686:
            return 52
        elif lat < 31.77209708:
            return 51
        elif lat < 33.53993436:
            return 50
        elif lat < 35.22899598:
            return 49
        elif lat < 36.85025108:
            return 48
        elif lat < 38.41241892:
            return 47
        elif lat < 39.92256684:
            return 46
        elif lat < 41.38651832:
            return 45
        elif lat < 42.80914012:
            return 44
        elif lat < 44.19454951:
            return 43
        elif lat < 45.54626723:
            return 42
        elif lat < 46.86733252:
            return 41
        elif lat < 48.16039128:
            return 40
        elif lat < 49.42776439:
            return 39
        elif lat < 50.67150166:
            return 38
        elif lat < 51.89342469:
            return 37
        elif lat < 53.09516153:
            return 36
        elif lat < 54.27817472:
            return 35
        elif lat < 55.44378444:
            return 34
        elif lat < 56.59318756:
            return 33
        elif lat < 57.72747354:
            return 32
        elif lat < 58.84763776:
            return 31
        elif lat < 59.95459277:
            return 30
        elif lat < 61.04917774:
            return 29
        elif lat < 62.13216659:
            return 28
        elif lat < 63.20427479:
            return 27
        elif lat < 64.26616523:
            return 26
        elif lat < 65.31845310:
            return 25
        elif lat < 66.36171008:
            return 24
        elif lat < 67.39646774:
            return 23
        elif lat < 68.42322022:
            return 22
        elif lat < 69.44242631:
            return 21
        elif lat < 70.45451075:
            return 20
        elif lat < 71.45986473:
            return 19
        elif lat < 72.45884545:
            return 18
        elif lat < 73.45177442:
            return 17
        elif lat < 74.43893416:
            return 16
        elif lat < 75.42056257:
            return 15
        elif lat < 76.39684391:
            return 14
        elif lat < 77.36789461:
            return 13
        elif lat < 78.33374083:
            return 12
        elif lat < 79.29428225:
            return 11
        elif lat < 80.24923213:
            return 10
        elif lat < 81.19801349:
            return 9
        elif lat < 82.13956981:
            return 8
        elif lat < 83.07199445:
            return 7
        elif lat < 83.99173563:
            return 6
        elif lat < 84.89166191:
            return 5
        elif lat < 85.75541621:
            return 4
        elif lat < 86.53536998:
            return 3
        elif lat < 87.00000000:
            return 2
        else:
            return 1
