#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @file
# @author (C) 2015 by Roman Khassraf <rkhassraf@gmail.com>
#         (C) 2017 by Piotr Krysik <ptrkrysik@gmail.com>
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

import collections

__chan_spacing = 2e5
__arfcn_pcs = 0x8000

# first uplink freq, distance between uplink/downlink frequency, list of range tuple
# each tuple in a range tuple contains: first arfcn of the range, last arfcn of the range, offset of the range
# entries are ordered by relevance
__band_conf = collections.OrderedDict([
    ('GSM900', {'f_start': 880.2e6, 'distance': 45e6, 'ranges': [(975, 1023), (0, 124)]}),
    ('DCS1800', {'f_start': 1710.2e6, 'distance': 95e6, 'ranges': [(512, 885)]}),
    ('GSM850', {'f_start': 824.2e6, 'distance': 45e6, 'ranges': [(128, 251)]}),
    ('PCS1900', {'f_start': 1850.2e6, 'distance': 80e6, 'ranges': [(512+__arfcn_pcs, 810+__arfcn_pcs)]}), #PCS band is "special" as its channel number range overlap with DCS1800
    ('GSM450', {'f_start': 450.6e6, 'distance': 10e6, 'ranges': [(259, 293)]}),
    ('GSM480', {'f_start': 479e6, 'distance': 10e6, 'ranges': [(306, 340)]}),
    ('GSM-R', {'f_start': 876.2e6, 'distance': 45e6, 'ranges': [(955, 1023), (0, 124)]}),
])


def get_bands():
    return __band_conf.keys()

def arfcn2band(arfcn):
    for band_name,band_desc in __band_conf.items():
        for arfcns_range in band_desc["ranges"]:
            arfcn_start = arfcns_range[0]
            arfcn_stop  = arfcns_range[1]
            if arfcn_start <= arfcn <= arfcn_stop:
                return band_name
    return None
    
def freq2band(freq, downlink=False):
    for band_name,band_desc in __band_conf.items():
        chans_total = 0
        #count total number of channels in the range
        for arfcns_range in band_desc["ranges"]:
            arfcn_start = arfcns_range[0]
            arfcn_stop  = arfcns_range[1]
            chans_in_range = arfcn_stop - arfcn_start + 1
            chans_total = chans_total + chans_in_range

        first_freq = band_desc["f_start"]
        if downlink:
            first_freq = first_freq + band_desc["distance"]
        last_freq  = first_freq + (chans_total - 1) * __chan_spacing
        
        if first_freq <= freq <= last_freq:
            return band_name
    return None

def uplink2band(freq):
    return freq2band(freq, False)

def downlink2band(freq):
    return freq2band(freq, True)
    
def is_valid_arfcn(arfcn):
    """
    Returns True if arfcn is valid in the given band, else False
    """
    band = arfcn2band(arfcn)
    if band is not None:
        conf = __band_conf.get(band)
        for arfcn_range in conf['ranges']:
            arfcn_start = arfcn_range[0]
            arfcn_end = arfcn_range[1]
            if arfcn_start <= arfcn <= arfcn_end:
                return True
    return False


def is_valid_uplink(freq):
    """
    Returns True if the given frequency is a valid uplink frequency in the given band
    """
    result = False
    band = uplink2band(freq)
    if band is not None:
        result = True
        
    return result

def is_valid_downlink(freq):
    """
    Returns True if the given frequency is a valid downlink frequency in the given band
    """
    result = False
    band = downlink2band(freq)
    if band is not None:
        result = True
        
    return result

def arfcn2uplink(arfcn):
    band = arfcn2band(arfcn)
    if band is not None:
        conf = __band_conf.get(band)
        f_start = conf['f_start']
        arfcns_total = 0
        for arfcn_range in conf['ranges']:
            arfcn_start = arfcn_range[0]
            arfcn_end = arfcn_range[1]

            if arfcn_start <= arfcn <= arfcn_end:
                f = f_start + (__chan_spacing * (arfcn - arfcn_start + arfcns_total))
                return round(f, 1)
            arfcns_total = arfcn_end - arfcn_start + 1
    return -1


def arfcn2downlink(arfcn):
    band = arfcn2band(arfcn)
    if band is not None:
        conf = __band_conf.get(band)
        distance = conf['distance']
        return round(arfcn2uplink(arfcn) + distance, 1)
    return -1

def uplink2arfcn(freq):
    band = uplink2band(freq)
    if band is not None:
        conf = __band_conf.get(band)
        arfcns_total = 0
        for arfcn_range in conf['ranges']:
            arfcn_start = arfcn_range[0]
            arfcn_end = arfcn_range[1]
            arfcns_in_range = arfcn_end - arfcn_start + 1
           
            freq_start = conf['f_start'] + arfcns_total * __chan_spacing
            freq_end = freq_start + (arfcns_in_range - 1) * __chan_spacing 
            if freq_start <= freq <= freq_end:
                arfcn = int(round(arfcn_start + ((freq - freq_start) / __chan_spacing), 0))
                return arfcn
            arfcns_total = arfcns_total + arfcns_in_range
    return -1

def downlink2arfcn(freq):
    band = downlink2band(freq)
    if band is not None:
        conf = __band_conf.get(band)
        distance = conf['distance']
        freq_uplink = freq - distance
        return int(round(uplink2arfcn(freq_uplink), 0))
    return -1


def get_arfcn_ranges(band):
    """
    Returns a list of arfcn tuples, each with first and last arfcn of the range.
    """
    result = []
    if band in __band_conf:
        conf = __band_conf.get(band)
        for arfcn_range in conf['ranges']:
            arfcn_tuple = (arfcn_range[0], arfcn_range[1])
            result.append(arfcn_tuple)
    return result

