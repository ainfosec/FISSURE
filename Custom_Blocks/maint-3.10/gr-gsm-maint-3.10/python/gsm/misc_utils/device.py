#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @file
# @author (C) 2019 by Vasil Velichkov <vvvelichkov@gmail.com>
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

import osmosdr
import os

def get_devices(hint=""):
    return osmosdr.device.find(osmosdr.device_t(hint))

def match(dev, filters):
    for f in filters:
        for k, v in f.items():
            try:
                if k not in dev.to_string() or dev[k] != v:
                    break
            except:
                pass
        else:
            return True
    return False

def exclude(devices, filters = ({'driver': 'audio'},)):
    return [dev for dev in devices if not match(dev, filters)]

def get_all_args(hint="nofake"):
    return list(map(lambda dev: dev.to_string(), exclude(get_devices(hint))))

def get_default_args(args):
    # The presence of GRC_BLOCKS_PATH environment variable indicates that
    # gnuradio-companion compiles a flowgraph and in this case no exception
    # have to be thrown otherwise the generaged python script will be invalid.
    # This allows compilation of flowgraphs without an SDR device.
    if args or os.getenv("GRC_BLOCKS_PATH"):
        return args

    devices = get_all_args("nofake")
    if not devices:
        raise RuntimeError("Unable to find any supported SDR devices")

    return devices[0]

def print_devices(hint=""):
    devices = exclude(get_devices(hint))
    if devices:
        print("\n".join(map(lambda dev: dev.to_string(), devices)))
    else:
        print("Unable to find any supported SDR devices")
