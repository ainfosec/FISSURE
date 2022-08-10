#!/usr/bin/env python
# -*- coding: utf-8 -*-
# 
# Copyright 2016-2017 Matt Hostetter.
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

import numpy as np
import argparse
import time
import calendar
import random
import csv
import sqlite3
import xml.etree.ElementTree as ET

plane_dict = dict()

# KML encodes the color as aabbggrr in hex (alpha, blue, green, red)
COLOR_LUT = [0x5531ff, 0x42afff, 0x5eedff, 0x70f749, 0xfdae2d, 0xe42ee8] # http://www.color-hex.com/color-palette/2193

FT_PER_METER    = 3.28084


def sqlite_to_kml(db_filename, kml_filename):
    # Read database and plot planes
    conn = sqlite3.connect(db_filename)
    conn.text_factory = str
    c = conn.cursor()

    kml = ""
    kml += kml_header()

    c.execute("SELECT DISTINCT ICAO FROM ADSB;")
    icao_tuples = c.fetchall()

    for icao_tuple in icao_tuples:
        # Look at each ICAO address individually
        icao = icao_tuple[0]
        c.execute("""SELECT DISTINCT Callsign FROM ADSB WHERE ICAO == "%s" AND DF == 17;""" % (icao))    
        callsign_tuples = c.fetchall()

        # Find the first non-null callsign for the plane.  They should all be the same, 
        # so pick the first one and then quit.
        callsign = "?"
        for callsign_tuple in callsign_tuples:
            if callsign_tuple[0] != None:
                callsign = callsign_tuple[0]
                break

        c.execute("""SELECT Datetime,Latitude,Longitude,Altitude,Heading FROM ADSB WHERE ICAO == "%s" AND Latitude IS NOT NULL""" % (icao))
        location_tuples = c.fetchall()

        kml_when = ""
        kml_coord = ""
        kml_angles = ""

        num_coords = 0

        for location_tuple in location_tuples:
            kml_when += """\n<when>%s</when>""" % (location_tuple[0])

            if location_tuple[1] != None and location_tuple[2] != None and location_tuple[3] != None:
                # NOTE: KML expects the altitude in meters
                lon = location_tuple[2]
                lat = location_tuple[1]
                alt = location_tuple[3]/FT_PER_METER
                kml_coord += """\n<gx:coord>%1.8f %1.8f %1.1f</gx:coord>""" % (lon, lat, alt)
                num_coords += 1
            else:
                kml_coord += """\n<gx:coord></gx:coord>"""

            # if location_tuple[4] != None:
            #     # Heading is specificed at 0 = North, 90 = East, 180 = South, 270 = West
            #     hdng = -1*location_tuple[4] + 90.0
            #     if hdng < 0:
            #         hdng += 360.0
            #     kml_angles += """\n<gx:angles>%1.2f %1.2f %1.2f</gx:angles>""" % (hdng, 0.0, 0.0)
            # else:
            #     kml_angles += """\n<gx:angles></gx:angles>"""

        # Check if there is enough data to log this plane to the KML file
        if num_coords >= 2:
            kml += """\n<Placemark>"""
            kml += """\n<name>%s</name>""" % (callsign)
            kml += kml_style(0xDD, COLOR_LUT[random.randrange(0,len(COLOR_LUT))], 2)
            kml += """\n<gx:Track>"""
            kml += """\n<altitudeMode>absolute</altitudeMode>"""
            # kml += """\n<altitudeMode>relativeToGround</altitudeMode>"""
            # kml += """\n<extrude>1</extrude>"""
            # kml += """\n<tesselate>1</tesselate>"""

            kml += kml_when
            kml += kml_coord
            kml += kml_angles

            kml += """\n<ExtendedData>"""
            kml += """\n<Data>"""
            kml += """\n<displayName>ICAO Address</displayName>"""
            kml += """\n<value>%s</value>""" % (icao)
            kml += """\n</Data>"""
            kml += """\n</ExtendedData>"""
            
            kml += """\n</gx:Track>"""
            kml += """\n</Placemark>"""

    
    kml += kml_footer()

    # print kml

    f = open(kml_filename, "w")
    f.write(kml)
    f.close()


def kml_header():
    kml = ""
    kml += """<?xml version="1.0" encoding="UTF-8"?>"""
    kml += """\n<kml xmlns="http://www.opengis.net/kml/2.2" xmlns:gx="http://www.google.com/kml/ext/2.2">"""
    kml += """\n<Document>"""
    kml += """\n<name>ADS-B Plane Tracking</name>"""
    kml += """\n<Snippet>Created %s</Snippet>""" % ("blah")
    kml += """\n<Folder>"""
    kml += """\n<name>Planes</name>"""
    
    return kml


def kml_footer():
    kml = ""
    kml += """\n</Folder>"""
    kml += """\n</Document>"""
    kml += """\n</kml>"""

    return kml


def kml_style(alpha, color, width):
    kml = ""
    kml += """\n<Style>"""
    kml += """\n<IconStyle>"""
    kml += """\n<Icon>"""
    kml += """\n<scale>1.5</scale>"""
    if 1:
        # kml += """\n<href>http://earth.google.com/images/kml-icons/track-directional/track-0.png</href>"""
        # kml += """\nhttps://cdn4.iconfinder.com/data/icons/delivery-1-1/512/plane-128.png"""
        kml += """\nhttp://www.iconsdb.com/icons/preview/white/airplane-7-xxl.png"""
        # kml += """\n<href>plane1.png</href>"""
    kml += """\n</Icon>"""
    kml += """\n</IconStyle>"""
    kml += """\n<LabelStyle>"""
    kml += """\n<scale>0.75</scale>"""
    kml += """\n</LabelStyle>"""
    kml += """\n<LineStyle>"""
    # KML encodes the color as aabbggrr in hex (alpha, blue, green, red)
    kml += """\n<color>%02x%06x</color>""" % (alpha, color)
    kml += """\n<width>%d</width>""" % (width)
    kml += """\n</LineStyle>"""
    # kml += """\n<PolyStyle>"""
    # kml += """\n<color>00x%06x</color>""" % (color)
    # kml += """\n<width>%d</width>""" % (width)
    # kml += """\n</PolyStyle>"""
    kml += """\n</Style>"""

    return kml


if __name__ == "__main__":
    # Set up the command-line arguments
    parser = argparse.ArgumentParser(description="Generate a Google Earth KML file from logged ADS-B data.")
    parser.add_argument("--db_file", metavar="db_file", type=str, default="adsb.sqlite", help="The input SQLite filename")
    parser.add_argument("--kml_file", metavar="kml_file", type=str, default="adsb.kml", help="The output KML filename")

    args = parser.parse_args()

    sqlite_to_kml(args.db_file, args.kml_file)
