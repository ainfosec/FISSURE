#!/usr/bin/env python
"""
pcapdump setup

Install script for pcapdump

Usage: python setup.py install

This file is part of libbtbb
Copyright 2012 Dominic Spill
"""

from distutils.core import setup

setup(
    name        = "pcapdump",
    version     = "0.8",
    description = "A reader and dump utility for Pcap files",
    author      = "Joshua Wright",
    url         = "https://sourceforge.net/projects/libbtbb/",
    license     = "GPL",
    packages    = ['pcapdump'],
    classifiers=[
        'Development Status :: 5 - Beta',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: GNU General Public License (GPL)',
        'Programming Language :: Python',
        'Operating System :: OS Independent',
        'Topic :: System :: Networking :: Monitoring',
    ],
)
