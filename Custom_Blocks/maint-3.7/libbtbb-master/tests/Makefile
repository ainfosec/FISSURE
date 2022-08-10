# Copyright 2011 Michael Ossmann, Dominic Spill
#
# This file is part of Project Ubertooth.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2, or (at your option)
# any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; see the file COPYING.  If not, write to
# the Free Software Foundation, Inc., 51 Franklin Street,
# Boston, MA 02110-1301, USA.

CC ?= gcc

SOURCE_FILES = test_syndromes.c
LIBRARY_SOURCE = ../bluetooth_packet.c
BINARY_FILES = test_syndromes
HEADER_FILES = ../bluetooth_packet.h

CFLAGS += -DHASH_FUNCTION=HASH_FNV -DHASH_EMIT_KEYS=3

all: test_packet

test_packet:
	$(CC) $(CFLAGS) $(CPPFLAGS) -O2 -Wall $(LIBRARY_SOURCE) $(SOURCE_FILES) -o $(BINARY_FILES)

clean:
	rm -f $(BINARY_FILES)

