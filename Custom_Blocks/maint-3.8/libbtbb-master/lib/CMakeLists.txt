#
# Copyright 2013 Dominic Spill
#
# This file is part of Libbtbb.
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
#

include(GNUInstallDirs)

# Based heavily upon the hackrf cmake setup.

project(libbtbb C)
set(MAJOR_VERSION 1)
set(MINOR_VERSION 0)
set(PACKAGE libbtbb)
set(VERSION ${MAJOR_VERSION}.${MINOR_VERSION})
add_definitions( -DVERSION="${VERSION}" )

if(NOT MSVC)
	add_definitions(-Wall)
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=gnu90")
endif()

add_subdirectory(src)

CONFIGURE_FILE(
    ${CMAKE_CURRENT_SOURCE_DIR}/libbtbb.pc.in
    ${CMAKE_CURRENT_BINARY_DIR}/libbtbb.pc
@ONLY)

INSTALL(
    FILES ${CMAKE_CURRENT_BINARY_DIR}/libbtbb.pc
    DESTINATION lib${LIB_SUFFIX}/pkgconfig
)
