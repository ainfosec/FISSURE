# Copyright 2011,2012 Free Software Foundation, Inc.
#
# This file is part of GNU Radio
#
# GNU Radio is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3, or (at your option)
# any later version.
#
# GNU Radio is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with GNU Radio; see the file COPYING.  If not, write to
# the Free Software Foundation, Inc., 51 Franklin Street,
# Boston, MA 02110-1301, USA.

########################################################################
# Setup library
########################################################################
include(GrPlatform) #define LIB_SUFFIX

include_directories(
    ${Boost_INCLUDE_DIR}
    ${UHD_INCLUDE_DIRS}
)
link_directories(
    ${Boost_LIBRARY_DIRS}
    ${UHD_LIBRARY_DIRS}
)

list(APPEND foo_sources
    burst_tagger_impl.cc
    packet_dropper_impl.cc
    packet_pad2.cc
    packet_pad_impl.cc
    periodic_msg_source_impl.cc
    random_periodic_msg_source_impl.cc
    rtt_measure_impl.cc
    wireshark_connector_impl.cc
)

set(PACKAGE_FIND_VERSION_MAJOR 0)
include(GnuradioConfigVersion)

if(${API_COMPAT} EQUAL 8)
    message(STATUS "next branch (3.8 install), using new API")
    add_definitions("-DGR_FOO_NEW_API")
elseif(${MINOR_VERSION} GREATER 7)
    message(STATUS "recent 3.7.8 install, using new API")
    add_definitions("-DGR_FOO_NEW_API")
elseif(${MINOR_VERSION} EQUAL 7 AND NOT ${MAINT_VERSION} STREQUAL "git")
    message(STATUS "recent real 3.7.7 install, using new API")
    add_definitions("-DGR_FOO_NEW_API")
elseif(${MINOR_VERSION} EQUAL 6 AND NOT ${MAINT_VERSION} STREQUAL "git" AND ${MAINT_VERSION} GREATER 0)
    message(STATUS "3.7.6 with maint version >= 1 install, using new API")
    add_definitions("-DGR_FOO_NEW_API")
else()
    message(STATUS "using old API")
endif()

add_library(gnuradio-foo SHARED ${foo_sources})
target_link_libraries(gnuradio-foo ${Boost_LIBRARIES} ${GNURADIO_ALL_LIBRARIES} ${UHD_LIBRARIES})
set_target_properties(gnuradio-foo PROPERTIES DEFINE_SYMBOL "gnuradio_foo_EXPORTS")

########################################################################
# Install built library files
########################################################################
install(TARGETS gnuradio-foo
    LIBRARY DESTINATION lib${LIB_SUFFIX} # .so/.dylib file
    ARCHIVE DESTINATION lib${LIB_SUFFIX} # .lib file
    RUNTIME DESTINATION bin              # .dll file
)
