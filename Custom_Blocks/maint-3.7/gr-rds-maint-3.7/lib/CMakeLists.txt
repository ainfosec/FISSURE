# Copyright 2011 Free Software Foundation, Inc.
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
include(GrMiscUtils)

add_library(gnuradio-rds SHARED
    decoder_impl.cc
    encoder_impl.cc
    parser_impl.cc
)
target_link_libraries(gnuradio-rds ${Boost_LIBRARIES}  ${GNURADIO_ALL_LIBRARIES})
set_target_properties(gnuradio-rds PROPERTIES DEFINE_SYMBOL "gnuradio_RDS_EXPORTS")

########################################################################
# Install built library files
########################################################################
install(TARGETS gnuradio-rds
    LIBRARY DESTINATION lib${LIB_SUFFIX} # .so/.dylib file
    ARCHIVE DESTINATION lib${LIB_SUFFIX} # .lib file
    RUNTIME DESTINATION bin              # .dll file
)

GR_LIBRARY_FOO(gnuradio-rds)
