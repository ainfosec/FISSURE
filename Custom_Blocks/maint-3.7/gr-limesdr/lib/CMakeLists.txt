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

include_directories(${Boost_INCLUDE_DIR} 
		    ${LIMESUITE_INCLUDE_DIRS} 
		    ${CMAKE_CURRENT_BINARY_DIR})
link_directories(${Boost_LIBRARY_DIRS} 
		 ${LIMESDR_PKG_LIBRARY_DIRS})

list(APPEND limesdr_sources
    source_impl.cc
    sink_impl.cc
    common/device_handler.cc
)

set(limesdr_sources "${limesdr_sources}" PARENT_SCOPE)
if(NOT limesdr_sources)
	MESSAGE(STATUS "No C++ sources... skipping lib/")
	return()
endif(NOT limesdr_sources)

add_library(gnuradio-limesdr SHARED ${limesdr_sources})
target_link_libraries(
  gnuradio-limesdr 
  ${Boost_LIBRARIES} 
  ${GNURADIO_ALL_LIBRARIES} 
  ${LIMESUITE_LIB})
  
set_target_properties(
  gnuradio-limesdr PROPERTIES DEFINE_SYMBOL "gnuradio_limesdr_EXPORTS")

if(APPLE)
    set_target_properties(
      gnuradio-limesdr PROPERTIES 
      INSTALL_NAME_DIR "${CMAKE_INSTALL_PREFIX}/lib")
endif(APPLE)

########################################################################
# Install built library files
########################################################################
install(TARGETS gnuradio-limesdr
	LIBRARY DESTINATION lib${LIB_SUFFIX} # .so/.dylib file
	ARCHIVE DESTINATION lib${LIB_SUFFIX} # .lib file
	RUNTIME DESTINATION bin              # .dll file
	)
