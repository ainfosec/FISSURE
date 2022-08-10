# Copyright 2014 Jared Boone <jared@sharebrained.com>.
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

########################################################################
# Setup library
########################################################################
include(GrPlatform) #define LIB_SUFFIX

include_directories(${Boost_INCLUDE_DIR})
link_directories(${Boost_LIBRARY_DIRS} ${GNURADIO_RUNTIME_LIBRARY_DIRS})

list(APPEND tpms_sources
    ask_env_impl.cc
    fixed_length_frame_sink_impl.cc
    burst_detector_impl.cc
)

add_library(gnuradio-tpms SHARED ${tpms_sources})
target_link_libraries(gnuradio-tpms ${Boost_LIBRARIES} ${GNURADIO_RUNTIME_LIBRARIES} ${GNURADIO_ALL_LIBRARIES} fftw3f)
set_target_properties(gnuradio-tpms PROPERTIES DEFINE_SYMBOL "gnuradio_tpms_EXPORTS")

########################################################################
# Install built library files
########################################################################
install(TARGETS gnuradio-tpms
    LIBRARY DESTINATION lib${LIB_SUFFIX} # .so/.dylib file
    ARCHIVE DESTINATION lib${LIB_SUFFIX} # .lib file
    RUNTIME DESTINATION bin              # .dll file
)

########################################################################
# Build and register unit test
########################################################################
include(GrTest)

include_directories(${CPPUNIT_INCLUDE_DIRS})

list(APPEND test_tpms_sources
    ${CMAKE_CURRENT_SOURCE_DIR}/test_tpms.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/qa_tpms.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/qa_fixed_length_frame_sink.cc
    ${CMAKE_CURRENT_SOURCE_DIR}/qa_ask_env.cc
)

add_executable(test-tpms ${test_tpms_sources})

target_link_libraries(
  test-tpms
  ${GNURADIO_RUNTIME_LIBRARIES}
  ${Boost_LIBRARIES}
  ${CPPUNIT_LIBRARIES}
  gnuradio-tpms
)

GR_ADD_TEST(test_tpms test-tpms)
